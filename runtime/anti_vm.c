/*
 * runtime/anti_vm.c -- hypervisor-presence checks, called from
 * runtime/anti_debug.c's karity_anti_debug_scan() and folded into the same
 * taint value (see include/karity/anti_vm.h and anti_debug.h's file
 * headers for why this is one function among several feeding one funnel,
 * not a separate mechanism). Same freestanding discipline as the rest of
 * this runtime: no windows.h, WinAPI resolved by name hash.
 *
 * Each check returns its taint contribution directly (constant-or-0),
 * computed branchlessly, exactly like runtime/anti_debug.c's own checks --
 * see that file's karity_ad_mask_nz comment for why (no per-check `if` for a
 * patcher to NOP). Split into a passive scan (side-effect-free CPUID checks,
 * run unconditionally by the caller and masked) and an active scan (the
 * VMware backdoor, which raises a first-chance exception a debugger would
 * see, so the caller only runs it when the VM category is actually enabled).
 */
#include "karity/anti_vm.h"

#include "api_resolve.h"

#define KARITY_STATUS_PRIVILEGED_INSTRUCTION 0xC0000096UL

#define KARITY_EXCEPTION_CONTINUE_EXECUTION ((int32_t)-1)
#define KARITY_EXCEPTION_CONTINUE_SEARCH    ((int32_t)0)

/* Branchless boolean->mask, duplicated from runtime/anti_debug.c (same
 * per-file hand-rolling discipline as the hashes above) -- ~0 if v!=0 else
 * 0. See anti_debug.c's karity_ad_mask_nz for the rationale. */
static uint64_t karity_avm_mask_nz(uint64_t v)
{
    return (uint64_t)0 - (uint64_t)((v | ((uint64_t)0 - v)) >> 63);
}

/* karity_hash_name() results, precomputed offline -- see runtime/api_resolve.h.
 * kernel32.dll/AddVectoredExceptionHandler/RemoveVectoredExceptionHandler
 * duplicated from runtime/anti_debug.c's own copies -- see that file's
 * comment on why each file hand-rolls what it needs rather than sharing. */
#define KARITY_HASH_KERNEL32_DLL                       0xBE1260896DDB9555ULL
#define KARITY_HASH_ADD_VECTORED_EXCEPTION_HANDLER     0xC63AE8E0277409F7ULL
#define KARITY_HASH_REMOVE_VECTORED_EXCEPTION_HANDLER  0x27AFCB413211D03CULL

#define KARITY_AVM_TAINT_HV_BIT        0xECEFE37B9E250D03ULL
#define KARITY_AVM_TAINT_HV_VENDOR     0xB5BAB1CD888417A5ULL
#define KARITY_AVM_TAINT_VMWARE_PORT   0x922BADB05DA83CFFULL
#define KARITY_AVM_TAINT_CPUID_TIMING  0xBB5D75B895F628F3ULL

typedef void *(*karity_pfn_add_veh)(uint32_t first, void *handler);
typedef uint32_t (*karity_pfn_remove_veh)(void *handle);

typedef struct {
    void *exception_record;
    void *context_record;
} karity_avm_exception_pointers;

static void karity_avm_cpuid(uint32_t leaf, uint32_t subleaf, uint32_t out[4])
{
    __asm__ volatile("cpuid"
                      : "=a"(out[0]), "=b"(out[1]), "=c"(out[2]), "=d"(out[3])
                      : "a"(leaf), "c"(subleaf));
}

static uint64_t karity_avm_rdtsc(void)
{
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

/* CPUID leaf 1, ECX bit 31: the "hypervisor present" bit every major
 * hypervisor (VMware, VirtualBox, Hyper-V, KVM, Xen, Parallels) sets per
 * the Intel/AMD-documented convention, since real hardware never sets it.
 * The single most common anti-VM check in existence -- worth keeping
 * anyway since it's one signal among several here, not the whole defense
 * (see the file header). */
static uint64_t karity_avm_check_hypervisor_bit(void)
{
    uint32_t regs[4];
    karity_avm_cpuid(1, 0, regs);
    return KARITY_AVM_TAINT_HV_BIT & karity_avm_mask_nz(regs[2] & 0x80000000u); /* ECX */
}

/* CPUID leaf 0x40000000: the hypervisor vendor-ID leaf. Real (non-
 * virtualized) hardware doesn't implement this leaf at all and returns all
 * zeros for it; every hypervisor that sets the presence bit above also
 * populates this with a 12-byte ASCII signature (EBX:ECX:EDX) --
 * "VMwareVMware", "VBoxVBoxVBox", "Microsoft Hv", "KVMKVMKVM\0\0\0", ...
 * Checked independently of the presence bit (not gated on it) so a
 * hypervisor configuration that hides one but not the other still
 * contributes here -- fewer public anti-VM snippets bother reading this
 * leaf at all, most stop at the bit above. */
static uint64_t karity_avm_check_hypervisor_vendor(void)
{
    uint32_t regs[4];
    karity_avm_cpuid(0x40000000u, 0, regs);
    return KARITY_AVM_TAINT_HV_VENDOR & karity_avm_mask_nz(regs[1]); /* EBX: first 4 vendor bytes */
}

static volatile int g_avm_vmware_faulted;

static int32_t karity_avm_vmware_veh(karity_avm_exception_pointers *ep)
{
    uint32_t code = *(uint32_t *)ep->exception_record; /* ExceptionCode, +0x00 */
    uint64_t *rip;

    if (code != KARITY_STATUS_PRIVILEGED_INSTRUCTION) return KARITY_EXCEPTION_CONTINUE_SEARCH;
    g_avm_vmware_faulted = 1;
    rip = (uint64_t *)((uint8_t *)ep->context_record + 0xF8); /* CONTEXT.Rip, see anti_debug.c */
    *rip += 1; /* `in eax, dx` (opcode 0xED) is exactly one byte */
    return KARITY_EXCEPTION_CONTINUE_EXECUTION;
}

/* The classic VMware "backdoor I/O port": EAX='VMXh' (0x564D5868),
 * ECX=0x0A (GETVERSION), EDX='VX' (0x5658, the port number), then
 * `in eax, dx`. On real hardware this is an ordinary ring-3 port read,
 * which Windows never grants IOPL for, so it raises
 * STATUS_PRIVILEGED_INSTRUCTION every time -- caught here and treated as
 * "not VMware" (fail open), same VEH-wrap-one-instruction shape
 * runtime/anti_debug.c's CloseHandle trap already uses. Under VMware's
 * older (still widely deployed) software/hybrid execution engine, this
 * exact EAX/EDX signature is trapped and emulated *before* the usual
 * ring-3 IOPL check applies, and the hypervisor rewrites EBX to echo the
 * same magic number back as confirmation -- independent of, and not
 * reachable through, either CPUID check above (a hardened VM image that
 * masks CPUID entirely can still be caught here, and vice versa). */
static uint64_t karity_avm_check_vmware_backdoor(void)
{
    void *kernel32 = karity_resolve_module(KARITY_HASH_KERNEL32_DLL);
    karity_pfn_add_veh add_veh;
    karity_pfn_remove_veh remove_veh;
    void *veh;
    uint32_t eax, ebx, ecx, edx;
    uint64_t not_faulted, magic_echoed;

    if (!kernel32) return 0;
    add_veh = (karity_pfn_add_veh)karity_resolve_proc(kernel32, KARITY_HASH_ADD_VECTORED_EXCEPTION_HANDLER);
    remove_veh = (karity_pfn_remove_veh)karity_resolve_proc(kernel32, KARITY_HASH_REMOVE_VECTORED_EXCEPTION_HANDLER);
    if (!add_veh || !remove_veh) return 0;

    veh = add_veh(1, (void *)karity_avm_vmware_veh);
    if (!veh) return 0;

    g_avm_vmware_faulted = 0;
    eax = 0x564D5868u; /* 'VMXh' */
    ebx = 0;
    ecx = 0x0Au; /* GETVERSION */
    edx = 0x5658u; /* 'VX', backdoor port */
    __asm__ volatile("in %%dx, %%eax"
                      : "+a"(eax), "+b"(ebx), "+c"(ecx), "+d"(edx)
                      :
                      : "cc");

    remove_veh(veh);
    /* VMware iff the port read did NOT fault AND EBX came back echoing the
     * magic -- both branchless. "didn't fault" is the complement of the fault
     * flag's nz-mask; "echoed" is the complement of (ebx XOR magic)'s nz-mask
     * (all-ones exactly when ebx == the magic). */
    not_faulted = ~karity_avm_mask_nz((uint64_t)(uint32_t)g_avm_vmware_faulted);
    magic_echoed = ~karity_avm_mask_nz((uint64_t)(ebx ^ 0x564D5868u));
    return KARITY_AVM_TAINT_VMWARE_PORT & not_faulted & magic_echoed;
}

/* Many hypervisors trap-and-emulate CPUID (at minimum to fix up leaf 1's
 * own hypervisor-present bit and the vendor leaf above, whether or not
 * they let the guest execute it natively otherwise), which costs a real
 * VMEXIT/VMENTRY round trip -- typically thousands to tens of thousands of
 * cycles, versus a couple hundred for native CPUID. That gap is far
 * smaller than a full OS exception dispatch (see
 * runtime/anti_debug.c's hidden-int3 probe, which measures exactly that
 * and uses a much larger threshold for it), so this needs its own,
 * proportionally smaller-but-still-generous threshold -- large enough to
 * absorb ordinary scheduling jitter on bare metal, small enough to still
 * catch a genuine VMEXIT round trip. */
static uint64_t karity_avm_check_cpuid_timing(void)
{
    uint32_t regs[4];
    uint64_t t0, t1;

    t0 = karity_avm_rdtsc();
    karity_avm_cpuid(1, 0, regs);
    t1 = karity_avm_rdtsc();

    return KARITY_AVM_TAINT_CPUID_TIMING & karity_avm_mask_nz((uint64_t)((t1 - t0) > 200000ULL));
}

/* Side-effect-free CPUID-based checks -- safe to run unconditionally on the
 * scan path; the caller masks the result by whether the VM category is
 * enabled (see runtime/anti_debug.c). */
uint64_t karity_anti_vm_scan_passive(void)
{
    uint64_t taint = 0;
    taint |= karity_avm_check_hypervisor_bit();
    taint |= karity_avm_check_hypervisor_vendor();
    taint |= karity_avm_check_cpuid_timing();
    return taint;
}

/* The VMware backdoor probe raises a (self-caught) first-chance
 * privileged-instruction exception, which a debugger would see -- so the
 * caller only invokes this when the VM category is actually enabled, keeping
 * a --anti-vm-off binary free of that observable side effect. */
uint64_t karity_anti_vm_scan_active(void)
{
    return karity_avm_check_vmware_backdoor();
}

/* Everything, for the standalone hosted reporter (tests/test_anti_vm.c). */
uint64_t karity_anti_vm_scan(void)
{
    return karity_anti_vm_scan_passive() | karity_anti_vm_scan_active();
}
