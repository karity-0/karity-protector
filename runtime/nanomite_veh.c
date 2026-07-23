/*
 * runtime/nanomite_veh.c -- exception-based trap/decrypt/execute handler.
 *
 * On a fault at a known trap site, reconstructs the original ciphertext
 * (the marker clobbered a few bytes of it in place -- see
 * include/karity/nanomite.h), decrypts it into a per-thread scratch slot
 * with an appended indirect jump back to the resume point, and redirects
 * the faulting thread's RIP there.
 *
 * No windows.h: EXCEPTION_POINTERS/EXCEPTION_RECORD/CONTEXT are accessed by
 * raw offset (documented below) rather than through struct definitions, the
 * same style runtime/vm_thunk.S already uses for karity_vmctx and
 * runtime/api_resolve.c uses for the PE/PEB structures -- these offsets are
 * part of the stable, documented-enough-in-practice x64 Windows ABI (every
 * one of them is the same trick public shellcode/exception-hook writeups
 * use), and avoids finding out the hard way whether windows.h's CONTEXT
 * definition survives -ffreestanding -fno-builtin cleanly.
 */
#include "nanomite_veh.h"

#include "api_resolve.h"

#define KARITY_NANOMITE_SCRATCH_SLOTS 64u
/* Worst case is a full-size block ending in a Jcc: a rewritten short Jcc (2
 * bytes) plus *two* absolute-indirect jumps, one per outgoing edge (14 bytes
 * each: FF 15/25 00000000 + abs VA) -- 2 + 14 + 14 = 30 bytes, more than the
 * CALL case's push+jmp (6 bytes each) + two 8-byte VAs = 28 -- see
 * karity_nanomite_veh's branch_kind handling. */
#define KARITY_NANOMITE_TRAILER_MAX 30u
#define KARITY_NANOMITE_SLOT_SIZE (KARITY_NANOMITE_MAX_BLOCK + KARITY_NANOMITE_TRAILER_MAX)

#define KARITY_STATUS_ILLEGAL_INSTRUCTION     0xC000001DUL
#define KARITY_STATUS_PRIVILEGED_INSTRUCTION  0xC0000096UL

#define KARITY_EXCEPTION_CONTINUE_EXECUTION ((int32_t)-1)
#define KARITY_EXCEPTION_CONTINUE_SEARCH    ((int32_t)0)

/* karity_hash_name() results, precomputed offline -- see runtime/api_resolve.h.
 * Kept numeric so the literal API/module name strings never sit in the
 * freestanding blob. */
#define KARITY_HASH_KERNEL32_DLL                       0xBE1260896DDB9555ULL
#define KARITY_HASH_ADD_VECTORED_EXCEPTION_HANDLER     0xC63AE8E0277409F7ULL
#define KARITY_HASH_REMOVE_VECTORED_EXCEPTION_HANDLER  0x27AFCB413211D03CULL
#define KARITY_HASH_VIRTUAL_ALLOC                      0xC5DF5A3B097BC257ULL
#define KARITY_HASH_VIRTUAL_FREE                       0xC02D8E5EE144A60EULL

#define KARITY_MEM_COMMIT             0x1000u
#define KARITY_MEM_RESERVE            0x2000u
#define KARITY_MEM_RELEASE            0x8000u
#define KARITY_PAGE_EXECUTE_READWRITE 0x40u

typedef void *(*karity_pfn_add_veh)(uint32_t first, void *handler);
typedef uint32_t (*karity_pfn_remove_veh)(void *handle);
typedef void *(*karity_pfn_virtual_alloc)(void *addr, uint64_t size, uint32_t alloc_type, uint32_t protect);
typedef int (*karity_pfn_virtual_free)(void *addr, uint64_t size, uint32_t free_type);

/* Mirrors EXCEPTION_POINTERS: { PEXCEPTION_RECORD; PCONTEXT; }, two
 * pointers -- kept minimal rather than pulling in windows.h. */
typedef struct {
    void *exception_record;
    void *context_record;
} karity_exception_pointers;

static const karity_nanomite_site *g_sites;
static uint32_t g_site_count;
static uint64_t g_anchor;
static uint8_t *g_scratch;
static void *g_veh_handle;
static karity_pfn_remove_veh g_remove_veh;
static karity_pfn_virtual_free g_virtual_free;

static uint64_t karity_nanomite_current_tid(void)
{
    uint64_t tid;
    __asm__ volatile("mov %%gs:0x48, %0" : "=r"(tid)); /* TEB.ClientId.UniqueThread */
    return tid;
}

/* Not a cryptographic distribution, just enough mixing that thread IDs
 * (which cluster in the low bits on Windows) don't collapse onto a handful
 * of slots. Two faulting threads landing on the same slot at the same time
 * is a known, undefended race in this first cut -- see the block comment
 * in karity_nanomite_install. */
static uint32_t karity_nanomite_pick_slot(void)
{
    uint64_t mixed = (karity_nanomite_current_tid() >> 2) * 2654435761ULL;
    return (uint32_t)(mixed % KARITY_NANOMITE_SCRATCH_SLOTS);
}

/* Writes the 6-byte `FF <op2> <disp32>` instruction only (`jmp`/`call`
 * qword ptr [rip+disp32], op2 0x25/0x15) -- an indirect control transfer
 * through an absolute address stored elsewhere in the block.
 * Address-range-independent: unlike a rel32 form, this reaches anywhere in
 * the 64-bit address space, which matters because the scratch slot
 * (VirtualAlloc, no placement hint) can land arbitrarily far from its
 * target. The 8-byte pointer itself is written separately via
 * karity_nanomite_write_u64, since for a CALL the two can't simply be
 * adjacent (see karity_nanomite_veh's branch_kind handling: a `call`'s own
 * auto-pushed return address lands right after these 6 bytes, which is
 * where the pointer data would otherwise sit). */
static void karity_nanomite_write_ff6(uint8_t *dst, uint8_t op2, int32_t disp32)
{
    uint32_t udisp = (uint32_t)disp32;
    dst[0] = 0xFF;
    dst[1] = op2;
    dst[2] = (uint8_t)(udisp >> 0);
    dst[3] = (uint8_t)(udisp >> 8);
    dst[4] = (uint8_t)(udisp >> 16);
    dst[5] = (uint8_t)(udisp >> 24);
}

static void karity_nanomite_write_u64(uint8_t *dst, uint64_t v)
{
    uint32_t i;
    for (i = 0; i < 8; i++) {
        dst[i] = (uint8_t)(v >> (8 * i));
    }
}

/* Writes the 2-byte short-form `Jcc rel8` (opcode 0x70|cc). Only ever used
 * inside the JCC trampoline below, where disp8 is a small, purely local
 * displacement within the same scratch slot -- unlike the original
 * rel8/rel32 Jcc it replaces, it never needs address-range fixup, so a
 * literal short jump (not an absolute-indirect one, which doesn't exist in
 * a conditional form on x86) is always correct here. */
static void karity_nanomite_write_short_jcc(uint8_t *dst, uint8_t cc, uint8_t disp8)
{
    dst[0] = (uint8_t)(0x70 | (cc & 0x0Fu));
    dst[1] = disp8;
}

static const karity_nanomite_site *karity_nanomite_find_site(uint64_t fault_rip)
{
    uint32_t i;
    for (i = 0; i < g_site_count; i++) {
        uint64_t trap_va = (uint64_t)((int64_t)g_anchor + g_sites[i].trap_delta);
        if (trap_va == fault_rip) return &g_sites[i];
    }
    return 0;
}

static int32_t karity_nanomite_veh(karity_exception_pointers *ep)
{
    uint32_t code;
    uint64_t fault_rip;
    const karity_nanomite_site *site;
    uint8_t cipher[KARITY_NANOMITE_MAX_BLOCK];
    uint8_t *slot;
    uint64_t resume_va;
    uint32_t i;

    code = *(uint32_t *)ep->exception_record; /* EXCEPTION_RECORD.ExceptionCode, +0x00 */
    if (code != KARITY_STATUS_ILLEGAL_INSTRUCTION && code != KARITY_STATUS_PRIVILEGED_INSTRUCTION) {
        return KARITY_EXCEPTION_CONTINUE_SEARCH;
    }
    fault_rip = *(uint64_t *)((uint8_t *)ep->exception_record + 0x10); /* ExceptionAddress */

    site = karity_nanomite_find_site(fault_rip);
    if (!site || site->block_len > KARITY_NANOMITE_MAX_BLOCK || site->marker_len > site->block_len ||
        site->branch_len > site->block_len) {
        return KARITY_EXCEPTION_CONTINUE_SEARCH;
    }

    /* Reconstruct the full ciphertext: the marker clobbered the first
     * marker_len bytes in the image (saved in site->clobbered); the rest
     * of the block is still sitting there untouched. */
    for (i = 0; i < site->marker_len; i++) {
        cipher[i] = site->clobbered[i];
    }
    for (i = site->marker_len; i < site->block_len; i++) {
        cipher[i] = ((const uint8_t *)(uintptr_t)fault_rip)[i];
    }
    karity_nanomite_xor_crypt(cipher, site->block_len, site->prng_seed);

    slot = g_scratch + (uint64_t)karity_nanomite_pick_slot() * KARITY_NANOMITE_SLOT_SIZE;
    resume_va = (uint64_t)((int64_t)g_anchor + site->resume_delta);

    if (site->branch_kind == KARITY_NANOMITE_BRANCH_NONE) {
        for (i = 0; i < site->block_len; i++) {
            slot[i] = cipher[i];
        }
        karity_nanomite_write_ff6(slot + site->block_len, 0x25, 0);
        karity_nanomite_write_u64(slot + site->block_len + 6, resume_va);
    } else if (site->branch_kind == KARITY_NANOMITE_BRANCH_JCC) {
        /* The block's trailing branch_len bytes are the original short/near
         * Jcc -- its rel8/rel32 target is correct only from its original
         * address, so drop it and re-test the (already real, since every
         * plain instruction before it was copied and re-executed verbatim
         * above) EFLAGS with a rewritten short Jcc that only needs to reach
         * a handful of local bytes, picking between two absolute-indirect
         * jumps -- x86 has no absolute-indirect *conditional* jump, so this
         * is the closest equivalent (see include/karity/nanomite.h):
         *   [Jcc cc, +14]                      <- tests real EFLAGS
         *   [jmp abs, reads fallthrough_va]     (14 bytes, not-taken path)
         *   [jmp abs, reads taken_va]           (14 bytes, taken path)
         * disp8=14 skips exactly over the "not-taken" jmp to land on the
         * "taken" jmp; falling through (condition false) runs the
         * "not-taken" jmp immediately instead. site->resume_delta doubles
         * as the not-taken/fallthrough target for this branch_kind, so
         * `resume_va` computed above already *is* that target. */
        uint32_t plain_len = site->block_len - site->branch_len;
        uint64_t taken_va = (uint64_t)((int64_t)g_anchor + site->branch_target_delta);

        for (i = 0; i < plain_len; i++) {
            slot[i] = cipher[i];
        }
        karity_nanomite_write_short_jcc(slot + plain_len, site->branch_cc, 14);
        karity_nanomite_write_ff6(slot + plain_len + 2, 0x25, 0);
        karity_nanomite_write_u64(slot + plain_len + 8, resume_va);
        karity_nanomite_write_ff6(slot + plain_len + 16, 0x25, 0);
        karity_nanomite_write_u64(slot + plain_len + 22, taken_va);
    } else {
        /* The block's trailing branch_len bytes are the original E8/E9
         * rel32 CALL/JMP -- correct only from its original address, not
         * from here, so drop them and synthesize an absolute indirect
         * transfer instead (see include/karity/nanomite.h). */
        uint32_t plain_len = site->block_len - site->branch_len;
        uint64_t target_va = (uint64_t)((int64_t)g_anchor + site->branch_target_delta);

        for (i = 0; i < plain_len; i++) {
            slot[i] = cipher[i];
        }
        if (site->branch_kind == KARITY_NANOMITE_BRANCH_CALL) {
            /* NOT a real `call`: its auto-pushed return address would land
             * right here in this VirtualAlloc'd scratch slot -- memory with
             * no RUNTIME_FUNCTION/UNWIND_INFO coverage at all (it isn't part
             * of any PE module). If the callee (or anything further down
             * its own call chain) raises an exception instead of returning
             * normally, RtlDispatchException's frame-by-frame unwind has to
             * resolve that return address to keep walking -- finding no
             * entry for it, it falls back to treating it as a leaf (pop one
             * return address and stop), which is wrong here: this "leaf"
             * was never a real call boundary, so that fallback consumes a
             * stack slot that actually belongs to the *real* caller further
             * up (this block's own original caller, e.g. main()), landing
             * on garbage and derailing the rest of the walk -- see
             * look/todo.md's former "nanomite interaction" gap for how this
             * was found (a genuine, unrelated hardware fault inside a
             * same-module callee reached through a CALL-kind nanomite block
             * never made it to the process's top-level handler).
             *
             * Fix: push `resume_va` ourselves -- a real address back in the
             * original image, already covered by *that* function's own real
             * UNWIND_INFO -- as the fake return address, then `jmp` (not
             * `call`) to the callee. A normal return lands directly on
             * resume_va with no extra indirection; an escaping exception
             * unwinds through a perfectly ordinary, already-valid frame
             * instead of this slot. Neither instruction touches a GPR
             * (`push`/`jmp` through RIP-relative memory operands), matching
             * every other transfer here in never clobbering the original
             * instruction's registers.
             *   [push qword ptr [rip+6], reads resume_va]
             *   [jmp qword ptr [rip+8], reads target_va]
             *   [resume_va]
             *   [target_va]
             */
            karity_nanomite_write_ff6(slot + plain_len, 0x35, 6);
            karity_nanomite_write_ff6(slot + plain_len + 6, 0x25, 8);
            karity_nanomite_write_u64(slot + plain_len + 12, resume_va);
            karity_nanomite_write_u64(slot + plain_len + 20, target_va);
        } else { /* KARITY_NANOMITE_BRANCH_JMP: unconditional, nothing to resume,
                    so the pointer data can sit immediately after it like the
                    plain-block case does */
            karity_nanomite_write_ff6(slot + plain_len, 0x25, 0);
            karity_nanomite_write_u64(slot + plain_len + 6, target_va);
        }
    }

    *(uint64_t *)((uint8_t *)ep->context_record + 0xF8) = (uint64_t)(uintptr_t)slot; /* CONTEXT.Rip */
    return KARITY_EXCEPTION_CONTINUE_EXECUTION;
}

int karity_nanomite_install(const karity_nanomite_site *sites, uint32_t site_count, uint64_t anchor)
{
    void *kernel32;
    karity_pfn_add_veh add_veh;
    karity_pfn_virtual_alloc virtual_alloc;

    kernel32 = karity_resolve_module(KARITY_HASH_KERNEL32_DLL);
    if (!kernel32) return 0;

    add_veh = (karity_pfn_add_veh)karity_resolve_proc(kernel32, KARITY_HASH_ADD_VECTORED_EXCEPTION_HANDLER);
    g_remove_veh = (karity_pfn_remove_veh)karity_resolve_proc(kernel32, KARITY_HASH_REMOVE_VECTORED_EXCEPTION_HANDLER);
    virtual_alloc = (karity_pfn_virtual_alloc)karity_resolve_proc(kernel32, KARITY_HASH_VIRTUAL_ALLOC);
    g_virtual_free = (karity_pfn_virtual_free)karity_resolve_proc(kernel32, KARITY_HASH_VIRTUAL_FREE);
    if (!add_veh || !g_remove_veh || !virtual_alloc || !g_virtual_free) return 0;

    /*
     * Known limitation of this first cut: one shared scratch region, slot
     * picked by (mixed) thread ID rather than a true per-thread allocation
     * -- two threads whose IDs happen to mix to the same slot and fault at
     * the same time will stomp each other's decrypted block. Fine for a
     * single-threaded proof of the trap/decrypt/execute/resume cycle; a
     * real per-thread slot table (or a lock held for the full decrypted-
     * block execution, not just the decrypt step) is follow-up work before
     * this is safe under real multithreaded load.
     */
    g_scratch = (uint8_t *)virtual_alloc(0, (uint64_t)KARITY_NANOMITE_SCRATCH_SLOTS * KARITY_NANOMITE_SLOT_SIZE,
                                          KARITY_MEM_COMMIT | KARITY_MEM_RESERVE, KARITY_PAGE_EXECUTE_READWRITE);
    if (!g_scratch) return 0;

    g_sites = sites;
    g_site_count = site_count;
    g_anchor = anchor;

    g_veh_handle = add_veh(1, (void *)karity_nanomite_veh);
    if (!g_veh_handle) {
        g_virtual_free(g_scratch, 0, KARITY_MEM_RELEASE);
        g_scratch = 0;
        return 0;
    }
    return 1;
}

void karity_nanomite_uninstall(void)
{
    if (g_veh_handle && g_remove_veh) {
        g_remove_veh(g_veh_handle);
        g_veh_handle = 0;
    }
    if (g_scratch && g_virtual_free) {
        g_virtual_free(g_scratch, 0, KARITY_MEM_RELEASE);
        g_scratch = 0;
    }
}
