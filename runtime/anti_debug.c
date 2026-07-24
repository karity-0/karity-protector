/*
 * runtime/anti_debug.c -- debugger-presence checks that feed a value
 * computation instead of a branch. See include/karity/anti_debug.h for the
 * why; this file is only the "what" -- one function per technique, combined
 * in karity_anti_debug_scan(), which *also* pulls in every technique from
 * runtime/anti_vm.c (hypervisor detection) and runtime/anti_sandbox.c
 * (automated-analysis-environment heuristics) and ORs their contributions
 * into the same result. Despite the filename, this function -- and the one
 * karity_anti_debug_taint value/watchdog thread it feeds -- is the single
 * combined "does this look like a live analyst instead of a real end
 * user" signal for all three categories, deliberately: three independent
 * taint values/thunks/watchdogs would just be three independent things to
 * find and neutralize instead of one. The name stayed "anti_debug" because
 * that's where this started (see look/todo.md); anti_vm.c/anti_sandbox.c
 * are later additions to the same funnel, not a parallel mechanism.
 *
 * Same discipline as runtime/nanomite_veh.c: no windows.h, PEB/CONTEXT/
 * EXCEPTION_POINTERS accessed by raw documented-in-practice offset, WinAPI
 * resolved by name hash via api_resolve.h so no plaintext import names sit
 * in the injected image. Compiled twice (see runtime/CMakeLists.txt): into
 * the freestanding runtime blob, and hosted (karity_anti_debug_hosted) for
 * tests/test_anti_debug.c, which validates several of these against the
 * test process's own (real, live, poke-able) PEB fields.
 *
 * Each check below (and in anti_vm.c/anti_sandbox.c) is independent and
 * self-contained -- deliberately not a table/array of function pointers
 * walked in a loop, which would itself be a single, easy-to-locate site to
 * patch (skip the loop, or zero the table). Each also returns its taint
 * contribution *directly* -- the taint constant when it fires, 0 when it
 * doesn't -- computed branchlessly (see karity_ad_mask_nz), rather than a
 * bool the aggregator branches on. That's the important part: the naive
 * `if (check()) taint |= CONST;` shape puts a `test/jz ... or imm` per check
 * right in the open, and each one can be defeated by NOPing a single branch
 * or OR. Here karity_anti_debug_scan() just ORs the checks' returned values
 * together with no per-check control flow at all, so there's no such edge to
 * cut; disabling a check means understanding and killing its arithmetic.
 * OR-combining keeps the result monotonic (any single technique firing makes
 * the whole thing nonzero, so nothing here needs a "majority vote" threshold
 * that could itself become a target), while still requiring an attacker to
 * trace and neutralize every contributing check across all three files, not
 * just the first one found. The only genuine branches left are the coarse
 * per-category execution gates around the few side-effecting/expensive
 * "active" probes (see karity_anti_debug_scan) -- everything passive is
 * fully branchless.
 */
#include "karity/anti_debug.h"

#include "karity/anti_sandbox.h"
#include "karity/anti_vm.h"

#include "api_resolve.h"

#define KARITY_STATUS_BREAKPOINT      0x80000003UL
#define KARITY_STATUS_INVALID_HANDLE  0xC0000008UL

#define KARITY_EXCEPTION_CONTINUE_EXECUTION ((int32_t)-1)
#define KARITY_EXCEPTION_CONTINUE_SEARCH    ((int32_t)0)

/* karity_hash_name() results, precomputed offline (h=5381; h=h*33+toupper(c)
 * per byte) -- see runtime/api_resolve.h. Kept numeric so the literal
 * module/API name strings never sit in the freestanding blob. The
 * kernel32.dll/AddVectoredExceptionHandler/RemoveVectoredExceptionHandler
 * values are the same ones runtime/nanomite_veh.c computed independently --
 * duplicated rather than shared, same "each file hand-rolls what it needs"
 * discipline the rest of this runtime already follows (see e.g. the
 * splitmix64 mix step appearing separately in include/karity/nanomite.h and
 * include/karity/bytecode_crypt.h). */
#define KARITY_HASH_KERNEL32_DLL                       0xBE1260896DDB9555ULL
#define KARITY_HASH_NTDLL_DLL                          0x0377A87F1EDAB0EDULL
#define KARITY_HASH_ADD_VECTORED_EXCEPTION_HANDLER     0xC63AE8E0277409F7ULL
#define KARITY_HASH_REMOVE_VECTORED_EXCEPTION_HANDLER  0x27AFCB413211D03CULL
#define KARITY_HASH_NT_QUERY_INFORMATION_PROCESS       0xC95EECB28CDC5DC2ULL
#define KARITY_HASH_GET_THREAD_CONTEXT                 0x9EE7CE626A967222ULL
#define KARITY_HASH_CLOSE_HANDLE                       0xBFC6A6CFFDB928E7ULL
#define KARITY_HASH_CREATE_THREAD                      0xB8BA6A0898BAAB11ULL
#define KARITY_HASH_SLEEP                              0x000000310E07CD7EULL

/* One distinct, arbitrary-bit-pattern constant per technique -- see the
 * file header for why OR-combining these (rather than e.g. walking a table)
 * matters. Values themselves carry no meaning beyond "nonzero and mutually
 * distinguishable"; nothing here or in any caller ever inspects which bits
 * are set. */
#define KARITY_AD_TAINT_BEING_DEBUGGED    0x1C80317FA3B1799DULL
#define KARITY_AD_TAINT_NT_GLOBAL_FLAG    0xBDD640FB06671AD1ULL
#define KARITY_AD_TAINT_HEAP_FORCE_FLAGS  0x3EB13B9046685257ULL
#define KARITY_AD_TAINT_DEBUG_PORT        0x23B8C1E9392456DFULL
#define KARITY_AD_TAINT_DEBUG_FLAGS       0x1A3D1FA7BC8960A9ULL
#define KARITY_AD_TAINT_DEBUG_OBJECT      0xBD9C66B3AD3C2D6DULL
#define KARITY_AD_TAINT_HW_BREAKPOINT     0x8B9D2434E465E151ULL
#define KARITY_AD_TAINT_CLOSEHANDLE_TRAP  0x972A846916419F83ULL
#define KARITY_AD_TAINT_HIDDEN_INT3       0x0822E8F36C031199ULL
#define KARITY_AD_TAINT_INT3_TIMING       0x17FC695A07A0CA6FULL

typedef int32_t (*karity_pfn_nt_query_information_process)(void *process, uint32_t info_class, void *info,
                                                             uint32_t info_len, uint32_t *return_len);
typedef int (*karity_pfn_get_thread_context)(void *thread, void *context);
typedef int (*karity_pfn_close_handle)(void *handle);
typedef void *(*karity_pfn_create_thread)(void *sec_attrs, uint64_t stack_size, void *start_addr, void *param,
                                           uint32_t flags, uint32_t *thread_id);
typedef void (*karity_pfn_sleep)(uint32_t ms);
typedef void *(*karity_pfn_add_veh)(uint32_t first, void *handler);
typedef uint32_t (*karity_pfn_remove_veh)(void *handle);

/* Mirrors EXCEPTION_POINTERS: { PEXCEPTION_RECORD; PCONTEXT; } -- same
 * minimal-by-offset style as runtime/nanomite_veh.c's own copy. */
typedef struct {
    void *exception_record;
    void *context_record;
} karity_ad_exception_pointers;

uint64_t karity_anti_debug_taint = 0;
uint32_t karity_anti_debug_enabled_categories = 0;

/* PRNG state for the poison selection below, seeded from RDTSC in
 * karity_anti_debug_init so it differs every process run. Advanced once per
 * published-taint update (init + every watchdog tick). */
static uint64_t g_ad_poison_state;

/* Decoy laundering sinks. An analyst's most direct route to this whole
 * mechanism is to breakpoint a well-known anti-analysis API
 * (NtQueryInformationProcess, GetThreadContext, CloseHandle, ...) and
 * forward-trace its return value -- straight to a mask, then the taint, then
 * the decryption-key XOR, exposing the entire detect->respond chain. To blunt
 * that, every API/PEB-derived raw value is *also* smeared into this bank via
 * meaningless arithmetic (karity_ad_smear, called from each check right where
 * the raw value is produced), and the live taint is round-tripped through the
 * bank net-neutrally on every publish (karity_ad_launder_roundtrip). So a
 * forward trace from any single API fans out into a spray of junk stores
 * going nowhere, and a backward slice from the published taint physically
 * runs through memory shared with pure-junk writes -- the real edge is buried
 * in decoys rather than sitting alone. `volatile` is load-bearing: nothing
 * ever reads this bank for a real decision, so without it the compiler would
 * dead-strip every laundering store and fold the net-neutral round-trip back
 * to the identity, undoing the whole point. This raises the cost of the
 * "breakpoint the API, follow the value" analysis; it does not make a precise
 * backward slice from the key XOR outright impossible (the honest remaining
 * limit -- see look/todo.md). */
static volatile uint64_t g_ad_decoy[6];

/* A fixed, pre-determined set of nonzero 64-bit "poison" values. When any
 * analysis check fires, one of these (rotated by a random amount) is folded
 * into the taint that gets XORed into the bytecode decryption key -- see
 * karity_ad_poison and the file/anti_debug.h headers. The SET is fixed at
 * build time ("pre-determined"), but WHICH one, and its rotation, are picked
 * pseudo-randomly per publish, so the exact corrupted key -- and therefore
 * where the decrypted bytecode first diverges from a correct decode, and how
 * it fails (bad opcode, wild jump, wrong memory access, wrong result) --
 * changes every run and drifts across a run as the watchdog republishes.
 * Two traces of a detected program can't be diffed to pin down the check:
 * they diverge in different places each time. Every entry has both its high
 * and low bit set so no rotation of any of them can be zero (a zero delta
 * would mean "clean" -- a false negative). */
#define KARITY_AD_POISON_COUNT 8u
static const uint64_t karity_ad_poison_table[KARITY_AD_POISON_COUNT] = {
    0xC952D459E3708D61ULL,
    0x9CE3ED08EC3C9BE5ULL,
    0xB1CE297410F5DB4DULL,
    0xCC66E5588769D801ULL,
    0x99966EC4A2A39067ULL,
    0xC6B1231FB19D7C77ULL,
    0x86B8A2E48B346591ULL,
    0x971733F41F2C5CFDULL,
};

static void *karity_ad_peb(void)
{
    void *peb;
    __asm__ volatile("mov %%gs:0x60, %0" : "=r"(peb));
    return peb;
}

static uint64_t karity_ad_rdtsc(void)
{
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

static void karity_ad_zero(void *dst, uint64_t n)
{
    uint8_t *b = (uint8_t *)dst;
    uint64_t i;
    for (i = 0; i < n; i++) b[i] = 0;
}

/* Same splitmix64 finalizer step already used (independently) by
 * include/karity/bytecode_crypt.h and include/karity/nanomite.h -- a tiny
 *, well-understood mix, not shared code, just the same public-domain
 * formula reappearing a third time. Only used here for watchdog sleep
 * jitter, where "not perfectly uniform" is irrelevant. */
static uint64_t karity_ad_mix64(uint64_t z)
{
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

/* Branchless boolean->mask conversion, the core of why the individual checks
 * below return a taint value directly instead of a bool the caller branches
 * on. The naive shape -- `if (check()) taint |= CONST;` -- compiles to a
 * visible `test/jz ... or [taint], imm` sequence per check: a pattern-matcher
 * (or a human) can locate every one and NOP the branch or the OR, defeating
 * each check independently with a one-instruction patch. Instead every check
 * folds its condition into an all-ones-or-zero mask with these (no `cmp`+
 * conditional-jump pair: `(v | -v) >> 63` is the sign bit of v|-v, which is
 * set for every v except 0), ANDs the taint constant with it, and the
 * aggregator just ORs the results with no branch at all -- so there's no
 * per-check control-flow edge to cut, and disabling one check means
 * understanding and neutralizing its arithmetic, not flipping one jcc. Same
 * "affect a value computation, not a branch" principle the whole taint funnel
 * is built on (see include/karity/anti_debug.h), applied one level down to
 * the checks' own internal aggregation. */
static uint64_t karity_ad_mask_nz(uint64_t v)
{
    return (uint64_t)0 - (uint64_t)((v | ((uint64_t)0 - v)) >> 63); /* ~0 if v!=0, else 0 */
}

static uint64_t karity_ad_mask_z(uint64_t v)
{
    return ~karity_ad_mask_nz(v); /* ~0 if v==0, else 0 */
}

/* All-ones if the given anti-analysis category is enabled this run, else 0
 * (see karity_anti_debug_enabled_categories). Also branchless, so the
 * category gate on the *value* (as opposed to the coarse execution gates
 * around the few side-effecting probes -- see karity_anti_debug_scan) is
 * likewise not a single jump that switches a whole category off. */
static uint64_t karity_ad_category_mask(uint32_t bit)
{
    return karity_ad_mask_nz((uint64_t)(karity_anti_debug_enabled_categories & bit));
}

/* Folds `v` (a raw API/PEB result, or the taint) into the decoy bank with
 * junk arithmetic -- rotations, an odd multiply, cross-slot XOR/mix -- so the
 * value visibly propagates into several unrelated-looking locations. Never
 * affects any real decision (nothing reads g_ad_decoy for one); its whole
 * purpose is to be a fan-out sink for data-flow tracing. See g_ad_decoy. */
static void karity_ad_smear(uint64_t v)
{
    uint64_t s0 = g_ad_decoy[0], s1 = g_ad_decoy[1], s2 = g_ad_decoy[2], s3 = g_ad_decoy[3];
    g_ad_decoy[0] = (s0 + v) * 0x9E3779B97F4A7C15ULL;
    g_ad_decoy[1] = s1 ^ ((v << 17) | (v >> 47));
    g_ad_decoy[2] = (s2 ^ v) + (s0 & v);
    g_ad_decoy[3] = s3 * 5u + (v ^ s1);
    g_ad_decoy[4] = karity_ad_mix64(g_ad_decoy[4] ^ v);
}

/* Physically routes the real taint `t` through the decoy bank and returns it
 * *exactly* unchanged (net-neutral), so a backward slice from the published
 * value runs through g_ad_decoy -- memory that karity_ad_smear also fills
 * with pure junk -- instead of a clean edge back to the checks. slot 5 holds
 * `t ^ old_junk` across the smears (which only touch slots 0-4), and the
 * final reload recovers t; `volatile` forces the store and reload to be real
 * memory traffic the compiler can't fold away. */
static uint64_t karity_ad_launder_roundtrip(uint64_t t)
{
    uint64_t pad = g_ad_decoy[5];
    g_ad_decoy[5] = t ^ pad;
    karity_ad_smear(t);
    karity_ad_smear(~t + 0x51ULL);
    return g_ad_decoy[5] ^ pad; /* == t, but forced through volatile memory */
}

/* Turns a raw scan result into the value actually published to
 * karity_anti_debug_taint. Clean (raw == 0) stays *exactly* 0 -- bit for bit,
 * so the XOR into the bytecode key in runtime/vm_thunk.S remains a true
 * no-op and a legitimate run is never affected (branchless: everything below
 * is ANDed with `detected`). When any check fired (raw != 0), it mixes in a
 * pseudo-randomly chosen, pseudo-randomly rotated entry from the fixed
 * karity_ad_poison_table so the published value -- and hence the corrupted
 * decryption key -- differs every run and drifts every watchdog tick. The
 * point is variety of *failure*: the same detected binary decodes a
 * different wrong instruction stream each time, so it crashes/loops/misbe-
 * haves in a different place on every run and two traces can't be diffed to
 * locate the check. Guaranteed nonzero when detected (the table entries all
 * have bit 63 set, rotation preserves nonzero-ness, and the final `| 1`
 * pins it regardless) so a detected run can never accidentally publish a
 * clean 0. */
static uint64_t karity_ad_poison(uint64_t raw)
{
    uint64_t detected = karity_ad_mask_nz(raw);
    uint64_t pick, rot, val;

    g_ad_poison_state = karity_ad_mix64(g_ad_poison_state + 0x9E3779B97F4A7C15ULL);
    pick = karity_ad_poison_table[g_ad_poison_state & (KARITY_AD_POISON_COUNT - 1u)];
    rot = (g_ad_poison_state >> 8) & 63u;
    val = (pick << rot) | (pick >> ((64u - rot) & 63u)); /* rotate-left, rot==0 safe */

    return ((raw ^ val) & detected) | (detected & 1ULL);
}

/* PEB->BeingDebugged (offset 0x02, BYTE). The oldest and most commonly
 * patched-around check in existence -- included anyway because it's still
 * one contribution among many, not the whole defense. */
static uint64_t karity_ad_check_being_debugged(void)
{
    uint8_t *peb = (uint8_t *)karity_ad_peb();
    uint8_t bd = peb[0x02];
    karity_ad_smear(bd); /* fan the raw PEB byte out into decoys (see g_ad_decoy) */
    return KARITY_AD_TAINT_BEING_DEBUGGED & karity_ad_mask_nz(bd);
}

/* PEB->NtGlobalFlag (offset 0xBC, DWORD, x64). The loader sets
 * FLG_HEAP_ENABLE_TAIL_CHECK|FLG_HEAP_ENABLE_FREE_CHECK|
 * FLG_HEAP_VALIDATE_PARAMETERS (0x70) here when the process was created
 * under a debugger -- independent of BeingDebugged, and less commonly
 * patched since fewer public snippets check it. */
static uint64_t karity_ad_check_nt_global_flag(void)
{
    uint8_t *peb = (uint8_t *)karity_ad_peb();
    uint32_t flags = *(uint32_t *)(peb + 0xBC);
    karity_ad_smear(flags);
    return KARITY_AD_TAINT_NT_GLOBAL_FLAG & karity_ad_mask_nz(flags & 0x70u);
}

/* PEB->ProcessHeap(+0x30)->ForceFlags(+0x74, DWORD, x64 classic NT heap
 * header). Windows forces extra heap validation (nonzero ForceFlags) on the
 * default process heap when a debugger is present at process creation --
 * lesser-known than NtGlobalFlag, and checks a completely different
 * subsystem's state, so a patch defeating one doesn't defeat the other.
 * Deliberately checks only ForceFlags (not the Flags field's exact bit
 * pattern next to it): ForceFlags nonzero is the one documented, version-
 * stable signal here; Flags' precise bit layout has drifted across Windows
 * releases and isn't worth the false-positive risk -- same "define what's
 * safe to define, leave the rest alone" stance as isa.h's OF-for-count>1
 * notes. */
static uint64_t karity_ad_check_heap_force_flags(void)
{
    uint8_t *peb = (uint8_t *)karity_ad_peb();
    uint8_t *heap = *(uint8_t **)(peb + 0x30);
    uint32_t force_flags;
    if (!heap) return 0; /* safety guard (can't deref null), not the detection decision -- the
                            "is it forced?" verdict below is what's kept branchless */
    force_flags = *(uint32_t *)(heap + 0x74);
    karity_ad_smear(force_flags);
    return KARITY_AD_TAINT_HEAP_FORCE_FLAGS & karity_ad_mask_nz(force_flags);
}

static void *karity_ad_resolve_ntdll(void)
{
    return karity_resolve_module(KARITY_HASH_NTDLL_DLL);
}

/* NtQueryInformationProcess(ProcessDebugPort=7): a ULONG_PTR that's -1 (all
 * bits set) when a usermode debugger is attached, 0 otherwise. Fails open
 * (returns "clean") if ntdll or the export can't be resolved -- same "wrong
 * is worse than nothing" stance as every other best-effort check in this
 * runtime. */
static uint64_t karity_ad_check_debug_port(void)
{
    void *ntdll = karity_ad_resolve_ntdll();
    karity_pfn_nt_query_information_process query;
    uint64_t debug_port = 0;
    int32_t status;

    if (!ntdll) return 0;
    query = (karity_pfn_nt_query_information_process)karity_resolve_proc(ntdll, KARITY_HASH_NT_QUERY_INFORMATION_PROCESS);
    if (!query) return 0;

    status = query((void *)(intptr_t)-1 /* GetCurrentProcess() pseudo handle */, 7 /* ProcessDebugPort */,
                    &debug_port, 8, 0);
    karity_ad_smear(debug_port ^ (uint64_t)(uint32_t)status);
    /* detected iff the call succeeded (status==0) AND the port is nonzero */
    return KARITY_AD_TAINT_DEBUG_PORT & karity_ad_mask_z((uint64_t)(uint32_t)status) & karity_ad_mask_nz(debug_port);
}

/* NtQueryInformationProcess(ProcessDebugFlags=0x1F): a ULONG that's really
 * EPROCESS->NoDebugInherit -- inverted from what the name suggests, 0 means
 * the process *is* being debugged, nonzero means it isn't. Independent
 * information source from ProcessDebugPort (different EPROCESS field
 * entirely), so a patch that only fakes the port doesn't fake this too. */
static uint64_t karity_ad_check_debug_flags(void)
{
    void *ntdll = karity_ad_resolve_ntdll();
    karity_pfn_nt_query_information_process query;
    uint32_t no_debug_inherit = 1;
    int32_t status;

    if (!ntdll) return 0;
    query = (karity_pfn_nt_query_information_process)karity_resolve_proc(ntdll, KARITY_HASH_NT_QUERY_INFORMATION_PROCESS);
    if (!query) return 0;

    status = query((void *)(intptr_t)-1, 0x1F /* ProcessDebugFlags */, &no_debug_inherit, 4, 0);
    karity_ad_smear(((uint64_t)no_debug_inherit << 32) ^ (uint64_t)(uint32_t)status);
    /* detected iff the call succeeded (status==0) AND NoDebugInherit is 0 */
    return KARITY_AD_TAINT_DEBUG_FLAGS & karity_ad_mask_z((uint64_t)(uint32_t)status) & karity_ad_mask_z(no_debug_inherit);
}

/* NtQueryInformationProcess(ProcessDebugObjectHandle=0x1E): succeeds with a
 * nonzero handle only while an actual debug object (i.e. a real attached
 * debugger) exists for this process; fails with STATUS_PORT_NOT_SET
 * otherwise. Lesser-known than the port/flags queries above -- most public
 * anti-debug snippets stop at ProcessDebugPort. */
static uint64_t karity_ad_check_debug_object_handle(void)
{
    void *ntdll = karity_ad_resolve_ntdll();
    karity_pfn_nt_query_information_process query;
    uint64_t handle = 0;
    int32_t status;

    if (!ntdll) return 0;
    query = (karity_pfn_nt_query_information_process)karity_resolve_proc(ntdll, KARITY_HASH_NT_QUERY_INFORMATION_PROCESS);
    if (!query) return 0;

    status = query((void *)(intptr_t)-1, 0x1E /* ProcessDebugObjectHandle */, &handle, 8, 0);
    karity_ad_smear(handle ^ (uint64_t)(uint32_t)status);
    /* detected iff the call succeeded (status==0) AND a nonzero handle came back */
    return KARITY_AD_TAINT_DEBUG_OBJECT & karity_ad_mask_z((uint64_t)(uint32_t)status) & karity_ad_mask_nz(handle);
}

/* GetThreadContext(current thread, CONTEXT_DEBUG_REGISTERS) -> Dr0..Dr3
 * nonzero means a hardware breakpoint is armed on this thread. CONTEXT
 * field offsets (x64): ContextFlags=0x30, Dr0=0x48, Dr1=0x50, Dr2=0x58,
 * Dr3=0x60 -- from the same well-established CONTEXT layout
 * runtime/nanomite_veh.c already relies on for CONTEXT.Rip at +0xF8 (Dr0's
 * offset here is internally consistent with that one: P1Home..P6Home
 * (0x00-0x2F) + ContextFlags/MxCsr/segment regs/EFlags (0x30-0x47) puts
 * Dr0 immediately after, at 0x48). Requesting the current thread's own
 * context is only reliably supported since Windows 8 -- on anything older
 * this either fails outright or (worse) silently returns a stale/zeroed
 * buffer, so a failed call is treated as "no breakpoints", same fail-open
 * stance as every resolution failure above. Needs a 16-byte-aligned
 * buffer (documented CONTEXT requirement); sized generously past the real
 * x64 CONTEXT (1232 bytes) since this file has no <windows.h> to take
 * sizeof(CONTEXT) from. */
static uint64_t karity_ad_check_hardware_breakpoints(void)
{
    void *kernel32 = karity_resolve_module(KARITY_HASH_KERNEL32_DLL);
    karity_pfn_get_thread_context get_ctx;
    unsigned char ctx_buf[1232] __attribute__((aligned(16)));
    uint64_t dr0, dr1, dr2, dr3;

    if (!kernel32) return 0;
    get_ctx = (karity_pfn_get_thread_context)karity_resolve_proc(kernel32, KARITY_HASH_GET_THREAD_CONTEXT);
    if (!get_ctx) return 0;

    karity_ad_zero(ctx_buf, sizeof(ctx_buf));
    *(uint32_t *)(ctx_buf + 0x30) = 0x00100010u; /* CONTEXT_AMD64 | CONTEXT_DEBUG_REGISTERS */

    if (!get_ctx((void *)(intptr_t)-2 /* GetCurrentThread() pseudo handle */, ctx_buf)) return 0;

    dr0 = *(uint64_t *)(ctx_buf + 0x48);
    dr1 = *(uint64_t *)(ctx_buf + 0x50);
    dr2 = *(uint64_t *)(ctx_buf + 0x58);
    dr3 = *(uint64_t *)(ctx_buf + 0x60);
    karity_ad_smear(dr0 ^ dr1);
    karity_ad_smear(dr2 ^ dr3);
    return KARITY_AD_TAINT_HW_BREAKPOINT & karity_ad_mask_nz(dr0 | dr1 | dr2 | dr3);
}

static volatile int g_ad_closehandle_trapped;

static int32_t karity_ad_closehandle_veh(karity_ad_exception_pointers *ep)
{
    uint32_t code = *(uint32_t *)ep->exception_record; /* ExceptionCode, +0x00 */
    if (code != KARITY_STATUS_INVALID_HANDLE) return KARITY_EXCEPTION_CONTINUE_SEARCH;
    g_ad_closehandle_trapped = 1;
    /* STATUS_INVALID_HANDLE is a documented continuable exception -- ntdll's
     * NtClose (the strict-handle-check path this trick relies on) tolerates
     * resuming right where it was raised, so no CONTEXT.Rip adjustment is
     * needed here (unlike the int3 probe below, which does need one). */
    return KARITY_EXCEPTION_CONTINUE_EXECUTION;
}

/* CloseHandle on a bogus handle: with no debugger attached, NtClose just
 * fails quietly (CloseHandle returns FALSE, no exception). Windows enables
 * "strict handle checking" whenever a debugger is attached, which makes the
 * exact same call raise STATUS_INVALID_HANDLE as a genuine first-chance
 * exception instead -- catchable with a VEH, which is exactly what this
 * does, briefly and only for the duration of one bogus CloseHandle call.
 * A well-known trick in security research circles, but the "installs a
 * temporary VEH around one call" shape (rather than a bare CloseHandle +
 * an obvious __except) makes it much less recognizable at a glance than
 * how it's usually written. */
static uint64_t karity_ad_check_closehandle_trap(void)
{
    void *kernel32 = karity_resolve_module(KARITY_HASH_KERNEL32_DLL);
    karity_pfn_add_veh add_veh;
    karity_pfn_remove_veh remove_veh;
    karity_pfn_close_handle close_handle;
    void *veh;
    int trapped;

    if (!kernel32) return 0;
    add_veh = (karity_pfn_add_veh)karity_resolve_proc(kernel32, KARITY_HASH_ADD_VECTORED_EXCEPTION_HANDLER);
    remove_veh = (karity_pfn_remove_veh)karity_resolve_proc(kernel32, KARITY_HASH_REMOVE_VECTORED_EXCEPTION_HANDLER);
    close_handle = (karity_pfn_close_handle)karity_resolve_proc(kernel32, KARITY_HASH_CLOSE_HANDLE);
    if (!add_veh || !remove_veh || !close_handle) return 0;

    veh = add_veh(1, (void *)karity_ad_closehandle_veh);
    if (!veh) return 0;

    g_ad_closehandle_trapped = 0;
    close_handle((void *)(intptr_t)0x11DEAD22); /* deliberately bogus, never a real open handle */
    trapped = g_ad_closehandle_trapped;

    remove_veh(veh);
    karity_ad_smear((uint64_t)(uint32_t)trapped * 0x100000001ULL);
    return KARITY_AD_TAINT_CLOSEHANDLE_TRAP & karity_ad_mask_nz((uint64_t)(uint32_t)trapped);
}

static volatile int g_ad_int3_reached;

static int32_t karity_ad_int3_veh(karity_ad_exception_pointers *ep)
{
    uint32_t code = *(uint32_t *)ep->exception_record; /* ExceptionCode, +0x00 */
    uint64_t *rip;

    if (code != KARITY_STATUS_BREAKPOINT) return KARITY_EXCEPTION_CONTINUE_SEARCH;
    g_ad_int3_reached = 1;
    rip = (uint64_t *)((uint8_t *)ep->context_record + 0xF8); /* CONTEXT.Rip */
    *rip += 1; /* skip the one-byte 0xCC we just executed */
    return KARITY_EXCEPTION_CONTINUE_EXECUTION;
}

/* "Hidden" int3: without any debugger attached, a self-installed VEH is
 * always the first (and here, only) handler Windows offers a first-chance
 * exception to, so executing a bare `int3` and having our own VEH catch it
 * is the deterministic, fast, expected outcome. The moment a real debugger
 * is attached, standard first-chance exception handling offers it to the
 * *debugger* before any of the target process's own handlers ever run --
 * an interactive debugger typically stops there outright (our VEH then
 * never runs at all: g_ad_int3_reached stays 0, itself already
 * suspicious), and even a debugger configured to pass the exception
 * through adds kernel-mediated round-trip latency neither path has any
 * reason to pay otherwise -- caught by the RDTSC delta below. Two
 * independent signals from one probe: "did our handler even run" and "how
 * long did the whole round trip take". The generous threshold (tens of
 * millions of cycles -- multiple orders of magnitude past a normal
 * exception dispatch's cost, typically thousands to low hundred-thousands
 * of cycles even on a loaded system) is deliberately loose to avoid
 * flagging scheduler jitter or a slow VM as a debugger. */
static uint64_t karity_ad_check_hidden_int3(void)
{
    void *kernel32 = karity_resolve_module(KARITY_HASH_KERNEL32_DLL);
    karity_pfn_add_veh add_veh;
    karity_pfn_remove_veh remove_veh;
    void *veh;
    uint64_t t0, t1, elapsed, taint;

    if (!kernel32) return 0;
    add_veh = (karity_pfn_add_veh)karity_resolve_proc(kernel32, KARITY_HASH_ADD_VECTORED_EXCEPTION_HANDLER);
    remove_veh = (karity_pfn_remove_veh)karity_resolve_proc(kernel32, KARITY_HASH_REMOVE_VECTORED_EXCEPTION_HANDLER);
    if (!add_veh || !remove_veh) return 0;

    veh = add_veh(1, (void *)karity_ad_int3_veh);
    if (!veh) return 0;

    g_ad_int3_reached = 0;
    t0 = karity_ad_rdtsc();
    __asm__ volatile("int3");
    t1 = karity_ad_rdtsc();

    remove_veh(veh);

    /* Two independent signals, both branchless: "our handler never ran"
     * (g_ad_int3_reached still 0) and "the round trip took absurdly long".
     * `elapsed > threshold` is a setcc, not a jump; mask_nz turns it into
     * the timing taint constant. mask_z(reached) contributes the primary
     * taint when the handler was skipped entirely. */
    elapsed = t1 - t0;
    karity_ad_smear(elapsed ^ ((uint64_t)(uint32_t)g_ad_int3_reached << 40));
    taint = KARITY_AD_TAINT_HIDDEN_INT3 & karity_ad_mask_z((uint64_t)(uint32_t)g_ad_int3_reached);
    taint |= KARITY_AD_TAINT_INT3_TIMING & karity_ad_mask_nz((uint64_t)(elapsed > 50000000ULL));
    return taint;
}

/* Combines every enabled detection technique into one taint value. Two
 * classes of check, treated differently:
 *
 *  - PASSIVE checks (all the debug queries above except the two exception
 *    probes, plus anti_vm's CPUID checks and anti_sandbox's PEB/quota
 *    checks) are side-effect-free and cheap, so they run *unconditionally*
 *    and their contribution is masked by a branchless per-category mask.
 *    There is deliberately no `if (enabled & CAT)` around them: a category
 *    being off is expressed purely as an AND with a zero mask, so no single
 *    control-flow edge switches a whole category's detection off (nor does
 *    any single per-check branch -- see karity_ad_mask_nz's comment). When a
 *    category is off, its checks still run but contribute 0; when on, the
 *    mask is all-ones and they contribute normally. Passive debug checks
 *    running under a debugger with --anti-debug *off* is harmless: they read
 *    PEB fields, raise nothing, and their result is masked away.
 *
 *  - ACTIVE probes (the CloseHandle and int3 debug probes; anti_vm's VMware
 *    backdoor; anti_sandbox's Sleep-skew) each either raise a first-chance
 *    exception (debugger-observable) or cost real wall-clock time, so unlike
 *    the passive checks they must NOT run when their category is off -- a
 *    program built without --anti-debug must stay completely transparent to
 *    a debugger, and one without --anti-sandbox must not eat 300ms at
 *    startup. These few get a genuine execution gate. That gate switches
 *    only these side-effecting probes, not a whole category's detection
 *    (the passive checks for the same category are already covering it
 *    branchlessly), so it's not the single "disable everything" edge the
 *    per-check branches used to be. Contributions are still mask-ANDed for
 *    defense in depth. */
uint64_t karity_anti_debug_scan(void)
{
    uint64_t taint = 0;
    uint64_t debug_mask = karity_ad_category_mask(KARITY_ANTI_ANALYSIS_DEBUG);
    uint64_t vm_mask = karity_ad_category_mask(KARITY_ANTI_ANALYSIS_VM);
    uint64_t sandbox_mask = karity_ad_category_mask(KARITY_ANTI_ANALYSIS_SANDBOX);
    uint64_t passive = 0;

    /* passive debug checks -- run always, contribute only through debug_mask */
    passive |= karity_ad_check_being_debugged();
    passive |= karity_ad_check_nt_global_flag();
    passive |= karity_ad_check_heap_force_flags();
    passive |= karity_ad_check_debug_port();
    passive |= karity_ad_check_debug_flags();
    passive |= karity_ad_check_debug_object_handle();
    passive |= karity_ad_check_hardware_breakpoints();
    taint |= passive & debug_mask;

    /* passive VM / sandbox checks -- likewise unconditional, masked by category */
    taint |= karity_anti_vm_scan_passive() & vm_mask;
    taint |= karity_anti_sandbox_scan_passive() & sandbox_mask;

    /* active, side-effecting probes -- genuinely gated on their category (see
     * the function comment), then still mask-ANDed */
    if (karity_anti_debug_enabled_categories & KARITY_ANTI_ANALYSIS_DEBUG) {
        uint64_t probes = karity_ad_check_closehandle_trap() | karity_ad_check_hidden_int3();
        taint |= probes & debug_mask;
    }
    if (karity_anti_debug_enabled_categories & KARITY_ANTI_ANALYSIS_VM) {
        taint |= karity_anti_vm_scan_active() & vm_mask;
    }
    if (karity_anti_debug_enabled_categories & KARITY_ANTI_ANALYSIS_SANDBOX) {
        taint |= karity_anti_sandbox_scan_active() & sandbox_mask;
    }

    return taint;
}

/* Watchdog thread body: re-runs the full scan and republishes the result
 * for as long as the process lives, closing the "check once at startup,
 * attach a debugger afterward" gap a single install-time check leaves
 * open. karity_anti_debug_taint is a naturally-aligned 8-byte global, so
 * this plain store is atomic on x64 with no lock needed against
 * runtime/vm_thunk.S's read. */
static uint32_t karity_ad_watchdog_proc(void *param)
{
    void *kernel32;
    karity_pfn_sleep sleep_fn;
    uint64_t jitter_state = karity_ad_rdtsc();
    (void)param;

    kernel32 = karity_resolve_module(KARITY_HASH_KERNEL32_DLL);
    sleep_fn = kernel32 ? (karity_pfn_sleep)karity_resolve_proc(kernel32, KARITY_HASH_SLEEP) : 0;
    if (!sleep_fn) return 0; /* no Sleep -> can't run a bounded loop responsibly; bail, initial
                                 scan result (already published before this thread started)
                                 stays live but un-refreshed -- fail open, not a busy spin */

    for (;;) {
        jitter_state = karity_ad_mix64(jitter_state);
        sleep_fn(200u + (uint32_t)(jitter_state % 300u)); /* 200-500ms, jittered so the interval
                                                               itself isn't a fixed, greppable
                                                               constant in a timeline trace */
        /* Republish through karity_ad_poison: a *clean* scan stays exactly 0
         * (no-op key XOR), a *detected* one gets a freshly randomized poison
         * each tick -- so the corrupted-key value, and thus where/how a
         * detected program misbehaves, drifts over the process's lifetime as
         * well as differing run-to-run. The scan result is first round-tripped
         * through the decoy bank (net-neutral) so the value's data flow is
         * entangled with junk -- see g_ad_decoy. */
        karity_anti_debug_taint =
            karity_ad_poison(karity_ad_launder_roundtrip(karity_anti_debug_scan()));
    }
}

int karity_anti_debug_init(uint32_t enabled_categories)
{
    void *kernel32;
    karity_pfn_create_thread create_thread;
    karity_pfn_close_handle close_handle;
    void *thread;

    karity_anti_debug_enabled_categories = enabled_categories;
    /* Seed the poison PRNG from the cycle counter so the first (and every)
     * published poison differs per process run -- the whole point is that a
     * detected binary's failure isn't reproducible across runs. */
    g_ad_poison_state = karity_ad_rdtsc();
    karity_anti_debug_taint =
        karity_ad_poison(karity_ad_launder_roundtrip(karity_anti_debug_scan()));

    kernel32 = karity_resolve_module(KARITY_HASH_KERNEL32_DLL);
    if (!kernel32) return 1;
    create_thread = (karity_pfn_create_thread)karity_resolve_proc(kernel32, KARITY_HASH_CREATE_THREAD);
    close_handle = (karity_pfn_close_handle)karity_resolve_proc(kernel32, KARITY_HASH_CLOSE_HANDLE);
    if (!create_thread || !close_handle) return 1;

    thread = create_thread(0, 0, (void *)karity_ad_watchdog_proc, 0, 0, 0);
    if (thread) close_handle(thread); /* fire-and-forget: the thread itself needs no handle to
                                          keep running, only the process needs to still be alive */
    return 1;
}
