/*
 * include/karity/anti_debug.h -- debugger/hypervisor/sandbox-presence
 * signals folded into a value computation, not a branch (see
 * look/todo.md section C). Despite the filename, "detection technique"
 * here spans three categories, all feeding the exact same taint value:
 * debugger presence (this file's own checks, runtime/anti_debug.c),
 * hypervisor presence (include/karity/anti_vm.h, runtime/anti_vm.c), and
 * automated-analysis-sandbox heuristics (include/karity/anti_sandbox.h,
 * runtime/anti_sandbox.c). One combined funnel rather than three parallel
 * ones is deliberate -- see runtime/anti_debug.c's own header for why.
 *
 * Every other anti-* mechanism in this project so far (nanomites, the SEH
 * fix, opcode rolling decryption) protects *code*. This protects a *check*:
 * the naive shape ("if (IsDebuggerPresent()) ExitProcess(1);") is trivial to
 * defeat once found, because finding it is easy -- it's a single compare
 * immediately followed by a jump to a visibly-abnormal exit path, and every
 * public disassembler/decompiler highlights exactly that shape. Patching it
 * out is a one-byte flip (the Jcc's condition, or just NOP the branch).
 *
 * Instead, karity_anti_debug_taint() runs a battery of independent
 * detection techniques (see runtime/anti_debug.c) and combines their
 * results into a single 64-bit value that is *supposed to be* 0 when the
 * environment looks clean, and unpredictably nonzero otherwise -- there is
 * no comparison against a "detected" sentinel anywhere in this file's
 * consumer. runtime/vm_thunk.S XORs the live value of that computation
 * (karity_anti_debug_taint, refreshed by a background watchdog thread --
 * see karity_anti_debug_init below) into ctx->bytecode_key_seed on every
 * single VM entry, *before* it's used to key this site's bytecode
 * decryption (include/karity/bytecode_crypt.h). When clean, the XOR is a
 * no-op and decryption is unaffected; the moment any check trips, every
 * subsequent VM invocation decrypts its bytecode with the wrong key and
 * runs garbage -- some wrong instruction stream, possibly a crash, possibly
 * just a wrong answer, always far away (in both code distance and time)
 * from whichever individual check actually tripped. There is no single
 * site to patch: an attacker has to find and neutralize *every*
 * contributing technique's effect on the taint value, not one branch.
 *
 * The value published on detection is not fixed. A clean scan publishes
 * exactly 0 (the XOR stays a true no-op -- legitimate runs are never
 * touched), but a scan that fired mixes in a pseudo-randomly chosen,
 * pseudo-randomly rotated entry from a fixed, pre-determined poison table
 * (see runtime/anti_debug.c's karity_ad_poison), reseeded from the cycle
 * counter each process run and re-rolled on every watchdog tick. So a
 * detected binary decrypts a *different* wrong instruction stream every run
 * -- and even drifts within a single run -- crashing, looping, or producing
 * a wrong result in a different place each time. Two traces of a detected
 * program therefore diverge from a correct trace at different points, so an
 * analyst can't diff them against each other to pin down which check fired
 * or where the tamper response lives; the failure is deliberately a moving
 * target rather than one reproducible fault.
 *
 * This is a mitigation, not a proof -- same stance as opcode randomization
 * and rolling decryption before it (see their own "남은 한계" writeups in
 * look/todo.md). A sufficiently patient attacker with a kernel debugger or
 * a hypervisor-based analysis platform can still defeat individual
 * techniques, or single-step through karity_anti_debug_taint() itself to
 * see which check(s) fire and reverse-engineer the combination formula. The
 * point is raising the cost from "flip one byte" to "fully reverse a
 * multi-technique, watchdog-refreshed value computation before touching
 * anything else."
 *
 * All three categories are opt-in (see KARITY_ANTI_ANALYSIS_* and
 * karity_anti_debug_init below) -- none run unless the corresponding
 * --anti-debug/--anti-vm/--anti-sandbox flag was passed at protect time.
 * The categories still differ sharply in *how safe they are to enable*, and
 * that difference is real, not cosmetic: a genuine end user is essentially
 * never "being debugged", but a substantial and entirely legitimate fraction
 * of real deployments run *inside a VM* on purpose (cloud desktops, corporate
 * VDI, Parallels/VMware Fusion, Windows Sandbox, CI) -- so --anti-vm in
 * particular will corrupt decryption for users who did nothing wrong, and
 * must be a deliberate choice. This was empirically confirmed, not just
 * theorized: this project's own build/test machine turned out to itself be
 * running under a hypervisor the first time anti-VM detection was tried here
 * (see look/todo.md). anti-sandbox's heuristics (Sandboxie's injected DLL,
 * unusually low CPU/RAM, a suspiciously fresh boot, a hooked/skipped Sleep)
 * carry less legitimate-use collision than anti-vm but more than anti-debug,
 * and its Sleep-skew probe costs a real ~300ms -- so it too is opt-in rather
 * than forced on. (An earlier revision left anti-sandbox unconditional;
 * making it a flag like the other two keeps the model uniform and gives the
 * operator one switch per category.)
 */
#ifndef KARITY_ANTI_DEBUG_H
#define KARITY_ANTI_DEBUG_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Bits for karity_anti_debug_init's enabled_categories parameter, one per
 * category. Shared between src/inject/injector.cpp (which builds this from
 * the --anti-debug/--anti-vm/--anti-sandbox CLI flags at protect time) and
 * runtime/anti_debug_thunk.S's call-site params (see that file), so the
 * choice made at protect time reaches the running program without needing
 * to recompile the freestanding runtime blob per protect run. */
#define KARITY_ANTI_ANALYSIS_DEBUG   0x1u
#define KARITY_ANTI_ANALYSIS_VM      0x2u
#define KARITY_ANTI_ANALYSIS_SANDBOX 0x4u

/* Which categories karity_anti_debug_scan() actually contributes -- set once
 * by karity_anti_debug_init below (from its enabled_categories parameter)
 * and consulted by every scan after that, including the watchdog's periodic
 * ones. The passive checks read it as a branchless per-category AND mask
 * (see runtime/anti_debug.c); the few side-effecting active probes read it
 * as a real execution gate. Exposed directly (rather than only through the
 * init parameter) so tests/test_anti_debug.c can flip categories on/off
 * without spawning a real watchdog thread just to do it -- same "poke the
 * real state directly" testing style already used there for PEB fields.
 * Starts at 0 (BSS): a build that never calls karity_anti_debug_init (most
 * hosted tests) contributes nothing from any category. */
extern uint32_t karity_anti_debug_enabled_categories;

/* Runs every *enabled* detection technique once, synchronously, and
 * returns their combined contribution: 0 if nothing looked suspicious,
 * nonzero otherwise (the specific nonzero value depends on which
 * technique(s) fired -- it is not itself meaningful, only its zero-ness is
 * checked anywhere, and even that check lives nowhere near this function
 * -- see the file header). Safe to call from a hosted (non-freestanding)
 * build too, e.g. for tests -- see runtime/CMakeLists.txt's
 * karity_anti_debug_hosted. */
uint64_t karity_anti_debug_scan(void);

/* This process's live taint value -- what runtime/vm_thunk.S actually reads
 * (via a direct symbol reference, not a function call, to keep the per-VM-
 * entry cost to a single aligned load) on every VM invocation. Updated by
 * karity_anti_debug_init below: once synchronously before it returns, then
 * periodically by a background watchdog thread for as long as the process
 * lives. A single naturally-aligned 8-byte store/load is atomic on x64, so
 * no lock is needed between the watchdog's writer and vm_thunk.S's reader.
 * Starts at 0 (BSS), so a build that never calls karity_anti_debug_init at
 * all (e.g. most hosted tests) gets the pre-existing, unmodified
 * bytecode_key_seed behavior -- this feature fails open by construction,
 * the same stance every bounds/guard check elsewhere in this runtime takes
 * (see e.g. isa.h's vstack_limit note). */
extern uint64_t karity_anti_debug_taint;

/* Stores enabled_categories into karity_anti_debug_enabled_categories, runs
 * the initial scan (updating karity_anti_debug_taint before returning, so
 * even a process that gets killed before the watchdog's first tick is
 * already covered), and spawns the watchdog thread that keeps re-running it
 * for the process's lifetime -- a one-time check alone is easy to beat by
 * simply attaching a debugger *after* it already ran once; periodic
 * re-verification closes that TOCTOU gap without needing continuous
 * checking on the hot VM-entry path itself. Always returns 1 (best-effort:
 * even if WinAPI resolution or thread creation fails, the synchronous
 * initial scan still ran and its result is already live -- there's no
 * scratch-buffer/handler dependency chain here the way nanomite's install
 * has, so a partial failure has nothing further to break). Called once, at
 * OEP, by runtime/anti_debug_thunk.S with the enabled_categories the
 * injector baked into that call site's inline params -- see
 * src/inject/injector.cpp. */
int karity_anti_debug_init(uint32_t enabled_categories);

#ifdef __cplusplus
}
#endif

#endif /* KARITY_ANTI_DEBUG_H */
