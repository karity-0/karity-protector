/* Validates runtime/anti_debug.c's individual checks by directly poking the
 * test process's own (real, live) PEB fields and confirming
 * karity_anti_debug_scan()'s result actually moves -- a real, deterministic
 * signal rather than a simulation, same "exercise the real mechanism" bar
 * test_nanomite.cpp already holds itself to. Checks that need an actual
 * attached debugger to trip for real (NtQueryInformationProcess's
 * DebugPort/DebugFlags/DebugObjectHandle, the CloseHandle exception trap,
 * the hidden-int3 probe) aren't poke-able this way -- their contribution to
 * the baseline (0, not currently debugged) is exercised implicitly by
 * test_scan_is_clean_by_default below, same as this project's other
 * documented-but-not-independently-verified edge paths (e.g. isa.h's SSE
 * memory-operand notes). */
#include <stdio.h>
#include <windows.h>

#include "karity/anti_debug.h"

static int g_failures = 0;

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__); \
            g_failures++; \
        } \
    } while (0)

static void *read_peb(void)
{
    void *peb;
    __asm__ volatile("mov %%gs:0x60, %0" : "=r"(peb));
    return peb;
}

/* Not itself running under a debugger is the whole premise of ctest running
 * unattended in CI -- if this genuinely fails, either a real debugger is
 * attached to the test process (expected to fail, not a bug) or one of the
 * checks has a false-positive bug worth investigating. */
static void test_scan_is_clean_by_default(void)
{
    uint64_t taint = karity_anti_debug_scan();
    CHECK(taint == 0, "karity_anti_debug_scan() is 0 when not actually being debugged");
}

static void test_being_debugged_bit(void)
{
    uint8_t *peb = (uint8_t *)read_peb();
    uint8_t original = peb[0x02];

    peb[0x02] = 1;
    CHECK(karity_anti_debug_scan() != 0, "flipping PEB->BeingDebugged makes the scan nonzero");

    peb[0x02] = original;
    CHECK(karity_anti_debug_scan() == 0, "restoring PEB->BeingDebugged brings the scan back to 0");
}

static void test_nt_global_flag_bits(void)
{
    uint8_t *peb = (uint8_t *)read_peb();
    uint32_t *flags = (uint32_t *)(peb + 0xBC);
    uint32_t original = *flags;

    *flags = original | 0x70u; /* FLG_HEAP_ENABLE_TAIL_CHECK|FREE_CHECK|VALIDATE_PARAMETERS */
    CHECK(karity_anti_debug_scan() != 0, "setting PEB->NtGlobalFlag's debug bits makes the scan nonzero");

    *flags = original;
    CHECK(karity_anti_debug_scan() == 0, "restoring PEB->NtGlobalFlag brings the scan back to 0");
}

/* karity_anti_debug_init itself (the watchdog-spawning entry point) is only
 * exercised end-to-end by the real injected protector -- calling it here
 * would leave a background thread running for the rest of this test
 * process's life, spamming Sleep/NtQueryInformationProcess for no reason.
 * What's testable and worth testing in a hosted unit test is
 * karity_anti_debug_scan() itself (the synchronous, callable-any-time
 * core); the watchdog wiring is covered by the real protector's own "실제
 * 검증" pass instead (see look/todo.md), same division of labor this
 * project already uses for e.g. nanomite's multithreading caveats. */
int main(void)
{
    test_scan_is_clean_by_default();
    test_being_debugged_bit();
    test_nt_global_flag_bits();

    if (g_failures == 0) {
        printf("all anti_debug tests passed\n");
        return 0;
    }
    fprintf(stderr, "%d anti_debug test(s) failed\n", g_failures);
    return 1;
}
