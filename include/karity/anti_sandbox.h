/*
 * include/karity/anti_sandbox.h -- automated-analysis-environment signals,
 * same "feed a value computation, not a branch" treatment as
 * include/karity/anti_debug.h (read that file's header first).
 *
 * karity_anti_sandbox_scan() is called from runtime/anti_debug.c's
 * karity_anti_debug_scan() and OR'd into the same combined result that ends
 * up in karity_anti_debug_taint -- one covert channel into the decryption
 * key for debug/VM/sandbox detection combined, not three separate ones.
 */
#ifndef KARITY_ANTI_SANDBOX_H
#define KARITY_ANTI_SANDBOX_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Runs every sandbox/automated-analysis-environment heuristic once and
 * returns their combined contribution (0 if the environment looks like an
 * ordinary, real user machine, nonzero otherwise -- see
 * include/karity/anti_debug.h for why only the zero-ness is ever
 * meaningful anywhere). Blocks for ~300ms (the Sleep-skew probe below) --
 * called once at process start and periodically by the watchdog, never on
 * the VM-entry hot path itself, so this is an acceptable, deliberate cost.
 * Safe to call from a hosted build too -- see
 * runtime/CMakeLists.txt's karity_anti_sandbox_hosted. */
uint64_t karity_anti_sandbox_scan(void);

#ifdef __cplusplus
}
#endif

#endif /* KARITY_ANTI_SANDBOX_H */
