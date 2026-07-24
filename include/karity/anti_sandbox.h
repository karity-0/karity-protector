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

/* Cheap, side-effect-free heuristics (Sandboxie DLL, low CPU/RAM, short
 * uptime) -- the caller (runtime/anti_debug.c) runs these unconditionally
 * and masks the result by whether the sandbox category is enabled, so
 * there's no single "skip sandbox detection" branch. Returns the combined
 * taint (0 if the environment looks like an ordinary real machine). */
uint64_t karity_anti_sandbox_scan_passive(void);

/* The Sleep-skew probe, which blocks ~300ms of real time -- the caller only
 * runs it when the sandbox category is enabled so an --anti-sandbox-off
 * binary doesn't stall at startup or on every watchdog tick. */
uint64_t karity_anti_sandbox_scan_active(void);

/* Passive | active, for standalone hosted callers/tests (see
 * include/karity/anti_debug.h for why only zero-ness is meaningful). Blocks
 * ~300ms via the active probe. Safe to call from a hosted build -- see
 * runtime/CMakeLists.txt's karity_anti_debug_hosted (which bundles
 * anti_sandbox.c). */
uint64_t karity_anti_sandbox_scan(void);

#ifdef __cplusplus
}
#endif

#endif /* KARITY_ANTI_SANDBOX_H */
