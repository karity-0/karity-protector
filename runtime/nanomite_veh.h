/*
 * runtime/nanomite_veh.h -- exception-based trap/decrypt/execute handler.
 *
 * Freestanding-safe (no libc, no windows.h -- see nanomite_veh.c for why).
 * Resolves everything it needs (AddVectoredExceptionHandler, VirtualAlloc,
 * ...) through runtime/api_resolve.h rather than an import table, since
 * injected code has none of its own.
 */
#ifndef KARITY_NANOMITE_VEH_H
#define KARITY_NANOMITE_VEH_H

#include "karity/nanomite.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Allocates the scratch region, then registers the handler. `sites` must
 * remain valid for as long as the handler stays installed -- the handler
 * reads through the pointer on every fault rather than copying the table.
 * `anchor` is the base every site's trap_delta/resume_delta is relative to
 * (see include/karity/nanomite.h).
 *
 * Returns 1 on success, 0 if any API resolution or allocation step failed
 * (in which case nothing is left registered/allocated).
 */
int karity_nanomite_install(const karity_nanomite_site *sites, uint32_t site_count, uint64_t anchor);

/* Unregisters the handler and frees the scratch region. Safe to call even
 * if install() was never called or failed. */
void karity_nanomite_uninstall(void);

#ifdef __cplusplus
}
#endif

#endif /* KARITY_NANOMITE_VEH_H */
