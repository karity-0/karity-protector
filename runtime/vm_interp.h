/*
 * runtime/vm_interp.h -- interpreter core entry point.
 *
 * Freestanding-safe (no libc, no globals). Called by the native entry/exit
 * trampoline (vm_thunk.S) once karity_vmctx has been populated from the
 * captured register file.
 */
#ifndef KARITY_VM_INTERP_H
#define KARITY_VM_INTERP_H

#include "karity/isa.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Runs bytecode starting at ctx->vip until VOP_VMEXIT/VOP_VMEXIT_REL (or an
 * unrecognized opcode, treated as an implicit exit for safety). Updates
 * ctx->vip/vsp/vreg in place; never touches ctx->rflags. Only
 * VOP_VMEXIT_REL touches ctx->exit_target (plain VOP_VMEXIT leaves whatever
 * was pre-filled before VM entry untouched).
 */
void karity_vm_run(karity_vmctx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* KARITY_VM_INTERP_H */
