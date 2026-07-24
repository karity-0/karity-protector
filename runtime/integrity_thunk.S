/*
 * runtime/integrity_thunk.S -- calls karity_integrity_init once at native
 * stub entry, then continues the stub normally.
 *
 * Call-site contract (mirrors karity_anti_debug_install_thunk in
 * anti_debug_thunk.S; the region base is delta-encoded the same ASLR-safe way
 * as vm_thunk.S's bytecode_va):
 *
 *     call    karity_integrity_install_thunk
 *   params:
 *     .quad   <region_va - params>   ; delta to the protected region's first
 *                                      ; byte (the generated interpreter), from
 *                                      ; this quad pair itself -- base-independent
 *                                      ; by construction, so ASLR rebasing keeps
 *                                      ; it correct (see src/inject/injector.cpp)
 *     .quad   <region_len>            ; length in bytes; 0 when --anti-tamper is
 *                                      ; off, which hashes to a no-op (see
 *                                      ; include/karity/integrity.h)
 *   continue_here:
 *     ...rest of the native stub...
 *
 * Like karity_anti_debug_install_thunk, `call`'s return address points at
 * this inline params block rather than at code, so this returns not via `ret`
 * but via an explicit jmp past the params. The length is a plain immediate,
 * not an address; the region base is reconstructed at runtime as params +
 * delta, so neither needs a PE base relocation.
 *
 * karity_integrity_init itself (runtime/integrity.c) is an ordinary C function
 * linked into this same karity_runtime_image executable, so the `call` to it
 * resolves at link time and survives objcopy's flattening, exactly as
 * anti_debug_thunk.S's own call to karity_anti_debug_init does.
 *
 * No register save/restore beyond the alignment dance: this runs at the very
 * start of the native stub, before anything meaningful is live in any register
 * (true PE entry has no defined incoming register state to preserve) -- same
 * reasoning anti_debug_thunk.S / nanomite_thunk.S give.
 */
.intel_syntax noprefix
.section .text
.global karity_integrity_install_thunk

karity_integrity_install_thunk:
    pop     rbx                  /* rbx = &params (the call's own return address) */

    mov     rcx, [rbx]           /* region delta (from params) */
    add     rcx, rbx             /* arg0 = region_va = params + delta */
    mov     rdx, [rbx+8]         /* arg1 = region_len */

    mov     r12, rsp             /* save rsp in a CALLEE-SAVED reg -- rax gets clobbered by
                                     karity_integrity_init's own return value, so it can't hold this;
                                     rbx is holding params, so use r12 (also callee-saved) */
    and     rsp, -16             /* align for the call */
    sub     rsp, 32              /* Win64 shadow space */
    call    karity_integrity_init
    mov     rsp, r12             /* restore rsp */

    lea     rax, [rbx+16]        /* continue_here = params + 16 */
    jmp     rax
