/*
 * runtime/anti_debug_thunk.S -- calls karity_anti_debug_init once at native
 * stub entry, then continues the stub normally.
 *
 * Call-site contract (mirrors karity_nanomite_install_thunk in
 * nanomite_thunk.S, minus the ASLR-relative delta the nanomite site table
 * needs):
 *
 *     call    karity_anti_debug_install_thunk
 *   params:
 *     .long   <enabled_categories>   ; KARITY_ANTI_ANALYSIS_* bitmask, chosen
 *                                      ; at protect time from --anti-debug/
 *                                      ; --anti-vm (see src/inject/injector.cpp
 *                                      ; and include/karity/anti_debug.h)
 *     .long   0                      ; padding to 8 bytes
 *   continue_here:
 *     ...rest of the native stub...
 *
 * Like karity_nanomite_install_thunk, `call`'s return address points at
 * this inline params block rather than at code, so this returns not via
 * `ret` but via an explicit jmp past the params. The bitmask is a plain
 * immediate, not an address, so unlike the nanomite site-table pointer it
 * needs no anchor-relative delta -- it's baked in raw and read as-is.
 *
 * karity_anti_debug_init itself (runtime/anti_debug.c) is an ordinary C
 * function linked into this same karity_runtime_image executable, so the
 * `call` to it resolves at link time and survives objcopy's flattening,
 * exactly as nanomite_thunk.S's own call to karity_nanomite_install does.
 *
 * No register save/restore beyond the alignment dance: this runs at the
 * very start of the native stub, before anything meaningful is live in any
 * register (true PE entry has no defined incoming register state to
 * preserve) -- same reasoning nanomite_thunk.S's own header gives.
 */
.intel_syntax noprefix
.section .text
.global karity_anti_debug_install_thunk

karity_anti_debug_install_thunk:
    pop     rbx                  /* rbx = &params (the call's own return address) */

    mov     ecx, [rbx]           /* arg0 = enabled_categories (32-bit load zero-extends rcx) */

    mov     r12, rsp             /* save rsp in a CALLEE-SAVED reg -- rax gets clobbered by
                                     karity_anti_debug_init's own return value, so it can't hold this;
                                     rbx is holding params, so use r12 (also callee-saved) */
    and     rsp, -16             /* align for the call */
    sub     rsp, 32              /* Win64 shadow space */
    call    karity_anti_debug_init
    mov     rsp, r12             /* restore rsp */

    lea     rax, [rbx+8]         /* continue_here = params + 8 */
    jmp     rax
