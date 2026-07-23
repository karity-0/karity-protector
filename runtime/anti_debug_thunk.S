/*
 * runtime/anti_debug_thunk.S -- calls karity_anti_debug_init once at native
 * stub entry, then falls straight through (a genuine `call`/`ret` pair, not
 * a return-address-as-data trick).
 *
 * Call-site contract (simpler than karity_nanomite_install_thunk in
 * nanomite_thunk.S): karity_anti_debug_init needs no ASLR-sensitive inline
 * data the way the nanomite site table does, so this is called via an
 * ordinary `call rel32` and returns via an ordinary `ret` -- the injector
 * (src/inject/injector.cpp) just needs this function's own offset within
 * the runtime blob (found via nm, same mechanism as karity_vm_thunk's and
 * karity_nanomite_install_thunk's) to patch a plain call to it into the
 * native stub, ahead of everything else there (see injector.cpp's assembly
 * step for the exact ordering relative to the nanomite install call).
 *
 * No register save/restore beyond what the alignment dance below needs:
 * this runs at the very start of the native stub, before anything
 * meaningful is live in any register (true PE entry has no defined
 * incoming register state to preserve) -- same reasoning
 * nanomite_thunk.S's own header already gives.
 */
.intel_syntax noprefix
.section .text
.global karity_anti_debug_install_thunk

karity_anti_debug_install_thunk:
    mov     r12, rsp             /* save rsp in a CALLEE-SAVED reg (not rax -- rax gets
                                     clobbered by karity_anti_debug_init's own return value) */
    and     rsp, -16             /* align for the call */
    sub     rsp, 32              /* Win64 shadow space */
    call    karity_anti_debug_init
    mov     rsp, r12             /* restore rsp -- [rsp] is still this thunk's own real
                                     return address, untouched by anything above */
    ret
