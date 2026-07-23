/*
 * runtime/vm_call.S -- native call passthrough for VOP_CALL.
 *
 * void karity_vm_native_call(karity_vmctx *ctx, uint64_t target_va);
 *   (Win64 ABI: ctx in RCX, target_va in RDX)
 *
 * A bytecode CALL can't be done in portable C: the callee expects its
 * arguments in real RCX/RDX/R8/R9 and a real, correctly-aligned stack with
 * Win64 shadow space already reserved -- all state the interpreter only
 * tracks inside karity_vmctx. This swaps in the real values, makes one
 * genuine `call`, and writes the result back.
 *
 * The stack swap reuses vreg[RSP] (the *original* program's real stack
 * pointer at this point, mirrored faithfully by every VM op so far) rather
 * than any scratch region, so the callee sees exactly the stack -- shadow
 * space included -- that the un-virtualized code would have set up for it.
 *
 * SEH/exception interaction (see runtime/vm_thunk.S's header for the full
 * picture): this function's own `mov rbx, rsp` right after the four pushes
 * already is the "capture rsp into an unused nonvolatile register before it
 * moves unpredictably" pattern that technique needs -- rbx holds this
 * function's true entry-relative rsp for its entire body, surviving the
 * `mov rsp, [vreg[RSP]]` swap and the outbound `call rdi` untouched, and
 * `mov rsp, rbx` right after restores it. So this file needs no new
 * instructions, just RUNTIME_FUNCTION/UNWIND_INFO metadata describing what's
 * already here (built in src/native/seh_unwind.cpp) -- karity_vm_native_call_
 * prolog_end/_end below are its two boundary markers, read via nm the same
 * way karity_vm_native_call itself already is (see runtime/CMakeLists.txt).
 */
.intel_syntax noprefix
.section .text
.global karity_vm_native_call
.global karity_vm_native_call_prolog_end
.global karity_vm_native_call_end

karity_vm_native_call:
    push    rbx
    push    rbp
    push    rsi
    push    rdi

    mov     rsi, rcx            /* rsi = ctx (callee-saved, survives the call below) */
    mov     rdi, rdx            /* rdi = target_va (callee-saved, ditto) */
    mov     rbx, rsp            /* rbx = our own rsp, to restore once the callee returns */
karity_vm_native_call_prolog_end:

    mov     rcx, [rsi + 1*8]    /* vreg[RCX] */
    mov     rdx, [rsi + 2*8]    /* vreg[RDX] */
    mov     r8,  [rsi + 8*8]    /* vreg[R8]  */
    mov     r9,  [rsi + 9*8]    /* vreg[R9]  */

    mov     rax, [rsi + 4*8]    /* vreg[RSP]: the real, original stack pointer */
    mov     rsp, rax

    call    rdi

    mov     rsp, rbx            /* back to our own stack */
    mov     [rsi + 0*8], rax    /* vreg[RAX] = return value */

    pop     rdi
    pop     rsi
    pop     rbp
    pop     rbx
    ret
karity_vm_native_call_end:
