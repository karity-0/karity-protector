/*
 * examples/indirect_call_demo.S -- exercises VOP_CALL_IND (memory-indirect
 * call, `call qword ptr [rip+X]`) end-to-end. OEP is literally the indirect
 * call itself, so it's the one instruction the lifter has to convert to
 * reach kOepJmpSize (5 bytes) -- everything after runs natively post-VMEXIT,
 * same pattern as liftable_demo.S.
 *
 * helper() returns 42; my_entry calls it indirectly through helper_ptr (a
 * plain in-image data pointer, standing in for what an IAT slot looks like
 * to the lifter -- same `[rip+disp32]` shape), moves the result into RCX,
 * and exits with it, so comparing the protected binary's exit code against
 * the unprotected one's is a simple correctness check. Also exercises
 * try_emit_address's ASLR-safe anchor+delta resolution for a *call target*
 * specifically, not just a MOV/LEA source -- and, in the interpreter that
 * runs the resulting bytecode, karity_vm_native_call's own address being
 * resolved via ctx->anchor rather than a bare protect-time VA (see
 * src/native/interp_codegen.h) -- both are on the critical path here, since
 * this is the OEP-lifted instruction and the whole binary segfaults under
 * ASLR if either one is wrong.
 *
 * Build:
 *   gcc -o indirect_call_demo.exe indirect_call_demo.S -nostartfiles -Wl,-e,my_entry -lkernel32
 */
.intel_syntax noprefix
.section .text
.global my_entry
.extern __imp_ExitProcess

my_entry:
    call    qword ptr [rip+helper_ptr]
    mov     rcx, rax
    sub     rsp, 40
    call    qword ptr [rip+__imp_ExitProcess]
    add     rsp, 40
    ret

helper:
    mov     rax, 42
    ret

.section .data
.align 8
helper_ptr:
    .quad helper
