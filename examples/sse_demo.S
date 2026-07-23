/*
 * examples/sse_demo.S -- exercises the lifter's scalar SSE/SSE2 support
 * (look/todo.md A-4: CVTSI2SD/CVTTSD2SI, MULSD register-register, and
 * MOVSD's [mem] load/store forms) end-to-end.
 *
 * OEP is `mov rax, 6`, which alone clears kOepJmpSize (5 bytes), so the
 * mandatory straight-line entry prefix is just that one instruction;
 * everything else is lifted by the CFG walker that starts right after it
 * (straight-line here -- no branches -- same as liftable_demo.S).
 *
 * 6.0 * 7.0 = 42.0, round-tripped through a real memory location (MOVSD
 * xmm<-mem and mem<-xmm, via VOP_LOAD64/VOP_STORE64 -- the raw 8-byte
 * double bit pattern needs no dedicated memory opcode of its own) and then
 * truncated back to the integer 42 via CVTTSD2SI. MULSD xmm0,xmm1 exercises
 * the VM's execution-local VOP_PUSH_XREG/VOP_POP_XREG bookkeeping (see
 * isa.h) that lets one lifted instruction's XMM producer feed another's
 * consumer within the same block. Exits with the final value (42) via
 * ExitProcess, so comparing the protected binary's exit code against the
 * unprotected one's is a simple correctness check.
 *
 * Build (no CRT involved, so no need to work around the lifter's gaps):
 *   gcc -o sse_demo.exe sse_demo.S -nostartfiles -Wl,-e,my_entry -lkernel32
 */
.intel_syntax noprefix
.section .text
.global my_entry
.extern __imp_ExitProcess

my_entry:
    mov     rax, 6
    cvtsi2sd xmm0, rax                  /* xmm0 = 6.0 */
    mov     rax, 7
    cvtsi2sd xmm1, rax                  /* xmm1 = 7.0 */
    mulsd   xmm0, xmm1                  /* xmm0 = 42.0 */
    lea     rbx, [rip+scratch]
    movsd   qword ptr [rbx], xmm0       /* scratch = 42.0 (MOVSD store) */
    movsd   xmm2, qword ptr [rbx]       /* xmm2 = 42.0 (MOVSD load) */
    cvttsd2si rax, xmm2                 /* rax = 42 */
    mov     rcx, rax
    sub     rsp, 40
    call    qword ptr [rip+__imp_ExitProcess]
    add     rsp, 40
    ret

.section .data
.align 8
scratch:
    .quad 0
