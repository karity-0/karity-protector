/*
 * examples/mul_div_demo.S -- exercises the lifter's MUL/IMUL/DIV/IDIV
 * support (look/todo.md A-4) end-to-end: the two-operand signed multiply
 * (VOP_IMUL2), the one-operand unsigned multiply that writes RDX:RAX
 * (VOP_MUL), and both divides (VOP_DIV/VOP_IDIV), which read RDX:RAX as
 * their implicit 128-bit dividend.
 *
 * OEP is `mov rax, 6`, which alone clears kOepJmpSize (5 bytes), so the
 * mandatory straight-line entry prefix is just that one instruction;
 * everything else is lifted by the CFG walker that starts right after it
 * (straight-line here -- no branches -- same as liftable_demo.S).
 *
 * RDX is zeroed/sign-extended by hand via `mov rdx, ...` before each divide
 * rather than the idiomatic `xor edx,edx`/`cqo` a compiler would emit --
 * those are 32-bit-operand forms the lifter doesn't model yet (32-bit
 * register handling is a separate, not-yet-done item: look/todo.md's
 * MOVZX/MOVSX entry), so this demo sticks to the 64-bit-operand subset the
 * lifter already supports, same as every other hand-assembled example here.
 *
 * 6*7 (two-operand IMUL) and 100*3 (one-operand MUL) feed two divides that
 * both land back on 42 (300/7 unsigned, -84/2 negated signed), so comparing
 * the protected binary's exit code against the unprotected one's (42) is a
 * simple correctness check that both the multiplies and the RDX:RAX-wide
 * divides actually round-trip.
 *
 * Build (no CRT involved, so no need to work around the lifter's gaps):
 *   gcc -o mul_div_demo.exe mul_div_demo.S -nostartfiles -Wl,-e,my_entry -lkernel32
 */
.intel_syntax noprefix
.section .text
.global my_entry
.extern __imp_ExitProcess

my_entry:
    mov     rax, 6
    mov     rcx, 7
    imul    rax, rcx                     /* rax = 42 (two-operand signed multiply) */

    mov     rax, 100
    mov     rcx, 3
    mul     rcx                          /* rax:rdx = 300:0 (one-operand unsigned multiply) */

    mov     rcx, 7
    mov     rdx, 0
    div     rcx                          /* rax = 300/7 = 42, rdx = 300%7 = 6 */

    mov     rax, 0
    sub     rax, 84                      /* rax = -84 */
    mov     rdx, 0
    sub     rdx, 1                       /* rdx = -1 (sign-extends rax, stands in for cqo) */
    mov     rcx, 2
    idiv    rcx                          /* rax = -84/2 = -42, rdx = -84%2 = 0 */
    neg     rax                          /* rax = 42 */

    mov     rcx, rax
    sub     rsp, 40
    call    qword ptr [rip+__imp_ExitProcess]
    add     rsp, 40
    ret
