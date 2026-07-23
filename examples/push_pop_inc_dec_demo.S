/*
 * examples/push_pop_inc_dec_demo.S -- exercises the lifter's PUSH-imm32,
 * PUSH/POP-[mem], and INC/DEC support (look/todo.md A-4) end-to-end.
 *
 * OEP is `mov rax, 0`, which alone clears kOepJmpSize (5 bytes), so the
 * mandatory straight-line entry prefix is just that one instruction;
 * everything else is lifted by the CFG walker that starts right after it
 * (straight-line here -- no branches -- same as liftable_demo.S).
 *
 * push 42 / pop rax / inc rax / dec rax round-trips through native-stack
 * PUSH/POP-imm and leaves rax unchanged at 42; storing it to a scratch
 * qword, then push/pop-[mem] round-tripping it through an offset qword and
 * reading it back, exercises PUSH/POP with a real [mem] operand. Exits
 * with the final value (42) via ExitProcess, so comparing the protected
 * binary's exit code against the unprotected one's is a simple correctness
 * check.
 *
 * Build (no CRT involved, so no need to work around the lifter's gaps):
 *   gcc -o push_pop_inc_dec_demo.exe push_pop_inc_dec_demo.S -nostartfiles -Wl,-e,my_entry -lkernel32
 */
.intel_syntax noprefix
.section .text
.global my_entry
.extern __imp_ExitProcess

my_entry:
    mov     rax, 0
    push    42
    pop     rax                         /* rax = 42 (push imm32 + pop reg) */
    inc     rax                         /* rax = 43 */
    dec     rax                         /* rax = 42 */
    lea     rbx, [rip+scratch]
    mov     qword ptr [rbx], rax        /* scratch[0] = 42 */
    push    qword ptr [rbx]             /* push,pop [mem]: round-trip scratch[0] -> scratch[8] */
    pop     qword ptr [rbx+8]
    mov     rcx, [rbx+8]                /* rcx = 42 */
    sub     rsp, 40
    call    qword ptr [rip+__imp_ExitProcess]
    add     rsp, 40
    ret

.section .data
.align 8
scratch:
    .quad 0
    .quad 0
