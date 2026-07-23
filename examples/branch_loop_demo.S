/*
 * examples/branch_loop_demo.S -- exercises the lifter's branch/loop CFG
 * support (src/vm/lifter.h A-3): a real backward Jcc loop, entirely inside
 * the lifted bytecode, reached and re-entered via VOP_JCC rather than
 * native control flow.
 *
 * OEP is `mov rax, 0`, which alone clears kOepJmpSize (5 bytes), so the
 * mandatory straight-line entry prefix is just that one instruction; the
 * loop (JNE looping back to loop_start) and the tail call are lifted by the
 * CFG walker that starts right after it.
 *
 * Computes 6*7 via a countdown loop (accumulate 7, six times) and exits
 * with that value (42) via ExitProcess, so comparing the protected
 * binary's exit code against the unprotected one's is a simple correctness
 * check that the loop actually ran to completion inside the VM.
 *
 * Build (no CRT involved, so no need to work around the lifter's gaps):
 *   gcc -o branch_loop_demo.exe branch_loop_demo.S -nostartfiles -Wl,-e,my_entry -lkernel32
 */
.intel_syntax noprefix
.section .text
.global my_entry
.extern __imp_ExitProcess

my_entry:
    mov     rax, 0        /* accumulator */
    mov     rcx, 6        /* counter */
loop_start:
    add     rax, 7
    sub     rcx, 1
    cmp     rcx, 0
    jne     loop_start
    mov     rcx, rax
    sub     rsp, 40
    call    qword ptr [rip+__imp_ExitProcess]
    add     rsp, 40
    ret
