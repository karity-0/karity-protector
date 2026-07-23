/*
 * examples/shift_rotate_demo.S -- exercises the lifter's SHL/ROL support
 * (look/todo.md A-4) end-to-end, including the count==0-after-masking
 * no-op case (rol by 64, which masks to 0) that has to leave both the
 * value and every flag bit completely untouched.
 *
 * OEP is `mov rax, 21`, which alone clears kOepJmpSize (5 bytes), so the
 * mandatory straight-line entry prefix is just that one instruction;
 * everything else is lifted by the CFG walker that starts right after it
 * (straight-line here -- no branches -- same as liftable_demo.S).
 *
 * 21 << 1 == 42, then rotating by 64 (masks to 0, a real hardware no-op)
 * must leave it at exactly 42. Exits with that value via ExitProcess, so
 * comparing the protected binary's exit code against the unprotected
 * one's is a simple correctness check.
 *
 * Build (no CRT involved, so no need to work around the lifter's gaps):
 *   gcc -o shift_rotate_demo.exe shift_rotate_demo.S -nostartfiles -Wl,-e,my_entry -lkernel32
 */
.intel_syntax noprefix
.section .text
.global my_entry
.extern __imp_ExitProcess

my_entry:
    mov     rax, 21
    shl     rax, 1                      /* rax = 42 */
    rol     rax, 64                     /* count masks to 0 -- real no-op */
    mov     rcx, rax
    sub     rsp, 40
    call    qword ptr [rip+__imp_ExitProcess]
    add     rsp, 40
    ret
