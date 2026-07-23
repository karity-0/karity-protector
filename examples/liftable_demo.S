/*
 * examples/liftable_demo.S -- a minimal target whose entry point sits
 * entirely inside the lifter's currently-supported instruction subset
 * (64-bit reg/reg mov, add/sub/xor/and/or between registers, mov reg,imm),
 * so karity-protector can actually virtualize it end-to-end.
 *
 * Real CRT-started executables (see hello_world.c) begin with instructions
 * outside that subset (e.g. `sub rsp, imm`) and are correctly rejected
 * rather than silently mis-virtualized -- see examples/README below.
 *
 * Computes 10 + 32 and exits with that value (42) via ExitProcess, so
 * running the protected binary and comparing its exit code against the
 * unprotected one is a simple correctness check.
 *
 * Build (no CRT involved, so no need to work around the lifter's gaps):
 *   gcc -o liftable_demo.exe liftable_demo.S -nostartfiles -Wl,-e,my_entry -lkernel32
 */
.intel_syntax noprefix
.section .text
.global my_entry
.extern __imp_ExitProcess

my_entry:
    mov     rax, 10
    mov     rbx, 32
    add     rax, rbx
    mov     rcx, rax
    xor     rdx, rdx
    or      rcx, rdx
    and     rcx, rcx
    sub     rcx, rdx
    nop
    nop
    nop
    nop
    sub     rsp, 40
    call    qword ptr [rip+__imp_ExitProcess]
    add     rsp, 40
    ret
