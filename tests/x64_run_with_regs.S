.intel_syntax noprefix
.section .text
.global x64_run_with_regs

/* void x64_run_with_regs(void *code, uint64_t regs_in[16], uint64_t regs_out[16]);
 * Win64 ABI: rcx=code, rdx=regs_in, r8=regs_out
 *
 * Loads rax/rcx/rbx/rbp/rsi/rdi/r8-r15/rdx from regs_in (indices 0,1,3,5,
 * 6,7,8..15,2 -- skipping index 4/RSP, which this harness never touches),
 * calls `code` (must end in `ret`), then writes rax/rcx/.../r15 back into
 * regs_out using the same index convention. `code` gets whatever real
 * calling convention happens to be live -- it is expected to be a
 * self-contained instruction sequence, not something that itself expects
 * Win64 args. */
x64_run_with_regs:
    push    rbx
    push    rbp
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    push    r15

    push    rcx             /* code */
    push    r8              /* regs_out */

    mov     rax, [rdx + 0*8]
    mov     rcx, [rdx + 1*8]
    mov     rbx, [rdx + 3*8]
    mov     rbp, [rdx + 5*8]
    mov     rsi, [rdx + 6*8]
    mov     rdi, [rdx + 7*8]
    mov     r8,  [rdx + 8*8]
    mov     r9,  [rdx + 9*8]
    mov     r10, [rdx + 10*8]
    mov     r11, [rdx + 11*8]
    mov     r12, [rdx + 12*8]
    mov     r13, [rdx + 13*8]
    mov     r14, [rdx + 14*8]
    mov     r15, [rdx + 15*8]
    mov     rdx, [rdx + 2*8]

    call    qword ptr [rsp+8]

    push    rax
    mov     rax, [rsp+8]     /* rax = regs_out */

    mov     [rax+1*8], rcx
    mov     [rax+2*8], rdx
    mov     [rax+3*8], rbx
    mov     [rax+5*8], rbp
    mov     [rax+6*8], rsi
    mov     [rax+7*8], rdi
    mov     [rax+8*8], r8
    mov     [rax+9*8], r9
    mov     [rax+10*8], r10
    mov     [rax+11*8], r11
    mov     [rax+12*8], r12
    mov     [rax+13*8], r13
    mov     [rax+14*8], r14
    mov     [rax+15*8], r15

    pop     rcx              /* real original rax */
    mov     [rax+0*8], rcx

    add     rsp, 16          /* discard [regs_out][code] */
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbp
    pop     rbx
    ret
