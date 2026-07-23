.intel_syntax noprefix
.section .text
.global test_call_junk_buffer

/* int test_call_junk_buffer(void *buf);  (Win64 ABI: buf in RCX)
 * buf must be executable memory ending in a `ret` byte. Sets sentinel
 * values in every register the junk generator might use as scratch
 * (RAX/RDX/RBX/RSI/RDI) plus CF, calls buf, then immediately pushes
 * everything to the stack (before touching any register as scratch for
 * comparison) and checks each one, plus RSP itself, against the sentinel. */
test_call_junk_buffer:
    push    rbx
    push    rsi
    push    rdi
    push    rbp
    mov     rbp, rsp

    mov     rax, 0x1111111111111111
    mov     rdx, 0x2222222222222222
    mov     rbx, 0x3333333333333333
    mov     rsi, 0x5555555555555555
    mov     rdi, 0x6666666666666666
    stc

    call    rcx

    pushfq
    push    rax
    push    rdx
    push    rbx
    push    rsi
    push    rdi

    pop     rdi
    mov     rax, 0x6666666666666666
    cmp     rdi, rax
    jne     .Lfail_rdi

    pop     rsi
    mov     rax, 0x5555555555555555
    cmp     rsi, rax
    jne     .Lfail_rsi

    pop     rbx
    mov     rax, 0x3333333333333333
    cmp     rbx, rax
    jne     .Lfail_rbx

    pop     rdx
    mov     rax, 0x2222222222222222
    cmp     rdx, rax
    jne     .Lfail_rdx

    pop     rax
    mov     rdx, 0x1111111111111111
    cmp     rax, rdx
    jne     .Lfail_rax

    popfq
    jnc     .Lfail_flags

    cmp     rsp, rbp
    jne     .Lfail_rsp

    xor     eax, eax
    jmp     .Ldone
.Lfail_rdi:   mov eax, 6
    jmp .Ldone
.Lfail_rsi:   mov eax, 5
    jmp .Ldone
.Lfail_rbx:   mov eax, 4
    jmp .Ldone
.Lfail_rdx:   mov eax, 3
    jmp .Ldone
.Lfail_rax:   mov eax, 2
    jmp .Ldone
.Lfail_flags: mov eax, 1
    jmp .Ldone
.Lfail_rsp:   mov eax, 7
.Ldone:
    pop     rbp
    pop     rdi
    pop     rsi
    pop     rbx
    ret
