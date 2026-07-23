.intel_syntax noprefix
/* Opcode rolling decryption (include/karity/bytecode_crypt.h, look/todo.md
 * section C): karity_vm_thunk now always reads a third quad -- the raw
 * XOR-keystream seed, not params-relative like the other two -- and both
 * interpreters unconditionally decrypt every bytecode fetch with it. This
 * file hand-assembles plaintext bytecode as .byte literals, which can't be
 * pre-encrypted by hand at assembly time, so each buffer below is exposed
 * (.global + an _end label so the C side knows its length) for
 * test_thunk_main.c to encrypt in place at startup with this exact fixed
 * seed -- the same literal appears in every params block's third .quad
 * below and must stay in sync with test_thunk_main.c's own copy. */
#define KARITY_TEST_SEED 0x9E3779B97F4A7C15

.section .data
.global bytecode, bytecode_end
bytecode:
    .byte 0x10                       /* VOP_PUSH_IMM */
    .quad 0xDEADBEEFCAFEBABE
    .byte 0x12                       /* VOP_POP_VREG */
    .byte 0                          /* vreg index 0 = RAX */
    .byte 0x01                       /* VOP_VMEXIT */
bytecode_end:

pre_call_rsp: .quad 0

.section .text
.global test_thunk
.extern karity_vm_thunk

/* vm_thunk's call into the interpreter is a direct `call rel32`
 * (karity_interp_rel32 in runtime/vm_thunk.S) patched at protect time --
 * there's no link-time symbol for it here either. test_thunk_main.c
 * patches that displacement (via VirtualProtect) to point at the hosted
 * reference interpreter before calling into either test function. */

test_thunk:
    push    rbx
    push    rbp
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    push    r15

    mov     rax, 0x1111111111111111
    mov     rcx, 0x3333333333333333
    mov     rdx, 0x4444444444444444
    mov     rbx, 0x5555555555555555
    mov     rbp, 0x6666666666666666
    mov     rsi, 0x7777777777777777
    mov     rdi, 0x8888888888888888
    mov     r8,  0x0808080808080808
    mov     r9,  0x0909090909090909
    mov     r10, 0x1010101010101010
    mov     r11, 0x1111100011111000
    mov     r12, 0x1212121212121212
    mov     r13, 0x1313131313131313
    mov     r14, 0x1414141414141414
    mov     r15, 0x1515151515151515
    stc

    lea     rax, [rip+pre_call_rsp]
    mov     [rax], rsp

    call    karity_vm_thunk
.Lparams1:
    .quad   bytecode - .Lparams1
    .quad   after_vm - .Lparams1
    .quad   KARITY_TEST_SEED
after_vm:
    /* capture everything before any comparison disturbs flags/registers */
    pushfq
    push    rax
    push    rcx
    push    rdx
    push    rbx
    push    rbp
    push    rsi
    push    rdi
    push    r8
    push    r9
    push    r10
    push    r11
    push    r12
    push    r13
    push    r14
    push    r15

    pop     rax
    mov     rcx, 0x1515151515151515
    cmp     rax, rcx
    jne     .Lfail16                 /* r15 */

    pop     rax
    mov     rcx, 0x1414141414141414
    cmp     rax, rcx
    jne     .Lfail15                 /* r14 */

    pop     rax
    mov     rcx, 0x1313131313131313
    cmp     rax, rcx
    jne     .Lfail14                 /* r13 */

    pop     rax
    mov     rcx, 0x1212121212121212
    cmp     rax, rcx
    jne     .Lfail13                 /* r12 */

    pop     rax
    mov     rcx, 0x1111100011111000
    cmp     rax, rcx
    jne     .Lfail12                 /* r11 */

    pop     rax
    mov     rcx, 0x1010101010101010
    cmp     rax, rcx
    jne     .Lfail11                 /* r10 */

    pop     rax
    mov     rcx, 0x0909090909090909
    cmp     rax, rcx
    jne     .Lfail10                 /* r9 */

    pop     rax
    mov     rcx, 0x0808080808080808
    cmp     rax, rcx
    jne     .Lfail9                  /* r8 */

    pop     rax
    mov     rcx, 0x8888888888888888
    cmp     rax, rcx
    jne     .Lfail8                  /* rdi */

    pop     rax
    mov     rcx, 0x7777777777777777
    cmp     rax, rcx
    jne     .Lfail7                  /* rsi */

    pop     rax
    mov     rcx, 0x6666666666666666
    cmp     rax, rcx
    jne     .Lfail6                  /* rbp */

    pop     rax
    mov     rcx, 0x5555555555555555
    cmp     rax, rcx
    jne     .Lfail4                  /* rbx */

    pop     rax
    mov     rcx, 0x4444444444444444
    cmp     rax, rcx
    jne     .Lfail3                  /* rdx */

    pop     rax
    mov     rcx, 0x3333333333333333
    cmp     rax, rcx
    jne     .Lfail2                  /* rcx */

    pop     rax
    mov     rcx, 0xDEADBEEFCAFEBABE
    cmp     rax, rcx
    jne     .Lfail1                  /* rax (VM result) */

    popfq
    jnc     .Lfail17                 /* CF must still be set (from stc before the call) */

    cmp     rsp, [rip+pre_call_rsp]
    jne     .Lfail18

    xor     eax, eax
    jmp     .Ldone
.Lfail1:  mov eax, 1
    jmp .Ldone
.Lfail2:  mov eax, 2
    jmp .Ldone
.Lfail3:  mov eax, 3
    jmp .Ldone
.Lfail4:  mov eax, 4
    jmp .Ldone
.Lfail6:  mov eax, 6
    jmp .Ldone
.Lfail7:  mov eax, 7
    jmp .Ldone
.Lfail8:  mov eax, 8
    jmp .Ldone
.Lfail9:  mov eax, 9
    jmp .Ldone
.Lfail10: mov eax, 10
    jmp .Ldone
.Lfail11: mov eax, 11
    jmp .Ldone
.Lfail12: mov eax, 12
    jmp .Ldone
.Lfail13: mov eax, 13
    jmp .Ldone
.Lfail14: mov eax, 14
    jmp .Ldone
.Lfail15: mov eax, 15
    jmp .Ldone
.Lfail16: mov eax, 16
    jmp .Ldone
.Lfail17: mov eax, 17
    jmp .Ldone
.Lfail18: mov eax, 18
.Ldone:
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbp
    pop     rbx
    ret

/* -------------------------------------------------------------------------
 * test_thunk2: exercises PUSH_VREG, ADD, POP_VREG, PUSH_IMM/STORE64/LOAD64
 * ---------------------------------------------------------------------- */
.section .data
scratch_mem: .quad 0
.global bytecode2, bytecode2_end
bytecode2:
    .byte 0x11              /* VOP_PUSH_VREG */
    .byte 1                 /* rcx */
    .byte 0x10               /* VOP_PUSH_IMM */
    .quad 1
    .byte 0x20               /* VOP_ADD */
    .byte 0x12               /* VOP_POP_VREG */
    .byte 1                  /* -> rcx */
    .byte 0x10                /* VOP_PUSH_IMM */
    .quad scratch_mem
    .byte 0x10                /* VOP_PUSH_IMM */
    .quad 0xABCDEF
    .byte 0x37                 /* VOP_STORE64 */
    .byte 0x10                 /* VOP_PUSH_IMM */
    .quad scratch_mem
    .byte 0x33                 /* VOP_LOAD64 */
    .byte 0x12                 /* VOP_POP_VREG */
    .byte 2                    /* -> rdx */
    .byte 0x01                 /* VOP_VMEXIT */
bytecode2_end:

.section .text
.global test_thunk2
test_thunk2:
    push    rbx
    mov     rcx, 100
    mov     rdx, 0
    lea     rax, [rip+bytecode2]
    call    karity_vm_thunk
.Lparams2:
    .quad   bytecode2 - .Lparams2
    .quad   after_vm2 - .Lparams2
    .quad   KARITY_TEST_SEED
after_vm2:
    cmp     rcx, 101
    jne     .Lt2_fail1
    cmp     rdx, 0xABCDEF
    jne     .Lt2_fail2
    cmp     qword ptr [rip+scratch_mem], 0xABCDEF
    jne     .Lt2_fail3
    xor     eax, eax
    jmp     .Lt2_done
.Lt2_fail1: mov eax, 101
    jmp .Lt2_done
.Lt2_fail2: mov eax, 102
    jmp .Lt2_done
.Lt2_fail3: mov eax, 103
.Lt2_done:
    pop     rbx
    ret

/* -------------------------------------------------------------------------
 * test_thunk_nested: a virtualized site's VOP_CALL landing directly on a
 * *second* virtualized site's own entry -- nests one karity_vm_thunk
 * invocation inside another (see runtime/vm_thunk.S's per-depth scratch
 * slot fix and src/inject/injector.h). outer's bytecode sets vreg[RCX]=41,
 * then VOP_CALLs straight into inner_stub (a second, independent
 * `call karity_vm_thunk` + quad pair, exactly like a real second
 * virtualization site's stub); inner reads that same real RCX (passed
 * through by karity_vm_native_call, runtime/vm_call.S) into its own
 * ctx->vreg[RCX], computes RCX+1, and VMEXITs to `after_inner` -- a plain
 * `ret` that hands control back to karity_vm_native_call, which writes
 * inner's result into *outer's* ctx->vreg[RAX]. outer then VMEXITs too.
 *
 * Before the per-depth-slot fix, inner's entry sequence would unconditionally
 * overwrite the single shared scratch buffer -- including outer's own
 * ctx->exit_target and ctx->vreg[RSP] fields, still live while outer's
 * karity_vm_native_call call is suspended -- so outer's own eventual exit
 * would resume at inner's exit target with inner's stack bookkeeping
 * instead of its own: reliably wrong control flow, not just a wrong value.
 * With separate slots, outer's own fields survive inner's execution
 * untouched, and this resolves to 42 exactly like a real, non-nested call
 * would.
 *
 * outer's bytecode also temporarily points vreg[RSP] (vreg[4]) at a
 * dedicated static buffer for the duration of the VOP_CALL, saving the
 * original value in vreg[RBX] (otherwise unused here) first and restoring
 * it right after. VOP_CALL swaps the real RSP to vreg[RSP] (runtime/
 * vm_call.S) before making the outbound call, and *that* becomes the real
 * stack inner_stub's own nested karity_vm_thunk invocation runs on --
 * including its own `sub rsp, 4096` interpreter-call headroom (runtime/
 * vm_thunk.S). Left pointing at the real stack for the whole invocation,
 * inner's headroom would be carved out of the exact same address range
 * outer's own still-live interpreter call frame and its own headroom
 * already occupy -- a genuine collision between the two invocations' real
 * stack usage, on top of (and unrelated to) the vmctx/vstack slot collision
 * this test otherwise exists to rule out. The restore afterward matters
 * just as much as the redirect: vreg[RSP] doubles as the value
 * karity_vm_thunk's own exit sequence restores real RSP to (runtime/
 * vm_thunk.S, `mov rsp, [rbx+32]`) -- leaving it pointed at the scratch
 * buffer would make outer's own VMEXIT resume execution on that buffer
 * instead of the real caller's stack, which is exactly as broken as it
 * sounds (caught by this test itself before the restore was added: outer's
 * final `ret`, back in test_thunk_nested, popped a garbage address off the
 * scratch buffer instead of its own real return address). */
.section .bss
.align 16
nested_native_stack:
    .space 16384
nested_native_stack_top:

.section .data
.global bytecode_inner, bytecode_inner_end
bytecode_inner:
    .byte 0x10               /* VOP_PUSH_IMM */
    .quad 1
    .byte 0x11                /* VOP_PUSH_VREG */
    .byte 1                    /* vreg[1] = RCX (passed through from outer's real RCX) */
    .byte 0x20                  /* VOP_ADD -> push(1 + RCX) */
    .byte 0x12                   /* VOP_POP_VREG */
    .byte 0                       /* -> vreg[0] = RAX */
    .byte 0x01                     /* VOP_VMEXIT */
bytecode_inner_end:

.global bytecode_outer, bytecode_outer_end
bytecode_outer:
    .byte 0x11                /* VOP_PUSH_VREG */
    .byte 4                    /* push current vreg[RSP] (the real caller stack, set by
                                   karity_vm_thunk's own entry) */
    .byte 0x12                  /* VOP_POP_VREG */
    .byte 3                      /* -> vreg[3] = RBX, saved for the restore below */
    .byte 0x10                    /* VOP_PUSH_IMM */
    .quad nested_native_stack_top
    .byte 0x12                     /* VOP_POP_VREG */
    .byte 4                         /* vreg[4] = RSP -- see comment above */
    .byte 0x10                       /* VOP_PUSH_IMM */
    .quad 41
    .byte 0x12                        /* VOP_POP_VREG */
    .byte 1                            /* vreg[1] = RCX = 41 */
    .byte 0x40                          /* VOP_CALL */
    .quad   inner_stub - .Lparams_outer   /* delta from outer's own anchor (.Lparams_outer) to
                                              inner_stub's entry */
    .byte 0x11                        /* VOP_PUSH_VREG */
    .byte 3                            /* push the saved real caller stack back */
    .byte 0x12                          /* VOP_POP_VREG */
    .byte 4                              /* vreg[4] = RSP, restored */
    .byte 0x01                            /* VOP_VMEXIT */
bytecode_outer_end:

.section .text
.global test_thunk_nested
test_thunk_nested:
    push    rbx

    call    karity_vm_thunk
.Lparams_outer:
    .quad   bytecode_outer - .Lparams_outer
    .quad   after_outer - .Lparams_outer
    .quad   KARITY_TEST_SEED
after_outer:
    cmp     rax, 42
    jne     .Lt3_fail1
    xor     eax, eax
    jmp     .Lt3_done
.Lt3_fail1: mov eax, 1
.Lt3_done:
    pop     rbx
    ret

inner_stub:
    call    karity_vm_thunk
.Lparams_inner:
    .quad   bytecode_inner - .Lparams_inner
    .quad   after_inner - .Lparams_inner
    .quad   KARITY_TEST_SEED
after_inner:
    ret                          /* pops karity_vm_native_call's own return address (runtime/
                                     vm_call.S's `call rdi`), resuming there exactly like a normal
                                     native callee's RET would */

/* -------------------------------------------------------------------------
 * test_thunk_taint: validates runtime/vm_thunk.S's
 * `xor r10, [rip + karity_anti_debug_taint]` line directly -- not by
 * running (possibly-corrupted) bytecode through a real interpreter, which
 * would risk this test process itself crashing the moment the decrypted
 * opcode stream stops being valid bytecode (this VM has no bytecode bounds
 * checking by design, see look/todo.md's "매칭 안 되는 맵" note on
 * OpcodeMap). Instead, test_thunk_main.c temporarily repoints
 * karity_interp_rel32 at karity_probe_capture_seed below instead of the
 * real reference interpreter -- a tiny function that does nothing but copy
 * ctx->bytecode_key_seed (offset 264, see runtime/vm_thunk.S) out to
 * `captured_seed` and return immediately, so karity_vm_thunk's own exit
 * sequence runs completely normally (real registers restored from ctx,
 * `ret` to exit_target) with no VM execution ever actually happening. This
 * isolates exactly one claim: does the seed karity_vm_thunk hands the
 * interpreter equal the raw quad value XORed with the live
 * karity_anti_debug_taint at the moment of that specific VM entry?
 * ---------------------------------------------------------------------- */
.section .data
.global captured_seed
captured_seed: .quad 0
dummy_bytecode: .byte 0x01 /* VOP_VMEXIT -- never actually read; the probe
                               interpreter never touches ctx->vip at all */

.section .text
.global karity_probe_capture_seed
karity_probe_capture_seed:
    mov     rax, [rcx+264]        /* ctx->bytecode_key_seed, Win64 arg0 (rcx) = ctx */
    lea     r10, [rip+captured_seed]
    mov     [r10], rax
    ret

.global test_thunk_taint
.extern karity_anti_debug_taint
test_thunk_taint:
    push    rbx

    /* case A: taint = 0 -> captured seed must equal the raw quad value unchanged */
    lea     rax, [rip+karity_anti_debug_taint]
    mov     qword ptr [rax], 0
    call    karity_vm_thunk
.Lparams_taintA:
    .quad   dummy_bytecode - .Lparams_taintA
    .quad   after_taintA - .Lparams_taintA
    .quad   KARITY_TEST_SEED
after_taintA:
    lea     rax, [rip+captured_seed]
    mov     rax, [rax]
    mov     rcx, KARITY_TEST_SEED
    cmp     rax, rcx
    jne     .Ltaint_fail1

    /* case B: taint = some nonzero value -> captured seed must equal the raw
       quad value XORed with exactly that taint */
    mov     rcx, 0x1234567887654321
    lea     rax, [rip+karity_anti_debug_taint]
    mov     [rax], rcx
    call    karity_vm_thunk
.Lparams_taintB:
    .quad   dummy_bytecode - .Lparams_taintB
    .quad   after_taintB - .Lparams_taintB
    .quad   KARITY_TEST_SEED
after_taintB:
    lea     rax, [rip+captured_seed]
    mov     rax, [rax]
    mov     rcx, KARITY_TEST_SEED
    mov     rdx, 0x1234567887654321
    xor     rcx, rdx
    cmp     rax, rcx
    jne     .Ltaint_fail2

    lea     rax, [rip+karity_anti_debug_taint] /* leave it 0 for anything run after this */
    mov     qword ptr [rax], 0

    xor     eax, eax
    jmp     .Ltaint_done
.Ltaint_fail1: mov eax, 1
    jmp .Ltaint_done
.Ltaint_fail2: mov eax, 2
.Ltaint_done:
    pop     rbx
    ret
