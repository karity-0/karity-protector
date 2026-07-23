/*
 * examples/movzx_movsx_demo.S -- exercises the lifter's MOVZX/MOVSX/MOVSXD
 * support (look/todo.md A-4) end-to-end.
 *
 * OEP is `mov rax, 10`, which alone clears kOepJmpSize (5 bytes), so the
 * mandatory straight-line entry prefix is just that one instruction;
 * everything else is lifted by the CFG walker that starts right after it
 * (straight-line here -- no branches -- same as liftable_demo.S).
 *
 * Every source register is set up via `mov r64, imm32` (sign-extended to
 * 64 bits) rather than a 32-bit-destination `mov` -- the lifter's plain MOV
 * case only supports 64-bit-register destinations, so a 32-bit `mov eax,
 * imm32` couldn't even appear in the mandatory prefix. That's fine here:
 * MOVZX/MOVSX only ever look at the low 8/16/32 bits of the pushed 64-bit
 * vreg value, so the upper bits left behind by a 64-bit mov are simply
 * ignored, same as real hardware ignores whatever garbage sits above AL/AX
 * /EAX when reading just that sub-register.
 *
 * Four independent contributions, each exercising a different
 * MOVZX/MOVSX/MOVSXD shape, sum to 42:
 *   - movzx rbx, al        (VOP_MOVZX, src=1 byte)                    -> 10
 *   - movsx rcx, al        (VOP_MOVSX, src=1 byte, dst=64-bit) negated -> 20
 *   - movsxd rcx, eax      (VOP_MOVSX, src=4 bytes / MOVSXD) negated   ->  1
 *   - movsx ecx, al        (VOP_MOVSX, src=1 byte, dst=32-bit)        -> 11
 * (The dst=32-bit-vs-64-bit distinction that VOP_MOVSX's dst_size operand
 * exists for -- see isa.h -- is only observable for a *negative* source
 * byte, where it's already pinned down precisely by the opcode-level and
 * interp-codegen-level unit tests; this demo just needs to prove the real
 * lifter recognizes the real instruction shapes and wires them through a
 * real injected interpreter, so a positive byte here is enough.)
 *
 * Build (no CRT involved, so no need to work around the lifter's gaps):
 *   gcc -o movzx_movsx_demo.exe movzx_movsx_demo.S -nostartfiles -Wl,-e,my_entry -lkernel32
 */
.intel_syntax noprefix
.section .text
.global my_entry
.extern __imp_ExitProcess

my_entry:
    mov     rax, 10
    movzx   rbx, al                     /* rbx = 10 */

    mov     rax, -20
    movsx   rcx, al                     /* rcx = -20 */
    neg     rcx                         /* rcx = 20 */
    add     rbx, rcx                    /* rbx = 30 */

    mov     rax, -1
    movsxd  rcx, eax                    /* rcx = -1 */
    neg     rcx                         /* rcx = 1 */
    add     rbx, rcx                    /* rbx = 31 */

    mov     rax, 11
    movsx   ecx, al                     /* rcx = 11 (32-bit dst, zero-uppered) */
    add     rbx, rcx                    /* rbx = 42 */

    mov     rcx, rbx
    sub     rsp, 40
    call    qword ptr [rip+__imp_ExitProcess]
    add     rsp, 40
    ret
