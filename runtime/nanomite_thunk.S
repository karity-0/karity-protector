/*
 * runtime/nanomite_thunk.S -- calls karity_nanomite_install once at native
 * stub entry, then falls through to continue the stub normally.
 *
 * Call-site contract (mirrors karity_vm_thunk in vm_thunk.S):
 *
 *     call    karity_nanomite_install_thunk
 *   params:
 *     .quad   <site_table_va - params>   ; delta, same ASLR-safety reasoning
 *                                          as vm_thunk.S's bytecode_va delta
 *     .long   <site_count>
 *     .long   0                          ; padding to 16 bytes
 *   continue_here:
 *     ...rest of the native stub...
 *
 * Unlike karity_vm_thunk, this call *does* return -- not via `ret` (the
 * pushed return address was consumed as data, not a real return address),
 * but via an explicit jmp to right after the inline params block.
 *
 * karity_nanomite_install itself (runtime/nanomite_veh.c) is called by a
 * plain `call karity_nanomite_install`, not the "patch a rel32 byte
 * operand at protect time" trick vm_thunk.S uses for the interpreter:
 * unlike the interpreter (generated fresh per protect run, outside this
 * translation unit entirely), karity_nanomite_install is an ordinary C
 * function linked into this same karity_runtime_image executable, so the
 * linker resolves the call correctly on its own, and that resolved
 * displacement survives objcopy's flattening unchanged.
 *
 * No register save/restore: this runs at the very start of the native
 * stub, before anything meaningful is live in any register (true PE entry
 * has no defined incoming register state to preserve), so clobbering
 * everything karity_nanomite_install and its WinAPI calls touch is fine.
 * `params` (== the site table's anchor, per include/karity/nanomite.h) is
 * kept in rbx across the call since rbx is callee-saved in the Win64 ABI.
 *
 * Known limitation: the return value (1 on success, 0 if API
 * resolution/allocation failed) is discarded -- on failure, the bytes
 * already patched into the image at protect time are still trap markers +
 * ciphertext with nothing to catch the fault, so the protected program
 * would crash for real the first time it reaches one. In practice this
 * only happens under deliberate tampering (e.g. kernel32's AVEH/VirtualAlloc
 * exports patched out), not on any normal Windows install.
 */
.intel_syntax noprefix
.section .text
.global karity_nanomite_install_thunk

karity_nanomite_install_thunk:
    pop     rbx                  /* rbx = &params == anchor */

    mov     rcx, [rbx]           /* site_table_delta */
    add     rcx, rbx             /* arg0 = site_table_va = anchor + delta */
    mov     edx, [rbx+8]         /* arg1 = site_count (32-bit load zero-extends rdx) */
    mov     r8,  rbx             /* arg2 = anchor */

    mov     r12, rsp             /* save rsp in a CALLEE-SAVED reg -- rax
                                     gets clobbered by the call's own return
                                     value (0/1), so it can't hold this */
    and     rsp, -16             /* align for the call */
    sub     rsp, 32              /* Win64 shadow space */
    call    karity_nanomite_install
    mov     rsp, r12             /* restore rsp */

    lea     rax, [rbx+16]        /* continue_here = params + 16 */
    jmp     rax
