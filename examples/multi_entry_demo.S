/*
 * examples/multi_entry_demo.S -- exercises multiple simultaneous
 * virtualization sites in one binary (src/inject/injector.h's
 * `extra_entry_rvas`): OEP is one site, and `second_func` -- a distinct
 * function -- is protected as a second, independent site via `--entry`.
 * Each gets its own lifted bytecode, its own anchor, and its own
 * `call thunk` + quad pair in the shared .kvm section, all funneled through
 * the same shared interpreter and vm_thunk.
 *
 * OEP's mandatory prefix is `mov rax, 0` (7 bytes); the CFG walker then just
 * lifts NOP padding until it runs off the end of the 256-byte probe window,
 * at which point it native-exits into `native_tail` -- which is
 * deliberately placed *past* that window so `call second_func` itself stays
 * genuinely native, not a lifted VOP_CALL. Nesting one vm_thunk invocation
 * inside another (a VOP_CALL landing on a *second* site's own vm_thunk
 * entry) is safe now -- vm_thunk.S gives each live nesting depth its own
 * scratch slot, see injector.h -- but this demo still keeps the call
 * genuinely native anyway, since that's the far more common real-world
 * shape (an ordinary, non-virtualized caller invoking a virtualized
 * function) and needs no special placement to arrange.
 *
 * second_func's own mandatory prefix is `mov rax, 32` (7 bytes); its
 * `add rax, 10` is picked up by its own CFG walker, and its `ret` stays
 * native (RET isn't lifted -- see src/vm/lifter.h).
 *
 * Computes 32+10=42 and exits with that value via ExitProcess, so comparing
 * the protected binary's exit code against the unprotected one's proves both
 * sites actually ran (through the VM) rather than one silently falling back
 * to native code.
 *
 * Build (no CRT involved):
 *   gcc -o multi_entry_demo.exe multi_entry_demo.S -nostartfiles -Wl,-e,my_entry -lkernel32
 *
 * Protect (second_func's RVA found via `nm multi_entry_demo.exe`, minus the
 * image base from `objdump -p`):
 *   karity-protector.exe multi_entry_demo.exe -o multi_entry_demo.protected.exe --entry <second_func RVA, hex>
 */
.intel_syntax noprefix
.section .text
.global my_entry
.global second_func
.extern __imp_ExitProcess

my_entry:
    mov     rax, 0
    /* Past this point stays outside the 256-byte probe/CFG-walk window
     * (see the file header comment above), so it's never lifted. */
    .fill 280, 1, 0x90

native_tail:
    call    second_func
    mov     rcx, rax
    sub     rsp, 40
    call    qword ptr [rip+__imp_ExitProcess]
    add     rsp, 40
    ret

    /* Padding so second_func's own 256-byte probe window doesn't overlap
     * my_entry's (the injector rejects overlapping sites) and has room to
     * fit entirely within this section's raw data. Never executed. */
    .fill 300, 1, 0x90

second_func:
    mov     rax, 32
    add     rax, 10
    ret

    .fill 300, 1, 0x90
