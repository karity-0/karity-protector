/*
 * examples/double_call_demo.S -- minimal repro for the vmctx/live-stack
 * collision bug fixed in runtime/vm_thunk.S (see look/todo.md B section):
 * a plain `sub rsp, 40; call helper` (helper returns normally) followed by
 * a second call (ExitProcess, via the IAT -> VOP_CALL_IND) in the *same*
 * lifted block. Before the fix, vmctx/vstack were carved out of the live
 * stack directly below vreg[RSP]'s starting value, so `helper`'s own
 * return-address push (at vreg[RSP]-8) landed on ctx->vsp -- every vstack
 * access after that (here, pushing ExitProcess's IAT-loaded target) read
 * back corrupted data and crashed. 100% reproducible SIGSEGV pre-fix;
 * exit code 42 (matching the unprotected binary) post-fix.
 *
 * Build (no CRT involved):
 *   gcc -o double_call_demo.exe double_call_demo.S -nostartfiles -Wl,-e,my_entry -lkernel32
 */
.intel_syntax noprefix
.section .text
.global my_entry
.extern __imp_ExitProcess

helper:
    mov     rax, 42
    ret

my_entry:
    mov     rax, 0
    sub     rsp, 40
    call    helper
    mov     rcx, rax
    add     rsp, 40
    sub     rsp, 40
    call    qword ptr [rip+__imp_ExitProcess]
    add     rsp, 40
    ret
