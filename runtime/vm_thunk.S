/*
 * runtime/vm_thunk.S -- native entry/exit trampoline (x64, Windows/PE ABI).
 *
 * Call-site contract. The host lifter replaces a virtualized region with:
 *
 *     call    karity_vm_thunk
 *   params:
 *     .quad   <bytecode_va    - params>  ; bytecode blob VA, relative to the
 *     .quad   <exit_target_va - params>  ; address of this quad pair itself
 *     .quad   <bytecode_key_seed>        ; raw, NOT relative to params -- a
 *                                         ; random XOR-keystream seed isn't
 *                                         ; an address, so ASLR rebasing
 *                                         ; doesn't affect it (see
 *                                         ; include/karity/bytecode_crypt.h)
 *
 * `call`'s return address is exactly `params` -- it points at this 24-byte
 * parameter block, not at code, and the thunk consumes it without falling
 * through.
 *
 * The two VAs are stored as *deltas* rather than absolute addresses because
 * this patch is written directly into the image's raw bytes with no
 * corresponding PE base relocation entry: if Windows relocates the image
 * (ASLR, base collision, ...) an absolute VA baked in at protect-time would
 * go stale, but a delta from the call's own return address is base-
 * independent by construction, exactly like the RIP-relative code Zydis
 * itself would have to account for.
 *
 * karity_vmctx layout (must match include/karity/isa.h exactly):
 *   +0    vreg[16]   RAX,RCX,RDX,RBX,RSP,RBP,RSI,RDI,R8..R15 (encoding order)
 *   +128  rflags
 *   +136  vip
 *   +144  vsp
 *   +152  exit_target
 *   +160  anchor      (= params, for VOP_PUSH_REL/VOP_CALL deltas)
 *   +168  vflags      (virtual EFLAGS-style bits for VOP_CMP/TEST/JCC; zeroed
 *                       here, since nothing before VM entry produces them)
 *   +176  interp_saved_rbx      (generated-interpreter scratch, not VM state
 *                                -- see interp_codegen.cpp and isa.h)
 *   +184  interp_xreg_scratch[8] (ditto, VOP_PUSH_XREG/POP_XREG bookkeeping)
 *   +248  interp_call_flags     (ditto, VOP_CALL/VOP_CALL_IND's outbound-call
 *                                EFLAGS round-trip)
 *   +256  bytecode_base  (= vip's value at entry, fixed for the whole call;
 *                          see isa.h and include/karity/bytecode_crypt.h)
 *   +264  bytecode_key_seed (this site's XOR-keystream seed, from the third
 *                             quad field above)
 *   +272  vstack_limit   (= vmctx_base + KARITY_VMCTX_SIZE, i.e. this slot's
 *                          own vstack region's first byte -- see isa.h and
 *                          the vstack-overflow-guard paragraph below)
 *   = 280 bytes total (KARITY_VMCTX_SIZE below)
 *
 * vmctx + the private 4 KiB VM operand stack both live in karity_vm_scratch,
 * a static buffer (see the .bss block at the end of this file) -- NOT
 * carved out of the live native stack the way earlier versions of this file
 * did it. That earlier approach placed vmctx just below vreg[RSP]'s starting
 * value; VOP_CALL/CALL_IND (runtime/vm_call.S) swap real RSP to vreg[RSP] to
 * make an outbound native call, and that call is free to write arbitrarily
 * far below it (return address at minimum, more if the callee has its own
 * frame) -- ordinary bytecode as simple as a single `sub rsp, 32` function
 * prologue before a `call` was enough to walk vreg[RSP] down into vmctx's
 * own fields, so the outbound call's return-address push clobbered live VM
 * state (observed: ctx->vsp overwritten mid-block, corrupting every vstack
 * access after it). Taking vmctx/vstack off the live stack entirely removes
 * that collision regardless of how far bytecode moves vreg[RSP]. The
 * interpreter's own real-stack locals (saved RBX, XMM scratch -- see
 * src/native/interp_codegen.cpp) used to still live on the live stack just
 * below vreg[RSP]'s value for the same reason, and *did* get reached in
 * practice: an outbound call through an ordinary, non-trivial callee (e.g.
 * libc `puts()`'s first-time lazy stdio-buffer growth, five-odd real frames
 * deep into `ftell`/`_flsbuf`/`ungetwc`/`realloc`) routinely digs deeper
 * than the headroom below ever budgeted for (256 bytes, at the time),
 * corrupting whatever real-stack-resident state it walked into. Two
 * independent fixes were needed, not one: (1) those two interpreter locals
 * moved *into karity_vmctx itself* (interp_saved_rbx/interp_xreg_scratch
 * above) instead of some fixed offset assumed to sit past ctx in this
 * particular static buffer -- every hosted test in this repo constructs its
 * own bare, stack-local `karity_vmctx ctx;` with a separately-allocated
 * vstack array, so "ctx + (sizeof(karity_vmctx) + vstack size)" would have
 * silently corrupted *those* stack frames instead the moment such a test
 * ran the generated interpreter (caught exactly this way:
 * tests/karity_test_interp_codegen segfaulting intermittently, not this
 * runtime); being real struct fields means every caller's buffer is
 * correctly sized via `sizeof(karity_vmctx)` automatically. (2) That alone
 * turned out not to be sufficient for the *original* puts() corruption,
 * though: karity_vm_native_call's own saved rbx/rbp/rsi/rdi (runtime/
 * vm_call.S) and the interpreter's own eventual `ret` address still live in
 * the real-stack gap below vreg[RSP], so the 256-byte headroom itself also
 * needed widening (now 4096, see below) -- confirmed by reproducing the
 * exact same corruption with a minimal single-VOP_CALL-to-puts() program
 * even after fix (1) alone. Widening isn't a proof against arbitrarily deep
 * callees, just a much larger, still-bounded budget -- same "known, not
 * fully guarded" stance as the 4 KiB vstack size itself.
 * Nested invocations (a virtualized site's VOP_CALL/VOP_CALL_IND landing on
 * another virtualized site's own entry, re-entering this routine before the
 * outer invocation has exited) are handled by giving each live nesting
 * depth its own slot in karity_vm_scratch -- see karity_vm_depth and the
 * slot-index computation at the top of karity_vm_thunk below. Before this,
 * every invocation computed the exact same vmctx_base regardless of
 * nesting, so a nested invocation's own entry sequence (which unconditionally
 * overwrites every vmctx field with the *current* real registers) stomped
 * the outer invocation's still-live vmctx/vstack out from under it the
 * moment it started -- see src/inject/injector.h for the fuller history of
 * this limitation. Depth beyond KARITY_VM_MAX_DEPTH clamps to the last slot
 * (so two invocations at or past that depth *do* collide again) -- a known,
 * bounded fallback in the same spirit as the fixed 4 KiB vstack size or the
 * widened-but-not-infinite outbound-call headroom below, not a hard
 * guarantee against arbitrarily deep nesting.
 * vstack overflow guard: the 4 KiB private vstack itself is still a fixed
 * size (unchanged by any of the above -- see KARITY_VM_SLOT_SIZE), but
 * walking past it is no longer silent corruption. ctx->vstack_limit (isa.h)
 * is set below to this slot's own vstack region's first byte, and every
 * "push" opcode handler (the only ones that ever move vsp further down --
 * see runtime/vm_interp.c and src/native/interp_codegen.cpp) checks the
 * decremented vsp against it before writing, deliberately trapping (a bare
 * UD2, src/native/interp_codegen.cpp) instead of writing outside the slot
 * (into the interpreter's own real stack frame, a neighboring nesting-depth
 * slot, or -- for a hosted test with its own separately-allocated vstack --
 * whatever real memory happens to sit below that buffer). A hard trap
 * rather than a "resume native execution anyway" fallback is deliberate:
 * unlike an unrecognized opcode (already-corrupted bytecode, "anything goes"
 * by design), a mid-block vstack overflow means the virtualized region's
 * effects on vreg[] are only partially applied -- jumping to exit_target as
 * if the block had finished would resume the *original* program somewhere
 * it never legitimately reaches, silently executing the wrong code instead
 * of just crashing where the problem actually is.
 * SEH/exception interaction: a hardware fault or C++/SEH exception raised
 * deep inside an outbound VOP_CALL/CALL_IND target (runtime/vm_call.S calling
 * an arbitrary real WinAPI/CRT/user function) used to just kill the process
 * outright instead of reaching the *original* program's own __try/__except
 * or vectored handler, even when the unvirtualized program would have caught
 * it cleanly. Root cause: x64 Windows SEH is table-based, not chain-based --
 * RtlDispatchException walks the stack frame by frame via RtlVirtualUnwind,
 * which needs a RUNTIME_FUNCTION+UNWIND_INFO entry (a PE image's Exception
 * Directory) for *every* frame in between to know how to recover that
 * frame's caller. This thunk (and runtime/vm_call.S, and the generated
 * interpreter -- src/native/interp_codegen.cpp) are hand-written/generated
 * machine code injected into a new PE section with no such entries at all,
 * so any unwind attempting to pass through them found nothing, and Windows'
 * documented fallback for "no entry found" (assume a true leaf function: rsp
 * unchanged since entry, return address sitting at [rsp]) is *wrong* here --
 * every one of these three functions moves rsp around (this one dynamically
 * realigns it before the interpreter call; vm_call.S swaps it to vreg[RSP]
 * entirely) -- so the unwinder read garbage as a return address the moment
 * it needed to step past any of them, well before ever reaching the original
 * program's own (perfectly intact) unwind info. Fix: src/inject/injector.cpp
 * (via src/native/seh_unwind.cpp) now synthesizes real RUNTIME_FUNCTION/
 * UNWIND_INFO entries for all three and splices them into a copy of the
 * image's own Exception Directory. Each of the three uses the same one-line
 * technique -- capture the live rsp into an otherwise-unused nonvolatile
 * register (here, rbp, at karity_vm_thunk_prolog_end below) *before* doing
 * anything that moves rsp unpredictably, and never touch that register again
 * until it's restored right before returning -- so a single UNWIND_INFO
 * "establish frame pointer" op correctly recovers this function's true entry
 * rsp (and hence its own caller's return address) regardless of how rsp
 * fluctuates in between, without needing to model every individual
 * push/sub/realign along the way. karity_vm_thunk_prolog_end/
 * karity_vm_thunk_end below are read by the injector (via nm, same mechanism
 * as karity_vm_thunk itself) to size UNWIND_INFO.SizeOfProlog and this
 * function's own RUNTIME_FUNCTION range. Known gaps, in the same "bounded,
 * not a hard guarantee" spirit as everything else in this file: a fault in
 * the handful of instructions before karity_vm_thunk_prolog_end or after
 * `mov rbp, [rbx+40]` in the exit sequence (rbp briefly not the SEH frame
 * pointer) would still unwind incorrectly -- both are register-shuffle-only
 * windows with no realistic fault source. Nanomite's own VEH-based fault
 * handling (runtime/nanomite_veh.c) is a separate, unrelated mechanism and
 * isn't part of this fix.
 */
#define KARITY_VMCTX_SIZE 280 /* sizeof(karity_vmctx), include/karity/isa.h */
#define KARITY_VM_MAX_DEPTH 8 /* live nesting depths with their own scratch slot; see above */
#define KARITY_VM_SLOT_SIZE (KARITY_VMCTX_SIZE + 4096) /* one slot = one vmctx + its private vstack */
.intel_syntax noprefix
.section .text
.global karity_vm_thunk
.global karity_interp_rel32

/*
 * The interpreter itself has no linked symbol here -- it's generated fresh
 * per protection run (see src/native/interp_codegen.h) and placed
 * elsewhere in the .kvm section, so this can't be an ordinary `call
 * karity_vm_run`. It's a direct `call rel32` with karity_interp_rel32
 * naming its own (initially zero) 4-byte operand: the injector finds this
 * offset the same way it finds karity_vm_thunk's (via nm, at
 * karity-protector's own build time) and patches the displacement in
 * directly, before the blob is copied into the target image.
 *
 * This used to be an indirect call through a data pointer instead
 * (`call qword ptr [rip+ptr]`) -- functionally equivalent, and easier to
 * patch, but something in the target process (observed: a plain mingw
 * console EXE, no opted-in mitigations) faulted on the indirect control
 * transfer into freshly-injected code every time, while every *direct*
 * jmp/call elsewhere in this project (OEP -> stub, stub -> this thunk)
 * has always worked. Patching the rel32 directly sidesteps whatever that
 * was rather than root-causing it further.
 */

karity_vm_thunk:
    push    rbp                         /* SEH: a genuine push (not just a ctx-field stash) so a
                                            standard UWOP_PUSH_NONVOL unwind code can hand the
                                            *original caller's* real rbp back to whatever unwinds
                                            through this frame -- see the "SEH/exception interaction"
                                            header paragraph above: the original caller's own scope-
                                            table-based __except handling (if any) needs its real rbp
                                            back to address its own locals correctly, and a plain
                                            ctx-field stash (which is all vreg[RBP]/ctx+40 below still
                                            is, for the ordinary non-exceptional restore path) isn't
                                            something a standard unwind code can read. */
    mov     rbp, rsp                    /* establish the SEH frame pointer right after that one push --
                                            never touched again until the exit sequence's own
                                            `mov rbp, [rbx+40]` far below, so it stays valid across
                                            everything in between, however far rsp itself wanders
                                            (the depth/slot scratch below, the dynamic realignment
                                            before calling the interpreter, ...). */
    .global karity_vm_thunk_fpreg_offset
karity_vm_thunk_fpreg_offset:           /* SEH: this instruction's own end offset -- where
                                            UNWIND_INFO's UWOP_SET_FPREG code applies (see
                                            src/native/seh_unwind.cpp/injector.cpp), distinct from
                                            karity_vm_thunk_prolog_end further below (SizeOfProlog
                                            itself, which also covers the `sub rsp, 4096` past this
                                            point -- see that label's own comment for why). */
    pushfq                              /* capture original flags before anything else touches them */
    push    rbx                         /* stash caller's rbx -- about to repurpose the register as
                                            vmctx_base, and every other GPR still needs to be read
                                            (into vmctx) before it's safe to clobber it */
    push    rax                         /* stash caller's rax too -- needed as scratch for the depth/
                                            slot computation below; undone by the very next pop, so
                                            this doesn't change the stack balance the "original RSP"
                                            computation further down depends on */

    lea     rbx, [rip + karity_vm_depth]
    mov     rax, [rbx]                  /* rax = this invocation's nesting depth (0 = outermost) */
    inc     qword ptr [rbx]             /* depth++ for the duration of this invocation, unclamped --
                                            paired with the matching dec in the exit path below, so it
                                            always nets back to 0 regardless of whether the slot index
                                            computed from it (next) gets clamped */
    cmp     rax, KARITY_VM_MAX_DEPTH
    jb      1f
    mov     rax, KARITY_VM_MAX_DEPTH - 1  /* clamp: reuse the deepest slot past KARITY_VM_MAX_DEPTH --
                                              see the file header */
1:
    imul    rax, rax, KARITY_VM_SLOT_SIZE
    lea     rbx, [rip + karity_vm_scratch]
    add     rbx, rax                    /* vmctx_base = this invocation's own scratch slot, not the
                                            live stack -- see the file header for why */

    pop     rax                        /* rax = caller's original rax (undoes the second push above) */
    mov     [rbx+0],   rax
    mov     [rbx+8],   rcx
    mov     [rbx+16],  rdx
    pop     rax                        /* rax = caller's original rbx (undoes the first push) */
    mov     [rbx+24],  rax
    lea     rax, [rsp+24]              /* original RSP = current rsp (both scratch pushes already
                                           popped back off, only pushfq's 8 bytes and the SEH `push
                                           rbp` still pending) + 8 (that pushfq) + 8 (the SEH push
                                           rbp) + 8 (the `call karity_vm_thunk` return address) */
    mov     [rbx+32],  rax
    mov     rax, [rbp]                 /* caller's original rbp -- the SEH `push rbp` above wrote it
                                           right where rbp itself now points (mov rbp,rsp ran
                                           immediately after that push), so this reads it back
                                           without needing a separate stack slot */
    mov     [rbx+40],  rax
    mov     [rbx+48],  rsi
    mov     [rbx+56],  rdi
    mov     [rbx+64],  r8
    mov     [rbx+72],  r9
    mov     [rbx+80],  r10
    mov     [rbx+88],  r11
    mov     [rbx+96],  r12
    mov     [rbx+104], r13
    mov     [rbx+112], r14
    mov     [rbx+120], r15

    pop     rax                        /* rax = original rflags (pushfq's value) */
    mov     [rbx+128], rax             /* rflags */

    mov     rax, [rbp+8]               /* rax = &{bytecode_delta, exit_target_delta, bytecode_key_seed}
                                           == `params` -- the call's own return address. Read via
                                           rbp+8 (rbp = R0-8, so [rbp+8] = [R0] = params), not [rsp]:
                                           rsp itself no longer equals R0 at this point now that the
                                           SEH `push rbp` sits between them, but rbp is a fixed
                                           reference point regardless. */
    mov     rcx, [rax]
    mov     rdx, [rax+8]
    add     rcx, rax                   /* bytecode_va    = params + bytecode_delta */
    add     rdx, rax                   /* exit_target_va = params + exit_target_delta */
    mov     [rbx+136], rcx             /* vip */
    mov     [rbx+152], rdx             /* exit_target */
    mov     [rbx+160], rax             /* anchor = params (rax still holds it; adds above don't touch it) */
    mov     qword ptr [rbx+168], 0     /* vflags = 0 (nothing produces it before VM entry) */
    mov     [rbx+256], rcx             /* bytecode_base = vip's starting value (rcx untouched since) --
                                           see include/karity/bytecode_crypt.h: keystream position for a
                                           fetch is vip-at-that-moment minus this fixed value */
    mov     r10, [rax+16]              /* bytecode_key_seed, raw (not params-relative -- it's a random
                                           value, not an address). r10 is free here: its caller-original
                                           value was already saved into ctx above, before this point. */
    xor     r10, [rip + karity_anti_debug_taint] /* Fold the live anti-debug signal (include/karity/
                                           anti_debug.h) into the decryption key instead of branching on
                                           it: 0 when the environment looks clean (no-op), unpredictably
                                           nonzero the moment any check trips -- every subsequent VM
                                           invocation on this thread then decrypts its bytecode with the
                                           wrong key and runs garbage, far away in both code and time from
                                           whichever check actually fired. karity_anti_debug_taint is a
                                           plain global (not a function call) so this costs one aligned
                                           load on the hot per-VM-entry path -- the checks themselves run
                                           once at karity_anti_debug_init and periodically on a background
                                           watchdog thread, not here. A build that never links
                                           runtime/anti_debug.c's watchdog in (most hosted tests) still
                                           links the symbol itself (BSS, zero-initialized) via
                                           karity_anti_debug_hosted, so this is a no-op there too -- see
                                           runtime/CMakeLists.txt. */
    xor     r10, [rip + karity_integrity_taint] /* Fold the live self-integrity checksum (include/
                                           karity/integrity.h) into the same key, right after the anti-
                                           debug taint above. Unlike that taint (0 when clean), this is
                                           the DETERMINISTIC hash of the generated interpreter's own live
                                           bytes: at protect time the injector stored this site's key as
                                           (real_seed ^ H_expected), so when the interpreter is pristine
                                           the live hash equals H_expected and this XOR cancels it back to
                                           real_seed; the moment any hashed byte is patched, the live hash
                                           differs and every subsequent VM entry decrypts with the wrong
                                           key and runs garbage -- far from wherever the patch is. Like
                                           karity_anti_debug_taint this is a plain global (one aligned load
                                           on the hot path; the hashing runs at karity_integrity_init and
                                           on a background watchdog, not here) and stays 0 in BSS when the
                                           feature is off (binary protected without --anti-tamper, or a
                                           hosted test), making this XOR a no-op there. */
    mov     [rbx+264], r10             /* bytecode_key_seed */

    lea     rax, [rbx + KARITY_VM_SLOT_SIZE] /* private VM operand stack, 4 KiB, right after vmctx
                                           within this invocation's own slot; vsp starts at the top
                                           of the slot (== the next slot's base) and grows down */
    mov     [rbx+144], rax             /* vsp */

    lea     rax, [rbx + KARITY_VMCTX_SIZE] /* vstack_limit = this slot's own vstack region's first
                                           byte -- the lowest legal address a push may decrement vsp
                                           to (see the vstack-overflow-guard paragraph above and
                                           isa.h) */
    mov     [rbx+272], rax             /* vstack_limit */

    mov     rcx, rbx                   /* Win64 arg0 = karity_vmctx* */
    sub     rsp, 4096                  /* headroom below the real target RSP before the interpreter's
                                           own frame (and karity_vm_native_call's own saved rbx/rbp/
                                           rsi/rdi, runtime/vm_call.S) starts -- see the file header's
                                           known-limitation note. Was 256 bytes; confirmed too thin by
                                           an actual outbound VOP_CALL into libc `puts()`, whose first-
                                           time lazy stdio-buffer growth is five-odd real stack frames
                                           deep (ftell/_flsbuf/ungetwc/realloc/HeapReAlloc) and reliably
                                           dug past 256 bytes below vreg[RSP], corrupting whatever of
                                           ours sat there -- 4 KiB matches the vstack's own already-
                                           established size elsewhere in this runtime as a "generous
                                           enough for real code, not a hard guarantee" budget. */
    .global karity_vm_thunk_prolog_end
karity_vm_thunk_prolog_end:            /* SEH: UNWIND_INFO.SizeOfProlog ends *here*, not right after
                                           `mov rbp, rsp` above -- empirically (see src/native/
                                           seh_unwind.cpp and the investigation that led here),
                                           a *fixed*-size stack adjustment occurring between
                                           establishing the frame pointer and the function's first
                                           outbound call needs its own UWOP_ALLOC_LARGE unwind code
                                           describing it, even though FrameRegister is set -- unlike
                                           purely *dynamic* adjustments after that point (the `and
                                           rsp,-16` right below, or karity_vm_native_call's real
                                           stack-pointer swap in runtime/vm_call.S), which are safe
                                           to leave completely undescribed. Everything between the
                                           two labels above (pushfq/push rbx/push rax, the depth/slot
                                           computation, the ctx field stores) nets to zero real rsp
                                           change by the time this point is reached -- see the
                                           original-RSP/params-read comments above -- so folding it
                                           into "the prologue" changes nothing about what those
                                           unwind codes need to say. */
    and     rsp, -16                   /* align for the call */
    sub     rsp, 32                    /* Win64 shadow space */
    .byte   0xE8
karity_interp_rel32:
    .long   0                          /* patched: interp_va - (this_va + 4) */

    dec     qword ptr [rip + karity_vm_depth]  /* pairs with the entry's inc -- this invocation is
                                                   about to leave, freeing its depth level for any
                                                   later (non-nested) invocation. Flags-clobbering is
                                                   fine here: the real flags get restored from ctx via
                                                   popfq right below regardless. */

    push    qword ptr [rbx+128]        /* restore rflags */
    popfq

    mov     rcx, [rbx+8]
    mov     rdx, [rbx+16]
    mov     rsi, [rbx+48]
    mov     rdi, [rbx+56]
    mov     rbp, [rbx+40]
    mov     r8,  [rbx+64]
    mov     r9,  [rbx+72]
    mov     r10, [rbx+80]
    mov     r11, [rbx+88]
    mov     r12, [rbx+96]
    mov     r13, [rbx+104]
    mov     r14, [rbx+112]
    mov     r15, [rbx+120]

    mov     rsp, [rbx+32]              /* real original RSP */
    push    qword ptr [rbx+152]        /* stage exit_target on the *real* stack */
    mov     rax, [rbx+0]               /* real RAX (rax no longer needed as scratch) */
    mov     rbx, [rbx+24]              /* real RBX last (reads through old rbx, then overwrites) */
    ret                                /* pop exit_target -> RIP; rsp ends exactly at original RSP */
    .global karity_vm_thunk_end
karity_vm_thunk_end:                   /* end-of-function marker, read by the injector to size this
                                           function's RUNTIME_FUNCTION entry (see SEH paragraph above
                                           and src/inject/injector.cpp/src/native/seh_unwind.cpp) */

/* karity_vm_depth: live (entered but not yet exited) karity_vm_thunk
 * invocation count on this thread -- see the entry/exit sequences above.
 * karity_vm_scratch: KARITY_VM_MAX_DEPTH slots, each one vmctx
 * (KARITY_VMCTX_SIZE bytes, including the generated interpreter's own
 * interp_saved_rbx/interp_xreg_scratch/interp_call_flags fields -- see the
 * file header and isa.h) immediately followed by that invocation's own 4 KiB
 * private VM operand stack -- see the file header for why this whole buffer
 * is static rather than carved out of the live stack, and for the per-depth
 * slot scheme that lets nested invocations avoid colliding with each other.
 * Not thread-safe (concurrent karity_vm_thunk invocations on *different*
 * threads still share the same depth counter and slots); same
 * single-thread assumption the rest of this runtime already makes. */
.section .bss
.align 16
karity_vm_depth:
    .space 8
karity_vm_scratch:
    .space KARITY_VM_SLOT_SIZE * KARITY_VM_MAX_DEPTH
