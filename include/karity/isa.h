#ifndef KARITY_ISA_H
#define KARITY_ISA_H

#include <stdint.h>

#define KARITY_ISA_VERSION 1u

typedef enum karity_vop {
    VOP_NOP        = 0x00, /* do nothing                                        */
    VOP_VMEXIT     = 0x01, /* restore native context, resume at exit_target     */

    /* data movement -------------------------------------------------------- */
    VOP_PUSH_IMM   = 0x10, /* imm64 operand -> vstack                           */
    VOP_PUSH_VREG  = 0x11, /* u8 vreg operand: vreg[i] -> vstack                */
    VOP_POP_VREG   = 0x12, /* u8 vreg operand: vstack -> vreg[i]                */
    VOP_PUSH_REL   = 0x13, /* i64 delta operand -> push(ctx->anchor + delta)    */
                           /* anchor is a live, correctly-relocated in-image    */
                           /* address (see runtime/vm_thunk.S); use this        */
                           /* instead of PUSH_IMM for any address that must     */
                           /* survive the image being loaded at a different    */
                           /* base than it was protected at (ASLR, etc).        */
    VOP_DROP       = 0x14, /* pop and discard (stack-neutral junk filler)       */

    /* arithmetic / logic (pop b, pop a, push a op b; all set ctx->vflags   */
    /* the same way the equivalent native instruction would)               */
    VOP_ADD        = 0x20,
    VOP_SUB        = 0x21,
    VOP_XOR        = 0x22,
    VOP_AND        = 0x23,
    VOP_OR         = 0x24,
    VOP_CMP        = 0x25, /* pop b, pop a; set vflags from a-b, push nothing */
    VOP_TEST       = 0x26, /* pop b, pop a; set vflags from a&b, push nothing */

    /* unary (pop a, push op a); 0x28 is deliberately skipped -- it's already
       a decoy sentinel byte in runtime/vm_interp.c's dispatch chain */
    VOP_NEG        = 0x27, /* push -a (two's complement); sets vflags exactly
                               like a native `0 - a` (CF/OF's "operand==0"/
                               "operand==INT64_MIN" special cases fall out of
                               that formula for free)                       */
    VOP_NOT        = 0x29, /* push ~a; does NOT touch vflags (matches native
                               NOT, which is flag-transparent)               */
    VOP_INC        = 0x2A, /* push a+1; sets vflags like native INC (OF/SF/
                               ZF/PF as if `a+1`, but CF is left exactly as
                               it was -- INC/DEC never touch CF, unlike
                               ADD/SUB)                                     */
    VOP_DEC        = 0x2B, /* push a-1; same CF-preserving contract as
                               VOP_INC, OF/SF/ZF/PF as if `a-1`             */

    /* shift/rotate (pop count, pop a, push result). count is masked to the
       low 6 bits (0-63) first, matching real x86-64 shift/rotate semantics
       for a 64-bit operand. If the masked count is 0, vflags is left
       completely untouched (matches native hardware exactly -- a shift by
       0 is a real no-op, flags included). OF is only ever set to a
       meaningful value when the masked count is exactly 1 (the one case
       the x86 spec actually defines it for); for any other nonzero count
       it's deliberately left cleared here rather than reproducing
       whatever a real CPU happens to compute -- the spec calls it
       undefined, and no legitimate compiler-generated code branches on it. */
    VOP_SHL        = 0x2D, /* logical left shift. CF = last bit shifted out;
                               SF/ZF/PF from the result; OF (count==1) =
                               MSB(result) XOR CF                          */
    VOP_SHR        = 0x2E, /* logical right shift. CF = last bit shifted
                               out; SF/ZF/PF from the result; OF (count==1)
                               = MSB of the *original* operand             */
    VOP_SAR        = 0x2F, /* arithmetic (sign-extending) right shift. Same
                               CF/SF/ZF/PF contract as VOP_SHR; OF is always
                               0 for count==1 (sign can't change)          */
    VOP_ROL        = 0x38, /* rotate left. Unlike the shifts above, SF/ZF/PF
                               are *not* touched at all (matches native
                               ROL/ROR); CF = LSB of the result; OF
                               (count==1) = MSB(result) XOR CF            */
    VOP_ROR        = 0x3A, /* rotate right. Same SF/ZF/PF-untouched
                               contract as VOP_ROL; CF = MSB of the result;
                               OF (count==1) = MSB(result) XOR bit62 of the
                               result                                     */
    VOP_MUL        = 0x3C, /* unsigned one-operand multiply: pop b, implicit
                               a = vreg[RAX] (vreg[0]); RDX:RAX = a*b (full
                               128-bit unsigned product). vreg[RAX]=low64,
                               vreg[RDX]=high64 -- mirrors native MUL, whose
                               destination is the fixed RDX:RAX pair, not
                               whatever bytecode follows. No push. CF=OF=1
                               iff high64 != 0; SF/ZF/AF/PF are left exactly
                               as they were (native SDM calls them
                               "undefined" here -- same "define it, don't
                               reproduce hardware garbage" choice as
                               VOP_ROL/VOP_ROR's count>1 OF).             */
    VOP_IMUL1      = 0x3D, /* signed one-operand multiply (native `imul
                               r/m64`): same pop-b/implicit-a/vreg[RAX]+
                               vreg[RDX]-write shape as VOP_MUL, signed
                               instead of unsigned. CF=OF=1 iff the true
                               128-bit signed product doesn't fit in 64
                               bits (high64 isn't just the sign-extension of
                               low64); SF/ZF/AF/PF left untouched, same as
                               VOP_MUL. 0x3E is deliberately skipped -- it's
                               already a decoy sentinel byte in
                               runtime/vm_interp.c's dispatch chain.       */
    VOP_IMUL2      = 0x3F, /* signed two-operand multiply (native `imul r64,
                               r/m64`; also covers the three-operand `imul
                               r64,r/m64,imm32` form -- lift-time identical
                               once both sources are on the vstack): pop b,
                               pop a, push low64(a*b). CF=OF=1 iff the true
                               128-bit signed product doesn't fit in 64
                               bits; SF/ZF/AF/PF left untouched. Unlike
                               VOP_MUL/VOP_IMUL1, this never touches
                               vreg[RAX]/vreg[RDX] at all -- matches native
                               two/three-operand IMUL, whose destination is
                               whichever register the instruction names,
                               with the high 64 bits of the product simply
                               discarded.                                 */
    VOP_DIV        = 0x48, /* unsigned divide (native `div r/m64`): pop b
                               (divisor), implicit dividend =
                               vreg[RDX]:vreg[RAX] (128-bit unsigned, same
                               convention as native DIV -- the caller must
                               already have zeroed/sign-extended vreg[RDX]
                               appropriately, exactly like real code needs
                               `xor edx,edx`/`cqo` before a real
                               `div`/`idiv`). vreg[RAX]=quotient,
                               vreg[RDX]=remainder. No push, no flags --
                               native DIV's flags are all explicitly
                               undefined, so vflags is left exactly as it
                               was. Divisor==0 or a quotient that doesn't
                               fit in 64 bits is a native #DE fault (SIGFPE)
                               in the real injected interpreter
                               (src/native/interp_codegen.cpp), which
                               executes an actual `div`; the portable C
                               reference implementation
                               (runtime/vm_interp.c) has no hardware fault
                               to raise for that case and instead leaves
                               vreg[RAX]/vreg[RDX] at whatever its software
                               division loop computes -- a known, documented
                               divergence between the two interpreters that
                               only matters for already-undefined-behavior
                               input (real unprotected hardware would have
                               crashed too).                               */
    VOP_IDIV       = 0x49, /* signed divide (native `idiv r/m64`): same
                               pop-b/implicit-128-bit-dividend/vreg[RAX]+
                               vreg[RDX]-write shape as VOP_DIV, with
                               truncating (toward zero) signed
                               division/remainder semantics instead. Same
                               #DE-divergence and flags-untouched notes as
                               VOP_DIV apply.                              */

    /* memory (pop addr, push [addr] / pop value, pop addr, [addr] = value) - */
    VOP_LOAD8      = 0x30,
    VOP_LOAD16     = 0x31,
    VOP_LOAD32     = 0x32,
    VOP_LOAD64     = 0x33,
    VOP_STORE8     = 0x34,
    VOP_STORE16    = 0x35,
    VOP_STORE32    = 0x36,
    VOP_STORE64    = 0x37,

    /* control flow ----------------------------------------------------------*/
    VOP_CALL       = 0x40, /* i64 delta operand: native call to
                               ctx->anchor + delta. Passes vreg[RCX/RDX/R8/R9]
                               (Win64 int arg regs) and the real vreg[RSP]-
                               based stack through untouched, honoring shadow
                               space/alignment; result -> vreg[RAX]. Clobbers
                               rflags and the volatile GPRs exactly like a
                               native `call` would. */
    VOP_JMP        = 0x41, /* i64 rel operand -> vip += rel (rel is relative
                               to the address right after this operand)      */
    VOP_JCC_NZ     = 0x42, /* pop cond, i64 rel operand: if cond != 0,
                               vip += rel (same relative-address convention
                               as VOP_JMP); otherwise falls through          */
    VOP_JCC        = 0x43, /* u8 cc operand (KARITY_CC_*, no stack pop), i64
                               rel operand: if ctx->vflags satisfies cc,
                               vip += rel; otherwise falls through. Mirrors
                               native Jcc, driven by vflags instead of a
                               popped stack value.                          */
    VOP_CALL_IND   = 0x45, /* no operand: pop target addr, native call to it.
                               Same passthrough/clobber contract as VOP_CALL
                               (vreg[RCX/RDX/R8/R9] + real vreg[RSP]-based
                               stack in, vreg[RAX] out); the only difference
                               is the target is a runtime value already on
                               the vstack (from a register or a dereferenced
                               [mem] operand) instead of a lift-time-known
                               anchor+delta -- needed for register-indirect
                               calls and IAT-style `call [rip+X]`/`call [reg
                               +disp]` calls, whose target isn't known until
                               the loader/program has run. 0x44 is skipped --
                               it's already a decoy sentinel byte in
                               runtime/vm_interp.c's dispatch chain. */
    VOP_VMEXIT_REL = 0x46, /* i64 delta operand: ctx->exit_target =
                               ctx->anchor + delta, then restore native
                               context and resume there -- same net effect as
                               VOP_VMEXIT, but with an explicit, bytecode-
                               encoded target instead of relying on whatever
                               ctx->exit_target was pre-filled with before VM
                               entry. Needed once a lifted region has more
                               than one native resume point (a branch/loop
                               edge that leaves the virtualized CFG): each
                               such edge carries its own target here, while
                               VOP_VMEXIT (no operand) remains the single-
                               exit-point case (e.g. the straight-line
                               mandatory entry prefix falling through with no
                               branch found at all). 0x47 is skipped -- it's
                               already a decoy sentinel byte in
                               runtime/vm_interp.c's dispatch chain. */

    /* sub-64-bit register/memory operand widening (pop a, push result; */
    /* never touches vflags -- matches native MOVZX/MOVSX/MOVSXD, which  */
    /* are all flag-transparent) ------------------------------------------- */
    VOP_MOVZX      = 0x4A, /* u8 src_size operand (1 or 2, bytes): push
                               zero_extend(a & ((1 << (src_size*8)) - 1)).
                               Unlike VOP_MOVSX below, there's no separate
                               destination-width operand: zero-extending a
                               narrow value into a 32-bit destination and
                               then letting native x86's implicit "writing
                               a 32-bit GPR zeroes its upper 32 bits" rule
                               apply produces the exact same 64-bit result
                               as zero-extending straight to 64 bits, so a
                               32-bit-dest `movzx r32, r/m8` and a
                               64-bit-dest `movzx r64, r/m8` lift to
                               identical bytecode. */
    VOP_MOVSX      = 0x4C, /* u8 src_size operand (1, 2, or 4 bytes), u8
                               dst_size operand (4 or 8 bytes): push
                               sign_extend(a, src_size*8 bits) truncated to
                               64 bits, then -- only if dst_size == 4 --
                               masked down to the low 32 bits. That extra
                               mask matters and is NOT redundant with a
                               plain 64-bit sign extension: native `movsx
                               r32, r/m8` sign-extends into a 32-bit result
                               and only *then* implicitly zeroes the upper
                               32 bits (e.g. src byte 0x80 -> 0x00000000_
                               FFFFFF80), which differs from a direct
                               64-bit sign extension of the same byte
                               (0xFFFFFFFF_FFFFFF80) whenever the source is
                               negative. `movsxd r64, r/m32` (opcode 0x63,
                               REX.W) is the same shape with src_size=4,
                               dst_size=8 -- lifted through this same
                               opcode, not a separate one. 0x4B is
                               deliberately skipped -- it's already a decoy
                               sentinel byte in runtime/vm_interp.c's
                               dispatch chain. */

    /* Scalar SSE/SSE2 floating point. Unlike vreg[], there is no persistent,
       ctx-resident XMM register file mirrored to/from real hardware at VM
       entry/exit (no karity_vmctx change, no vm_thunk.S XMM save/restore) --
       KARITY_XREG_COUNT "xreg" slots below are purely an execution-local
       bookkeeping device (a local array in runtime/vm_interp.c; interpreter-
       stack-frame-relative scratch memory in src/native/interp_codegen.cpp),
       scoped to a single karity_vm_run invocation, so that a MOVSD/MOVSS
       producer earlier in a lifted block can feed a consumer later in the
       same block. A native XMM register's value from *before* VM entry (or
       after VM exit) is simply not modeled -- same "wrong thing is worse
       than nothing" scoping as every other not-quite-supported instruction
       shape in this VM. All eight ops below are flag-transparent (matches
       native SSE arithmetic, which never touches integer RFLAGS at all). */
    VOP_PUSH_XREG  = 0x50, /* u8 xreg operand: xreg[i] (raw 8 bytes) -> vstack */
    VOP_POP_XREG   = 0x51, /* u8 xreg operand: vstack -> xreg[i] (raw 8 bytes) */
    VOP_ADDSD      = 0x52, /* pop b, pop a, push (double)a + (double)b, all as
                               raw 8-byte bit patterns */
    VOP_SUBSD      = 0x53,
    VOP_MULSD      = 0x54,
    VOP_DIVSD      = 0x55,
    VOP_ADDSS      = 0x56, /* pop b, pop a, push (float)a + (float)b; operands
                               and result are the low 4 bytes of an 8-byte
                               vstack slot, upper 4 bytes always zeroed on
                               push (matches VOP_MOVZX-style zero-extension,
                               so every producer of an SS value agrees on the
                               full 64-bit slot contents) */
    VOP_SUBSS      = 0x57,
    VOP_MULSS      = 0x58,
    VOP_DIVSS      = 0x59,
    VOP_CVTSI2SD   = 0x5A, /* pop a (int64), push (double)a as bits */
    VOP_CVTTSD2SI  = 0x5B, /* pop a (double bits), push (int64_t)a, truncating
                               toward zero; overflow/NaN is undefined behavior
                               in the C reference (runtime/vm_interp.c) but a
                               genuine hardware "integer indefinite" result in
                               the real injected interpreter (executes an
                               actual cvttsd2si) -- same kind of documented
                               two-interpreter divergence on already-
                               undefined-behavior input as VOP_DIV/VOP_IDIV */
    VOP_CVTSI2SS   = 0x5C, /* pop a (int64), push (float)a, zero-extended into
                               the full 8-byte slot */
    VOP_CVTTSS2SI  = 0x5D, /* pop a (float bits, low 4 bytes), push (int64_t)a,
                               truncating; same overflow/NaN divergence note
                               as VOP_CVTTSD2SI */

    VOP__COUNT
} karity_vop;

/* Number of virtualized general-purpose slots (RAX..R15, in encoding order). */
#define KARITY_VREG_COUNT 16

/* Number of execution-local scalar-float bookkeeping slots for
   VOP_PUSH_XREG/VOP_POP_XREG (see the comment above VOP_PUSH_XREG) -- covers
   XMM0..XMM7 only, matching this VM's lifter (src/vm/lifter.cpp's
   reg_to_xmm). */
#define KARITY_XREG_COUNT 8

/* vflags bit layout, deliberately identical to the corresponding bits of
   real x86 RFLAGS (CF=0, PF=2, ZF=6, SF=7, OF=11): the hand-generated
   interpreter (src/native/interp_codegen.cpp) captures real hardware flags
   after each ALU op via pushfq and stores them verbatim, so no translation
   is needed between "real" and "virtual" flag bits. AF (bit 4) is not
   modeled -- no KARITY_CC_* condition ever reads it (only DAA/DAS/AAA do,
   which this VM doesn't support). */
#define KARITY_FLAG_CF (1u << 0)
#define KARITY_FLAG_PF (1u << 2)
#define KARITY_FLAG_ZF (1u << 6)
#define KARITY_FLAG_SF (1u << 7)
#define KARITY_FLAG_OF (1u << 11)

/* Condition codes for VOP_JCC, identical to the x86 Jcc/SETcc "cc" nibble
   (Intel SDM Vol 2, Table 4-13 / the low nibble of opcodes 0x70+cc and
   0x0F 0x80+cc) so lifting a native Jcc mnemonic is a direct table lookup.
   Codes pair up by (cc, cc^1) as exact logical negations of each other. */
#define KARITY_CC_O   0x0 /* OF=1                                  */
#define KARITY_CC_NO  0x1 /* OF=0                                  */
#define KARITY_CC_B   0x2 /* CF=1                (unsigned <)      */
#define KARITY_CC_AE  0x3 /* CF=0                (unsigned >=)     */
#define KARITY_CC_E   0x4 /* ZF=1                (==)              */
#define KARITY_CC_NE  0x5 /* ZF=0                (!=)              */
#define KARITY_CC_BE  0x6 /* CF=1 or ZF=1        (unsigned <=)     */
#define KARITY_CC_A   0x7 /* CF=0 and ZF=0       (unsigned >)      */
#define KARITY_CC_S   0x8 /* SF=1                                  */
#define KARITY_CC_NS  0x9 /* SF=0                                  */
#define KARITY_CC_P   0xA /* PF=1                                  */
#define KARITY_CC_NP  0xB /* PF=0                                  */
#define KARITY_CC_L   0xC /* SF!=OF              (signed <)        */
#define KARITY_CC_GE  0xD /* SF==OF              (signed >=)       */
#define KARITY_CC_LE  0xE /* ZF=1 or SF!=OF      (signed <=)       */
#define KARITY_CC_G   0xF /* ZF=0 and SF==OF     (signed >)        */

typedef struct karity_vmctx {
    uint64_t vreg[KARITY_VREG_COUNT]; /* mirrors native RAX..R15               */
    uint64_t rflags;                  /* native RFLAGS snapshot                */
    uint64_t vip;                     /* bytecode cursor (absolute host addr)  */
    uint64_t vsp;                     /* vstack pointer (absolute host addr)   */
    uint64_t exit_target;             /* native RIP to resume at on VMEXIT     */
    uint64_t anchor;                  /* live in-image address (the call
                                          site's own return address); base for
                                          VOP_PUSH_REL/VOP_CALL deltas so they
                                          survive the image loading at a
                                          different base than protect-time   */
    uint64_t vflags;                  /* KARITY_FLAG_* bits, set by
                                          VOP_ADD/SUB/XOR/AND/OR/CMP/TEST and
                                          consumed by VOP_JCC. Appended after
                                          anchor so existing field offsets
                                          (used verbatim by runtime/vm_thunk.S
                                          and src/native/interp_codegen.cpp)
                                          don't shift.                       */
    uint64_t interp_saved_rbx;        /* Scratch for the *generated interpreter
                                          itself* (src/native/interp_codegen.cpp),
                                          not VM state: RBX is Win64 callee-
                                          saved, so the interpreter (which
                                          repurposes the physical register as
                                          its own ctx pointer) stashes the
                                          real caller's original value here
                                          across the whole call and restores
                                          it before returning. Lives in ctx
                                          itself -- not a local on the
                                          interpreter's own real stack frame --
                                          so an outbound VOP_CALL/CALL_IND
                                          that digs arbitrarily deep into its
                                          own callee's stack usage can never
                                          overwrite it (that used to happen:
                                          see runtime/vm_thunk.S's header).  */
    uint64_t interp_xreg_scratch[KARITY_XREG_COUNT]; /* Same reasoning, for
                                          VOP_PUSH_XREG/VOP_POP_XREG's
                                          execution-local bookkeeping slots
                                          (see the VOP_PUSH_XREG comment
                                          above) -- also generated-
                                          interpreter scratch, not persistent
                                          VM state, just ctx-resident instead
                                          of real-stack-resident for the same
                                          collision-safety reason.           */
    uint64_t interp_call_flags;       /* VOP_CALL/VOP_CALL_IND scratch: real
                                          EFLAGS captured right before the
                                          "align + shadow space" `sub rsp,40`
                                          bracket around the outbound native
                                          call, restored right before the
                                          call itself -- that sub generates
                                          its own (VM-irrelevant) flags from
                                          the interpreter's own rsp
                                          arithmetic, which nothing between
                                          it and the outbound call naturally
                                          overwrites, so without this an
                                          arbitrary real callee would
                                          observe VM-internal flag noise
                                          instead of whatever the emulated
                                          program's own last flag-producing
                                          instruction left (not stack- or
                                          register-resident: the sub itself
                                          moves real RSP in between, and
                                          every GPR live at that point is
                                          already spoken for -- see
                                          src/native/interp_codegen.cpp).   */
    uint64_t bytecode_base;           /* VA of this invocation's first
                                          bytecode byte -- the same value
                                          written into vip at entry (see
                                          runtime/vm_thunk.S), kept fixed
                                          here for the whole karity_vm_run
                                          call while vip itself moves
                                          (sequentially, and via jumps) as
                                          execution proceeds. Bytecode is
                                          encrypted at rest (see
                                          include/karity/bytecode_crypt.h);
                                          a fetch's logical keystream
                                          position is `vip - bytecode_base`,
                                          which must stay meaningful across
                                          arbitrary jumps within one site's
                                          blob, not just sequential
                                          advancement -- "rolling"
                                          decryption, see look/todo.md
                                          section C.                       */
    uint64_t bytecode_key_seed;       /* This site's random XOR-keystream
                                          seed (include/karity/
                                          bytecode_crypt.h), set once per
                                          protect run per site
                                          (src/inject/injector.cpp) and
                                          carried in the vm_thunk call-site
                                          quad (runtime/vm_thunk.S) alongside
                                          bytecode_va/exit_target_va --
                                          stored raw, not anchor-relative,
                                          since a random key isn't an
                                          address and ASLR doesn't apply
                                          to it.                           */
    uint64_t vstack_limit;            /* Lowest address `vsp` may legally
                                          point at after a push -- one past
                                          the last byte *below* the private
                                          vstack buffer (runtime/vm_thunk.S
                                          sets this to vmctx_base +
                                          sizeof(karity_vmctx), i.e. right
                                          where that invocation's own 4 KiB
                                          vstack region begins). Every real
                                          "push" opcode (PUSH_IMM/PUSH_VREG/
                                          PUSH_REL/PUSH_XREG -- the only ones
                                          that ever move vsp further down;
                                          see their handlers in
                                          runtime/vm_interp.c and
                                          src/native/interp_codegen.cpp)
                                          checks the decremented vsp against
                                          this before writing: walking below
                                          it used to silently corrupt
                                          whatever real memory sat past the
                                          fixed-size vstack buffer (the
                                          interpreter's own stack frame, or a
                                          neighboring nesting-depth slot --
                                          see vm_thunk.S's header) instead of
                                          failing. A caller that leaves this
                                          zero-initialized (every existing
                                          hosted test that doesn't set it)
                                          gets the pre-guard behavior back --
                                          vsp can never legally be a null-ish
                                          low address, so the check simply
                                          never fires. */
} karity_vmctx;


typedef struct karity_program_hdr {
    uint32_t magic;      /* KARITY_PROG_MAGIC                                   */
    uint16_t isa_ver;    /* KARITY_ISA_VERSION                                  */
    uint16_t reserved;
    uint32_t code_size;  /* bytecode length in bytes, excluding this header     */
    uint32_t entry_off;  /* first opcode offset, relative to end of header      */
} karity_program_hdr;

#define KARITY_PROG_MAGIC 0x314D524Bu /* 'KRM1' little-endian */

#endif /* KARITY_ISA_H */
