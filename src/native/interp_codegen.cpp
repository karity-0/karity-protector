#include "interp_codegen.h"

#include <algorithm>
#include <string>
#include <unordered_map>

#include "karity/isa.h"
#include "x64_asm.h"
#include "x86_junk.h"

namespace karity {

namespace {

using namespace x64;

// Register assignment. ctx must be non-volatile (Win64: RBX/RBP/RSI/RDI/
// R12-R15/RSP) because it has to survive the VOP_CALL handler's nested
// native call -- an arbitrary compiled callee is only guaranteed to
// preserve non-volatile registers. ip/sp/scratch can be volatile since
// they're explicitly flushed to/reloaded from *ctx around that same call.
// All five avoid R12/R13 as memory-operand bases (see x64_asm.h).
constexpr int REG_CTX = 3;  // RBX
constexpr int REG_IP  = 8;  // R8
constexpr int REG_SP  = 9;  // R9
constexpr int REG_T0  = 10; // R10
constexpr int REG_T1  = 11; // R11
constexpr int REG_RCX = 1;
constexpr int REG_RDX = 2;
constexpr int REG_RSP = 4;

// karity_vmctx field offsets (include/karity/isa.h) -- vreg[16] at 0..127.
// rflags (128) isn't listed: the interpreter never touches it (vm_thunk.S
// owns it, before/after this code runs). exit_target (152) *is* now written
// here, by VOP_VMEXIT_REL only -- plain VOP_VMEXIT still leaves it alone,
// relying on whatever vm_thunk.S pre-filled it with.
constexpr int32_t OFF_VIP         = 136;
constexpr int32_t OFF_VSP         = 144;
constexpr int32_t OFF_EXIT_TARGET = 152;
constexpr int32_t OFF_ANCHOR      = 160;
constexpr int32_t OFF_VFLAGS      = 168;
// "Opcode rolling decryption" (see include/karity/bytecode_crypt.h and
// look/todo.md section C): the bytecode this interpreter reads is encrypted
// at rest, and every fetch below decrypts on the fly using these two.
constexpr int32_t OFF_BYTECODE_BASE = 256;
constexpr int32_t OFF_BYTECODE_SEED = 264;
// vstack overflow guard (see the comment above guard_vstack_overflow's
// definition in generate_interpreter, and isa.h's vstack_limit comment).
constexpr int32_t OFF_VSTACK_LIMIT = 272;

// This interpreter's own private locals -- the caller's real RBX (saved
// across the whole call per Win64's callee-saved contract) and the
// PUSH_XREG/POP_XREG scratch array -- are real fields of karity_vmctx itself
// now (interp_saved_rbx/interp_xreg_scratch, see isa.h), not a stack
// reservation in the interpreter's own frame. This used to be a `push rbx` +
// `sub rsp, 8+XMM_SCRATCH_SIZE` on the interpreter's own real stack frame,
// sitting just below wherever vreg[RSP] happened to point -- VOP_CALL/
// CALL_IND swap real RSP to vreg[RSP] to make an outbound call (runtime/
// vm_call.S), and that callee is free to use as much of its own stack as it
// likes below that point. A trivial callee (a couple of instructions, no
// further calls) never reaches far enough to matter, but anything with a
// real internal call chain -- observed: an ordinary libc `puts()`'s
// first-time lazy stdio-buffer growth, five-odd frames deep into `ftell`/
// `_flsbuf`/`ungetwc`/`realloc` -- comfortably outgrows the margin vm_thunk.S
// reserves below vreg[RSP] before calling the interpreter at all (widened
// from 256 to 4096 bytes for the same reason, see that file) and can
// overwrite whatever real-stack-resident state sits in that gap. Moving
// these two fields into ctx removes them from that gap entirely rather than
// just making it wider (karity_vm_native_call's own saved rbx/rbp/rsi/rdi,
// runtime/vm_call.S, and the interpreter's own eventual `ret` address still
// live there, which is why vm_thunk.S's own margin needed widening too --
// this alone wasn't sufficient). Putting these two fields in ctx itself
// (rather than at some fixed offset *past* ctx, assumed to be the same
// static karity_vm_scratch buffer vm_thunk.S uses) matters for a second,
// independent reason: every hosted test in this repo constructs its own
// bare, stack-local `karity_vmctx ctx;` with an unrelated, separately-
// allocated vstack array (see tests/test_interp_codegen_main.cpp) --
// reading/writing past the end of *that* would have corrupted the test's
// own stack instead (caught this exact mistake via
// tests/test_interp_codegen_main.cpp itself segfaulting intermittently once
// every handful of runs, before this ended up as fields on the struct all
// such callers already size correctly via `sizeof(karity_vmctx)`).
constexpr int32_t OFF_SAVED_RBX    = 176; // interp_saved_rbx
constexpr int32_t OFF_XREG_SCRATCH = 184; // interp_xreg_scratch[0]
constexpr int32_t OFF_CALL_FLAGS   = 248; // interp_call_flags (see isa.h)

// vreg[i] lives at ctx + i*8; RAX=vreg[0], RDX=vreg[2] -- MUL/IMUL1/DIV/IDIV
// read/write these two implicitly, mirroring native hardware's fixed
// RAX/RDX operands for those instructions.
constexpr int32_t OFF_VREG_RAX = 0;
constexpr int32_t OFF_VREG_RDX = 16;
// Physical register indices for the same two, used as scratch to hold the
// implicit operand while the real mul/imul/div/idiv instruction executes --
// unused as a persistent role elsewhere in this file, and (like RCX/RDX
// below) fully restored by any J() junk that happens to pick them, so it's
// safe to keep a value alive in them across a J() call.
constexpr int PHYS_RAX = 0;
constexpr int PHYS_RDX = 2;
// SEH frame-pointer register (see the prologue/epilogue comments below) --
// unused as any persistent role elsewhere in this file, so free to repurpose
// for the whole function body the way REG_CTX/REG_IP/etc. are.
constexpr int PHYS_RBP = 5;

// VOP_PUSH_XREG/POP_XREG's execution-local "xreg" bookkeeping slots (see
// isa.h) live at ctx + OFF_XREG_SCRATCH (see above) -- KARITY_XREG_COUNT*8 =
// 64 bytes, addressed the same way vreg[] is (idx*8 computed at runtime into
// a scratch GPR, then a plain load/store), just based off REG_CTX plus this
// fixed offset instead of REG_CTX alone.
constexpr int32_t XMM_SCRATCH_SIZE = KARITY_XREG_COUNT * 8;
// Fixed scratch XMM registers used to do real SSE arithmetic/converts --
// never the persistent "xreg" slots above, which are memory-resident, not
// physical-register-resident (see the case 0x52-0x5D handlers).
constexpr int PHYS_XMM0 = 0;
constexpr int PHYS_XMM1 = 1;

// Two-pass label resolution for the jumps stitching dispatch/handlers
// together: `mark` resolves a label at the current write position and
// back-patches anything that referenced it before it existed; `ref` either
// patches immediately (label already resolved) or queues the patch.
class LabelSpace {
public:
    void mark(const std::string &name, std::vector<uint8_t> &code)
    {
        size_t pos = code.size();
        resolved_[name] = pos;
        auto range = pending_.equal_range(name);
        for (auto it = range.first; it != range.second; ++it) {
            patch_rel32(code, it->second, pos);
        }
        pending_.erase(range.first, range.second);
    }

    void ref(const std::string &name, size_t operand_pos, std::vector<uint8_t> &code)
    {
        auto found = resolved_.find(name);
        if (found != resolved_.end()) {
            patch_rel32(code, operand_pos, found->second);
        } else {
            pending_.emplace(name, operand_pos);
        }
    }

private:
    std::unordered_map<std::string, size_t> resolved_;
    std::unordered_multimap<std::string, size_t> pending_;
};

struct OpEntry {
    uint8_t opcode;
    std::string label;
};

// Built from opcode_map.h's opcode_table() -- the single source of truth
// shared with OpcodeMap itself, so this dispatch-table generator and the
// per-protect randomization it uses (see the cmp_reg_imm32 call below) can
// never disagree about which opcodes exist.
std::vector<OpEntry> all_ops()
{
    std::vector<OpEntry> v;
    v.reserve(opcode_table().size());
    for (const auto &e : opcode_table()) v.push_back({static_cast<uint8_t>(e.opcode), e.label});
    return v;
}

} // namespace

std::vector<uint8_t> generate_interpreter(uint64_t native_call_rel_to_interp, std::mt19937_64 &rng,
                                           const OpcodeMap &opcode_map, size_t *prolog_size_out)
{
    std::vector<uint8_t> code;
    LabelSpace labels;

    auto J = [&]() {
        switch (std::uniform_int_distribution<int>(0, 5)(rng)) {
        case 0: emit_native_junk(code, rng); break;
        case 1: emit_native_opaque_predicate(code, rng); break;
        case 2: emit_overlap_jump(code, rng); break;
        case 3: emit_overlap_opaque(code, rng); break;
        case 4: emit_overlap_midinsn(code, rng); break;
        default: emit_junk_call(code, rng); break;
        }
    };

    // Loads karity_vm_native_call's live (ASLR-correct) address into `dst`.
    // Deliberately not ctx->anchor + delta (see interp_codegen.h): fetches
    // this interpreter's own live RIP via call_rel32_self+pop instead, so
    // the result has nothing to do with whichever site's anchor happens to
    // be live in ctx right now. No J() between the call and the pop -- the
    // pop must retrieve exactly what that call just pushed.
    auto load_native_call_addr = [&](int dst) {
        size_t pop_target_offset = call_rel32_self(code);
        pop_reg(code, dst);
        int64_t k = static_cast<int64_t>(native_call_rel_to_interp) -
                    static_cast<int64_t>(pop_target_offset);
        mov_reg_imm64(code, REG_T1, static_cast<uint64_t>(k));
        alu_reg_reg(code, AluOp::Add, dst, REG_T1);
    };

    // Decrypts an nbytes-long (1 or 8) bytecode operand that was just fetched
    // raw (ciphertext) into val_reg from *(REG_IP+0) -- XORs the keystream
    // for byte range [REG_IP, REG_IP+nbytes) directly into val_reg in place
    // (see include/karity/bytecode_crypt.h for the seekable splitmix64
    // derivation this mirrors byte-for-byte; "opcode rolling decryption",
    // look/todo.md section C). Must be called before REG_IP is advanced past
    // the bytes it just fetched -- the offset math below reads REG_IP's
    // current (not-yet-advanced) value.
    //
    // Scratch registers: RSI/RDI/R12/R13, saved with plain push/pop at the
    // start/end of every call and otherwise never touched by this file (this
    // interpreter's register assignment above only persistently occupies
    // RBX/R8/R9/R10/R11 + RCX/RDX/RSP/RAX transiently + XMM0/1) -- so this
    // can never disturb REG_CTX/REG_IP/REG_SP/REG_T0/REG_T1/val_reg. The
    // push/pop isn't optional bookkeeping: these four are Win64 *non-
    // volatile* (callee-saved) registers, exactly like RBX above -- an
    // earlier version of this lambda just clobbered them outright on the
    // (wrong) theory that "unused elsewhere in this file" was sufficient,
    // which corrupted the caller's own RSI/RDI/R12/R13/RBP the moment any
    // real caller (confirmed with a plain -O2 GCC caller, same as the RBX
    // bug above) trusted the ABI to preserve them across this call --
    // tests/karity_test_interp_codegen segfaulted deep in unrelated later
    // code, not inside the interpreter itself, which is what a corrupted
    // callee-saved register in the *caller's* frame looks like. Real RSP
    // push/pop here is unrelated to (and doesn't collide with) the vreg[RSP]
    // real-stack concerns documented elsewhere in this file/vm_thunk.S: this
    // is this interpreter's *own* native call frame doing ordinary register
    // spills, the same as any compiled function would, never anywhere near
    // an outbound VOP_CALL/CALL_IND's stack swap.
    //
    // Deliberately one full splitmix64 mix per output *byte* rather than
    // nanomite's 8-bytes-per-mix chunking -- see bytecode_crypt.h's header
    // comment for why (avoids ever needing to combine two keystream chunks
    // for an unaligned 8-byte fetch, which would need runtime-variable
    // shift/mask logic here). Not interleaved with J(): kept as one dense
    // block rather than add any interaction risk with junk insertion, even
    // though J() itself only ever clobbers RAX/RFLAGS, both fully restored
    // (see x86_junk.h) -- so calling J() around (not inside) this is safe.
    constexpr int CR_OFF = 6, CR_SEED = 7, CR_Z = 12, CR_TMP = 13; // RSI/RDI/R12/R13
    constexpr uint64_t kSplitmixInc = 0x9E3779B97F4A7C15ULL;
    constexpr uint64_t kSplitmixC1  = 0xBF58476D1CE4E5B9ULL;
    constexpr uint64_t kSplitmixC2  = 0x94D049BB133111EBULL;
    // `disp`: for the rare fetch not at [REG_IP+0] (MOVSX's dst_size, read
    // from [REG_IP+1] while src_size is still pending at [REG_IP+0] and
    // REG_IP hasn't advanced past either yet) -- folded into the offset
    // computation itself rather than requiring the caller to pre-adjust a
    // register, so every call site's val_reg/nbytes/disp mirror exactly the
    // raw fetch call (mov_reg_mem64/movzx_reg_mem8) immediately above it.
    auto decrypt_operand = [&](int val_reg, int nbytes, int32_t disp = 0) {
        push_reg(code, CR_OFF);
        push_reg(code, CR_SEED);
        push_reg(code, CR_Z);
        push_reg(code, CR_TMP);
        mov_reg_reg(code, CR_OFF, REG_IP);
        mov_reg_mem64(code, CR_TMP, REG_CTX, OFF_BYTECODE_BASE);
        alu_reg_reg(code, AluOp::Sub, CR_OFF, CR_TMP); // CR_OFF = REG_IP - bytecode_base
        if (disp != 0) alu_reg_imm32(code, AluOp::Add, CR_OFF, static_cast<uint32_t>(disp));
        mov_reg_mem64(code, CR_SEED, REG_CTX, OFF_BYTECODE_SEED);
        for (int i = 0; i < nbytes; i++) {
            // CR_Z = seed + (off+i+1)*INC
            mov_reg_reg(code, CR_Z, CR_OFF);
            alu_reg_imm32(code, AluOp::Add, CR_Z, static_cast<uint32_t>(i + 1));
            mov_reg_imm64(code, CR_TMP, kSplitmixInc);
            imul_reg_reg(code, CR_Z, CR_TMP);
            alu_reg_reg(code, AluOp::Add, CR_Z, CR_SEED);
            // splitmix64 mix: z ^= z>>30; z *= C1; z ^= z>>27; z *= C2; z ^= z>>31;
            mov_reg_reg(code, CR_TMP, CR_Z);
            shr_reg_imm8(code, CR_TMP, 30);
            alu_reg_reg(code, AluOp::Xor, CR_Z, CR_TMP);
            mov_reg_imm64(code, CR_TMP, kSplitmixC1);
            imul_reg_reg(code, CR_Z, CR_TMP);
            mov_reg_reg(code, CR_TMP, CR_Z);
            shr_reg_imm8(code, CR_TMP, 27);
            alu_reg_reg(code, AluOp::Xor, CR_Z, CR_TMP);
            mov_reg_imm64(code, CR_TMP, kSplitmixC2);
            imul_reg_reg(code, CR_Z, CR_TMP);
            mov_reg_reg(code, CR_TMP, CR_Z);
            shr_reg_imm8(code, CR_TMP, 31);
            alu_reg_reg(code, AluOp::Xor, CR_Z, CR_TMP);
            // low byte -> shift into position i*8 -> XOR into val_reg
            alu_reg_imm32(code, AluOp::And, CR_Z, 0xFF);
            if (i != 0) shl_reg_imm8(code, CR_Z, static_cast<uint8_t>(i * 8));
            alu_reg_reg(code, AluOp::Xor, val_reg, CR_Z);
        }
        pop_reg(code, CR_TMP);
        pop_reg(code, CR_Z);
        pop_reg(code, CR_SEED);
        pop_reg(code, CR_OFF);
    };

    // vstack overflow guard (see runtime/vm_thunk.S's header and isa.h's
    // vstack_limit comment): called right after REG_SP has been decremented
    // for a push, before the value is actually written to *REG_SP. REG_RDX
    // is free scratch here in every one of this lambda's call sites (never
    // holds anything live across a push handler, same as its other transient
    // uses elsewhere in this file, e.g. INC/DEC's old-CF isolation above).
    // Unsigned "below" (jb, not jl) matters: vsp/vstack_limit are addresses.
    auto guard_vstack_overflow = [&]() {
        mov_reg_mem64(code, REG_RDX, REG_CTX, OFF_VSTACK_LIMIT);
        J();
        alu_reg_reg(code, AluOp::Cmp, REG_SP, REG_RDX);
        size_t j = jb_rel32(code);
        labels.ref("vstack_overflow", j, code);
    };

    // --- prologue ------------------------------------------------------
    // SEH/exception interaction (see runtime/vm_thunk.S's header for the
    // full picture): this generated blob is injected code with no
    // RUNTIME_FUNCTION/UNWIND_INFO entry of its own, so if an exception ever
    // needs to unwind *through* it (raised somewhere inside the VOP_CALL/
    // CALL_IND handlers' outbound native call below, e.g.), Windows has to be
    // able to recover this function's true entry rsp. `push rbp` + `mov rbp,
    // rsp` right here -- before anything else, while rbp is still free (the
    // *caller's* rbp doesn't need saving the way RBX below does: nothing in
    // this file ever reads/writes it as a persistent value) -- is the same
    // one-line "capture rsp into an unused nonvolatile register before it
    // moves unpredictably" technique vm_thunk.S/vm_call.S use, needed here
    // specifically because the CALL/CALL_IND handlers' own "align + shadow
    // space" `sub rsp, 40` (further down) persists across their outbound
    // `call rdi`, so this function's rsp is *not* constant across its whole
    // body the way it used to be before this change -- a plain "no entry
    // means leaf, rsp unchanged" fallback would read garbage there. `pop
    // rbp` right before `ret` (epilogue, below) undoes it; the actual
    // RUNTIME_FUNCTION/UNWIND_INFO entry describing these two instructions
    // is built at protect time in src/native/seh_unwind.cpp, since (unlike
    // vm_thunk.S/vm_call.S) this code doesn't exist until generate_interpreter
    // runs -- prolog_size_out reports this prologue's fixed 4-byte length
    // (1 for `push rbp` + 3 for `mov rbp,rsp`, both REX/ModRM-fixed
    // encodings regardless of anything randomized elsewhere in this file) so
    // the injector doesn't have to duplicate that arithmetic.
    push_reg(code, PHYS_RBP);
    mov_reg_reg(code, PHYS_RBP, REG_RSP);
    if (prolog_size_out) *prolog_size_out = code.size();

    // RBX is Win64 callee-saved: any normal caller may be trusting the ABI
    // to keep a value alive in it across this call (GCC does exactly that
    // at -O2, which is how this was actually caught -- vm_thunk.S happens
    // not to care, since it reloads everything from ctx afterward, but a
    // plain call from ordinary code corrupts whatever the caller had). Saved
    // into ctx's own static scratch (OFF_SAVED_RBX, see above) rather than
    // pushed onto the real stack -- and note this has to happen through RCX
    // (still holding ctx, unclobbered arg0) *before* RBX is repurposed as
    // REG_CTX below, since afterwards the original value would already be
    // gone.
    mov_mem64_reg(code, REG_RCX, OFF_SAVED_RBX, REG_CTX);

    // ctx = arg0 (RCX); ip/sp = ctx->vip/vsp
    mov_reg_reg(code, REG_CTX, REG_RCX);
    J();
    mov_reg_mem64(code, REG_IP, REG_CTX, OFF_VIP);
    J();
    mov_reg_mem64(code, REG_SP, REG_CTX, OFF_VSP);

    // --- dispatch loop ------------------------------------------------------
    labels.mark("dispatch", code);
    movzx_reg_mem8(code, REG_T0, REG_IP, 0);
    decrypt_operand(REG_T0, 1);
    J();
    alu_reg_imm32(code, AluOp::Add, REG_IP, 1);

    std::vector<OpEntry> dispatch_order = all_ops();
    std::shuffle(dispatch_order.begin(), dispatch_order.end(), rng);
    for (auto &e : dispatch_order) {
        J();
        // e.opcode is the *semantic* isa.h value (also what the switch below
        // keys its codegen decisions on) -- opcode_map.encode() is what
        // translates it to the physical byte this protect run's bytecode
        // actually carries; the two are only guaranteed equal for the
        // default identity map.
        cmp_reg_imm32(code, REG_T0, opcode_map.encode(static_cast<karity_vop>(e.opcode)));
        size_t j = je_rel32(code);
        labels.ref(e.label, j, code);
    }
    J();
    {
        size_t j = jmp_rel32(code);
        labels.ref("epilogue", j, code);
    }

    // --- handlers, laid out in an independently shuffled order -------------
    std::vector<OpEntry> layout_order = all_ops();
    std::shuffle(layout_order.begin(), layout_order.end(), rng);

    for (auto &e : layout_order) {
        labels.mark(e.label, code);

        switch (e.opcode) {
        case 0x00: // NOP
            break;

        case 0x01: // VMEXIT
        {
            size_t j = jmp_rel32(code);
            labels.ref("epilogue", j, code);
            continue; // no fallthrough jmp-to-dispatch
        }

        case 0x10: // PUSH_IMM
            mov_reg_mem64(code, REG_T0, REG_IP, 0);
            decrypt_operand(REG_T0, 8);
            J();
            alu_reg_imm32(code, AluOp::Add, REG_IP, 8);
            J();
            alu_reg_imm32(code, AluOp::Sub, REG_SP, 8);
            guard_vstack_overflow();
            J();
            mov_mem64_reg(code, REG_SP, 0, REG_T0);
            break;

        case 0x11: // PUSH_VREG
            movzx_reg_mem8(code, REG_T0, REG_IP, 0);
            decrypt_operand(REG_T0, 1);
            J();
            alu_reg_imm32(code, AluOp::Add, REG_IP, 1);
            J();
            shl_reg_imm8(code, REG_T0, 3);
            J();
            alu_reg_reg(code, AluOp::Add, REG_T0, REG_CTX);
            J();
            mov_reg_mem64(code, REG_T1, REG_T0, 0);
            J();
            alu_reg_imm32(code, AluOp::Sub, REG_SP, 8);
            guard_vstack_overflow();
            J();
            mov_mem64_reg(code, REG_SP, 0, REG_T1);
            break;

        case 0x12: // POP_VREG
            movzx_reg_mem8(code, REG_T0, REG_IP, 0);
            decrypt_operand(REG_T0, 1);
            J();
            alu_reg_imm32(code, AluOp::Add, REG_IP, 1);
            J();
            shl_reg_imm8(code, REG_T0, 3);
            J();
            alu_reg_reg(code, AluOp::Add, REG_T0, REG_CTX);
            J();
            mov_reg_mem64(code, REG_T1, REG_SP, 0);
            J();
            mov_mem64_reg(code, REG_T0, 0, REG_T1);
            J();
            alu_reg_imm32(code, AluOp::Add, REG_SP, 8);
            break;

        case 0x13: // PUSH_REL
            mov_reg_mem64(code, REG_T0, REG_IP, 0);
            decrypt_operand(REG_T0, 8);
            J();
            alu_reg_imm32(code, AluOp::Add, REG_IP, 8);
            J();
            mov_reg_mem64(code, REG_T1, REG_CTX, OFF_ANCHOR);
            J();
            alu_reg_reg(code, AluOp::Add, REG_T0, REG_T1);
            J();
            alu_reg_imm32(code, AluOp::Sub, REG_SP, 8);
            guard_vstack_overflow();
            J();
            mov_mem64_reg(code, REG_SP, 0, REG_T0);
            break;

        case 0x14: // DROP
            alu_reg_imm32(code, AluOp::Add, REG_SP, 8);
            break;

        case 0x20: case 0x21: case 0x22: case 0x23: case 0x24: // ADD/SUB/XOR/AND/OR
        {
            AluOp op = e.opcode == 0x20 ? AluOp::Add
                     : e.opcode == 0x21 ? AluOp::Sub
                     : e.opcode == 0x22 ? AluOp::Xor
                     : e.opcode == 0x23 ? AluOp::And
                                        : AluOp::Or;
            mov_reg_mem64(code, REG_T0, REG_SP, 0);
            J();
            alu_reg_imm32(code, AluOp::Add, REG_SP, 8);
            J();
            alu_mem64_reg(code, op, REG_SP, 0, REG_T0);
            // Capture real hardware RFLAGS immediately -- vflags' bit layout
            // is deliberately identical to native RFLAGS (see isa.h), so no
            // translation is needed. Must happen before any junk (J()) runs,
            // since junk code is free to clobber real flags.
            pushfq(code);
            pop_reg(code, REG_T1);
            mov_mem64_reg(code, REG_CTX, OFF_VFLAGS, REG_T1);
            break;
        }

        case 0x25: // CMP: pop b, pop a, set vflags from a-b, push nothing
        {
            mov_reg_mem64(code, REG_T0, REG_SP, 0); // T0 = b
            J();
            alu_reg_imm32(code, AluOp::Add, REG_SP, 8); // pop b; sp now -> a
            J();
            alu_mem64_reg(code, AluOp::Cmp, REG_SP, 0, REG_T0); // flags = a - b, no writeback
            pushfq(code);
            pop_reg(code, REG_T1);
            mov_mem64_reg(code, REG_CTX, OFF_VFLAGS, REG_T1);
            J();
            alu_reg_imm32(code, AluOp::Add, REG_SP, 8); // pop a too (nothing pushed back)
            break;
        }

        case 0x26: // TEST: pop b, pop a, set vflags from a&b, push nothing
        {
            mov_reg_mem64(code, REG_T0, REG_SP, 0); // T0 = b
            J();
            alu_reg_imm32(code, AluOp::Add, REG_SP, 8); // pop b; sp now -> a
            J();
            test_mem64_reg(code, REG_SP, 0, REG_T0); // flags = a & b, no writeback
            pushfq(code);
            pop_reg(code, REG_T1);
            mov_mem64_reg(code, REG_CTX, OFF_VFLAGS, REG_T1);
            J();
            alu_reg_imm32(code, AluOp::Add, REG_SP, 8); // pop a too (nothing pushed back)
            break;
        }

        case 0x27: // NEG: in-place (pop a, push -a); vflags = as-if `0 - a`
        {
            mov_reg_mem64(code, REG_T0, REG_SP, 0); // T0 = a
            J();
            neg_reg(code, REG_T0); // T0 = -a; sets real hardware flags exactly
            // like native NEG (equivalent to a 0-operand SUB) -- must capture
            // before any junk (J()) gets a chance to clobber real flags.
            pushfq(code);
            pop_reg(code, REG_T1);
            mov_mem64_reg(code, REG_CTX, OFF_VFLAGS, REG_T1);
            J();
            mov_mem64_reg(code, REG_SP, 0, REG_T0);
            break;
        }

        case 0x29: // NOT: in-place (pop a, push ~a); never touches vflags
        {
            mov_reg_mem64(code, REG_T0, REG_SP, 0);
            J();
            not_reg(code, REG_T0);
            J();
            mov_mem64_reg(code, REG_SP, 0, REG_T0);
            break;
        }

        case 0x2A: // INC: in-place (pop a, push a+1). Real hardware INC
                   // itself never touches CF, but pushfq captures whatever
                   // CF happened to already be lying around in the real
                   // CPU flags (unrelated interpreter-internal ALU ops),
                   // not ctx->vflags' own CF bit -- so unlike ADD/SUB/NEG,
                   // this can't just store the captured flags verbatim; CF
                   // has to be explicitly carried over from the old
                   // ctx->vflags instead.
        case 0x2B: // DEC: same contract, a-1
        {
            mov_reg_mem64(code, REG_T0, REG_SP, 0);
            J();
            if (e.opcode == 0x2A) inc_reg(code, REG_T0); else dec_reg(code, REG_T0);
            pushfq(code);
            pop_reg(code, REG_T1); // T1 = real flags after inc/dec (OF/SF/ZF/PF correct, CF garbage)
            J();
            mov_reg_mem64(code, REG_RCX, REG_CTX, OFF_VFLAGS); // RCX = old vflags
            alu_reg_imm32(code, AluOp::And, REG_RCX, KARITY_FLAG_CF); // RCX = old CF bit only
            alu_reg_imm32(code, AluOp::And, REG_T1, 0xFFFFFFFEu);     // T1 = captured flags, CF bit cleared
            alu_reg_reg(code, AluOp::Or, REG_T1, REG_RCX);            // T1 = captured (sans CF) | old CF
            mov_mem64_reg(code, REG_CTX, OFF_VFLAGS, REG_T1);
            J();
            mov_mem64_reg(code, REG_SP, 0, REG_T0);
            break;
        }

        case 0x2D: // SHL
        case 0x2E: // SHR
        case 0x2F: // SAR: pop count, pop a, push result. Real x86 shift-by-
                   // CL only reads CL's low 6 bits (auto-masked in hardware
                   // for a 64-bit operand), so the whole popped count can
                   // go straight into RCX. count==0 (after masking) must
                   // skip the real instruction *and* the flags capture
                   // entirely -- native hardware leaves both the value and
                   // every flag bit untouched in that case, and pushfq
                   // would otherwise grab whatever real CPU flags happen
                   // to be lying around from unrelated interpreter-internal
                   // ops, not ctx->vflags.
        {
            mov_reg_mem64(code, REG_RCX, REG_SP, 0); // count
            J();
            alu_reg_imm32(code, AluOp::Add, REG_SP, 8);
            J();
            mov_reg_mem64(code, REG_T0, REG_SP, 0); // a (peek, still on top)
            J();
            mov_reg_reg(code, REG_T1, REG_RCX);
            alu_reg_imm32(code, AluOp::And, REG_T1, 63); // T1 = masked count, just to test
            test_reg_reg(code, REG_T1, REG_T1);
            {
                std::string skip_label = e.label + std::string("_skip");
                size_t j = je_rel32(code);
                labels.ref(skip_label, j, code);
                J();
                if (e.opcode == 0x2D) shl_reg_cl(code, REG_T0);
                else if (e.opcode == 0x2E) shr_reg_cl(code, REG_T0);
                else sar_reg_cl(code, REG_T0);
                pushfq(code);
                pop_reg(code, REG_T1);
                mov_mem64_reg(code, REG_CTX, OFF_VFLAGS, REG_T1);
                J();
                labels.mark(skip_label, code);
            }
            mov_mem64_reg(code, REG_SP, 0, REG_T0);
            break;
        }

        case 0x38: // ROL
        case 0x3A: // ROR: same count/skip-when-zero shape as SHL/SHR/SAR
                   // above, but real ROL/ROR never touch SF/ZF/PF at all
                   // (only CF, and OF for count==1) -- so unlike those,
                   // this can't store the captured flags verbatim even
                   // when count != 0; SF/ZF/PF have to be carried over from
                   // the old ctx->vflags the same way INC/DEC carries CF.
        {
            mov_reg_mem64(code, REG_RCX, REG_SP, 0); // count
            J();
            alu_reg_imm32(code, AluOp::Add, REG_SP, 8);
            J();
            mov_reg_mem64(code, REG_T0, REG_SP, 0); // a (peek, still on top)
            J();
            mov_reg_reg(code, REG_T1, REG_RCX);
            alu_reg_imm32(code, AluOp::And, REG_T1, 63);
            test_reg_reg(code, REG_T1, REG_T1);
            {
                std::string skip_label = e.label + std::string("_skip");
                size_t j = je_rel32(code);
                labels.ref(skip_label, j, code);
                J();
                if (e.opcode == 0x38) rol_reg_cl(code, REG_T0); else ror_reg_cl(code, REG_T0);
                pushfq(code);
                pop_reg(code, REG_T1); // T1 = real flags (CF/OF meaningful; SF/ZF/PF are real-CPU garbage)
                J();
                mov_reg_mem64(code, REG_RDX, REG_CTX, OFF_VFLAGS); // RDX = old vflags
                alu_reg_imm32(code, AluOp::And, REG_RDX,
                               static_cast<uint32_t>(~(KARITY_FLAG_CF | KARITY_FLAG_OF))); // keep all but CF/OF
                alu_reg_imm32(code, AluOp::And, REG_T1,
                               static_cast<uint32_t>(KARITY_FLAG_CF | KARITY_FLAG_OF)); // isolate new CF/OF
                alu_reg_reg(code, AluOp::Or, REG_T1, REG_RDX);
                mov_mem64_reg(code, REG_CTX, OFF_VFLAGS, REG_T1);
                J();
                labels.mark(skip_label, code);
            }
            mov_mem64_reg(code, REG_SP, 0, REG_T0);
            break;
        }

        case 0x3C: // MUL: pop b, implicit a = vreg[RAX]; RDX:RAX = a*b
                   // (unsigned). Real hardware MUL already computes CF/OF
                   // exactly per isa.h's contract, so pushfq's capture can
                   // be stored back verbatim (masked to CF/OF only, same
                   // as every other flag-partial op here) -- no manual
                   // overflow arithmetic needed, unlike the C reference
                   // implementation (runtime/vm_interp.c), which has no
                   // hardware MUL to just execute.
        case 0x3D: // IMUL1: same shape, signed (native `imul r/m64`)
        {
            mov_reg_mem64(code, REG_T0, REG_SP, 0); // T0 = b
            J();
            alu_reg_imm32(code, AluOp::Add, REG_SP, 8); // pop b
            J();
            mov_reg_mem64(code, PHYS_RAX, REG_CTX, OFF_VREG_RAX); // physical RAX = vreg[RAX]
            if (e.opcode == 0x3C) mul_reg(code, REG_T0); else imul_reg(code, REG_T0);
            pushfq(code);
            pop_reg(code, REG_T1); // T1 = real flags (CF/OF meaningful; others real-CPU garbage)
            J();
            mov_mem64_reg(code, REG_CTX, OFF_VREG_RAX, PHYS_RAX); // store low64 back
            J();
            mov_mem64_reg(code, REG_CTX, OFF_VREG_RDX, PHYS_RDX); // store high64 back
            J();
            mov_reg_mem64(code, REG_RCX, REG_CTX, OFF_VFLAGS); // RCX = old vflags
            alu_reg_imm32(code, AluOp::And, REG_RCX, static_cast<uint32_t>(~(KARITY_FLAG_CF | KARITY_FLAG_OF)));
            alu_reg_imm32(code, AluOp::And, REG_T1, static_cast<uint32_t>(KARITY_FLAG_CF | KARITY_FLAG_OF));
            alu_reg_reg(code, AluOp::Or, REG_T1, REG_RCX);
            mov_mem64_reg(code, REG_CTX, OFF_VFLAGS, REG_T1);
            break;
        }

        case 0x3F: // IMUL2: pop b, pop a, push low64(a*b) (native `imul
                   // r64,r/m64` / `imul r64,r/m64,imm32`). Never touches
                   // vreg[RAX]/vreg[RDX] -- unlike MUL/IMUL1, the
                   // destination is whichever vreg the lifter already
                   // arranged to pop into.
        {
            mov_reg_mem64(code, REG_T0, REG_SP, 0); // T0 = b
            J();
            alu_reg_imm32(code, AluOp::Add, REG_SP, 8); // pop b; sp -> a
            J();
            mov_reg_mem64(code, REG_T1, REG_SP, 0); // T1 = a (peek, still on top)
            J();
            imul_reg_reg(code, REG_T1, REG_T0); // T1 = a*b (low64); CF/OF set by real hardware
            pushfq(code);
            pop_reg(code, REG_RCX); // RCX = real flags (CF/OF meaningful)
            J();
            mov_reg_mem64(code, REG_RDX, REG_CTX, OFF_VFLAGS); // RDX = old vflags
            alu_reg_imm32(code, AluOp::And, REG_RDX, static_cast<uint32_t>(~(KARITY_FLAG_CF | KARITY_FLAG_OF)));
            alu_reg_imm32(code, AluOp::And, REG_RCX, static_cast<uint32_t>(KARITY_FLAG_CF | KARITY_FLAG_OF));
            alu_reg_reg(code, AluOp::Or, REG_RCX, REG_RDX);
            mov_mem64_reg(code, REG_CTX, OFF_VFLAGS, REG_RCX);
            J();
            mov_mem64_reg(code, REG_SP, 0, REG_T1); // store result in place of 'a'
            break;
        }

        case 0x48: // DIV: pop b (divisor), implicit dividend =
                   // vreg[RDX]:vreg[RAX]; vreg[RAX]=quotient,
                   // vreg[RDX]=remainder (native `div r/m64`). No flags --
                   // native DIV's are all explicitly undefined, so
                   // ctx->vflags is never touched here. Divisor==0 or an
                   // overflowing quotient raises a genuine hardware #DE
                   // (SIGFPE) from the `div`/`idiv` instruction below,
                   // exactly like the same unprotected code would -- see
                   // isa.h for how this differs from the C reference
                   // interpreter's software fallback.
        case 0x49: // IDIV: same shape, signed (native `idiv r/m64`)
        {
            mov_reg_mem64(code, REG_T0, REG_SP, 0); // T0 = divisor
            J();
            alu_reg_imm32(code, AluOp::Add, REG_SP, 8); // pop
            J();
            mov_reg_mem64(code, PHYS_RAX, REG_CTX, OFF_VREG_RAX);
            J();
            mov_reg_mem64(code, PHYS_RDX, REG_CTX, OFF_VREG_RDX);
            if (e.opcode == 0x48) div_reg(code, REG_T0); else idiv_reg(code, REG_T0);
            J();
            mov_mem64_reg(code, REG_CTX, OFF_VREG_RAX, PHYS_RAX);
            J();
            mov_mem64_reg(code, REG_CTX, OFF_VREG_RDX, PHYS_RDX);
            break;
        }

        case 0x30: // LOAD8
            mov_reg_mem64(code, REG_T0, REG_SP, 0);
            J();
            movzx_reg_mem8(code, REG_T1, REG_T0, 0);
            J();
            mov_mem64_reg(code, REG_SP, 0, REG_T1);
            break;
        case 0x31: // LOAD16
            mov_reg_mem64(code, REG_T0, REG_SP, 0);
            J();
            movzx_reg_mem16(code, REG_T1, REG_T0, 0);
            J();
            mov_mem64_reg(code, REG_SP, 0, REG_T1);
            break;
        case 0x32: // LOAD32
            mov_reg_mem64(code, REG_T0, REG_SP, 0);
            J();
            mov_reg_mem32(code, REG_T1, REG_T0, 0); // implicit zero-extend
            J();
            mov_mem64_reg(code, REG_SP, 0, REG_T1);
            break;
        case 0x33: // LOAD64
            mov_reg_mem64(code, REG_T0, REG_SP, 0);
            J();
            mov_reg_mem64(code, REG_T1, REG_T0, 0);
            J();
            mov_mem64_reg(code, REG_SP, 0, REG_T1);
            break;

        case 0x34: // STORE8
            mov_reg_mem64(code, REG_T0, REG_SP, 0);
            J();
            alu_reg_imm32(code, AluOp::Add, REG_SP, 8);
            J();
            mov_reg_mem64(code, REG_T1, REG_SP, 0);
            J();
            alu_reg_imm32(code, AluOp::Add, REG_SP, 8);
            J();
            mov_mem8_reg(code, REG_T1, 0, REG_T0);
            break;
        case 0x35: // STORE16
            mov_reg_mem64(code, REG_T0, REG_SP, 0);
            J();
            alu_reg_imm32(code, AluOp::Add, REG_SP, 8);
            J();
            mov_reg_mem64(code, REG_T1, REG_SP, 0);
            J();
            alu_reg_imm32(code, AluOp::Add, REG_SP, 8);
            J();
            mov_mem16_reg(code, REG_T1, 0, REG_T0);
            break;
        case 0x36: // STORE32
            mov_reg_mem64(code, REG_T0, REG_SP, 0);
            J();
            alu_reg_imm32(code, AluOp::Add, REG_SP, 8);
            J();
            mov_reg_mem64(code, REG_T1, REG_SP, 0);
            J();
            alu_reg_imm32(code, AluOp::Add, REG_SP, 8);
            J();
            mov_mem32_reg(code, REG_T1, 0, REG_T0);
            break;
        case 0x37: // STORE64
            mov_reg_mem64(code, REG_T0, REG_SP, 0);
            J();
            alu_reg_imm32(code, AluOp::Add, REG_SP, 8);
            J();
            mov_reg_mem64(code, REG_T1, REG_SP, 0);
            J();
            alu_reg_imm32(code, AluOp::Add, REG_SP, 8);
            J();
            mov_mem64_reg(code, REG_T1, 0, REG_T0);
            break;

        case 0x40: // CALL
            mov_reg_mem64(code, REG_T0, REG_IP, 0); // delta
            decrypt_operand(REG_T0, 8);
            J();
            alu_reg_imm32(code, AluOp::Add, REG_IP, 8);
            J();
            mov_mem64_reg(code, REG_CTX, OFF_VIP, REG_IP); // flush ip/sp: the
            J();                                            // callee (or
            mov_mem64_reg(code, REG_CTX, OFF_VSP, REG_SP);  // something it
            J();                                            // calls) may be
            mov_reg_mem64(code, REG_T1, REG_CTX, OFF_ANCHOR); // virtualized
            J();                                              // and re-enter
            alu_reg_reg(code, AluOp::Add, REG_T1, REG_T0);     // through
            J();                                               // vm_thunk
            mov_reg_reg(code, REG_RCX, REG_CTX);
            J();
            mov_reg_reg(code, REG_RDX, REG_T1);
            J();
            // Real EFLAGS get saved/restored around this handler's own
            // "sub rsp,40" (align + shadow space, for calling
            // karity_vm_native_call itself) -- that sub sets flags from
            // the *interpreter's own* rsp arithmetic, nothing to do with
            // the bytecode program's state, and nothing between it and the
            // outbound `call rdi` inside karity_vm_native_call (a run of
            // push/mov instructions, none of which touch flags) would
            // naturally overwrite it -- so without this, the callee (an
            // arbitrary native function, e.g. a real WinAPI/CRT call) would
            // see VM-internal noise in CF/PF/AF/etc. instead of whatever
            // the emulated program's own last flag-producing instruction
            // actually left, an ABI-observable difference from the
            // unvirtualized program even though ordinary calling
            // conventions don't guarantee any particular incoming flags.
            // Round-tripped through ctx->interp_call_flags (OFF_CALL_FLAGS),
            // not the stack directly: `sub rsp,40` sits *between* the save
            // and restore, so a naive pushfq/.../popfq pair would have the
            // restore read from 40+8 bytes below where the save actually
            // wrote -- garbage, not the saved flags (caught this exact
            // mistake the same way as OFF_SAVED_RBX: an intermittent-then-
            // 100%-reproducible tests/karity_test_interp_codegen segfault).
            pushfq(code);
            pop_reg(code, REG_T1); // T1 = real flags (free again: delta already moved to RDX)
            mov_mem64_reg(code, REG_CTX, OFF_CALL_FLAGS, REG_T1);
            J();
            alu_reg_imm32(code, AluOp::Sub, REG_RSP, 40); // align + shadow space
            J();
            load_native_call_addr(REG_T0); // clobbers T1 internally -- already saved above
            mov_reg_mem64(code, REG_T1, REG_CTX, OFF_CALL_FLAGS);
            push_reg(code, REG_T1);
            popfq(code); // restore before the outbound call, not after -- push_reg/popfq
                         // here are adjacent on purpose, nothing else may move rsp between them
            call_reg(code, REG_T0);
            J();
            alu_reg_imm32(code, AluOp::Add, REG_RSP, 40);
            J();
            mov_reg_mem64(code, REG_IP, REG_CTX, OFF_VIP); // reload: the call
            J();                                            // may have
            mov_reg_mem64(code, REG_SP, REG_CTX, OFF_VSP);  // clobbered r8-r11
            break;

        case 0x45: // CALL_IND: same native-call passthrough as CALL, but the
                   // target is a runtime value popped off the vstack instead
                   // of a lift-time anchor+delta.
            mov_reg_mem64(code, REG_T1, REG_SP, 0); // target
            J();
            alu_reg_imm32(code, AluOp::Add, REG_SP, 8); // pop
            J();
            mov_mem64_reg(code, REG_CTX, OFF_VIP, REG_IP); // flush ip/sp: see
            J();                                            // VOP_CALL's
            mov_mem64_reg(code, REG_CTX, OFF_VSP, REG_SP);  // comment
            J();
            mov_reg_reg(code, REG_RCX, REG_CTX);
            J();
            mov_reg_reg(code, REG_RDX, REG_T1);
            J();
            pushfq(code); // save real flags via ctx -- see VOP_CALL's comment
            pop_reg(code, REG_T1);
            mov_mem64_reg(code, REG_CTX, OFF_CALL_FLAGS, REG_T1);
            J();
            alu_reg_imm32(code, AluOp::Sub, REG_RSP, 40); // align + shadow space
            J();
            load_native_call_addr(REG_T0); // see VOP_CALL's comment
            mov_reg_mem64(code, REG_T1, REG_CTX, OFF_CALL_FLAGS);
            push_reg(code, REG_T1);
            popfq(code); // restore before the outbound call, not after
            call_reg(code, REG_T0);
            J();
            alu_reg_imm32(code, AluOp::Add, REG_RSP, 40);
            J();
            mov_reg_mem64(code, REG_IP, REG_CTX, OFF_VIP); // reload: the call
            J();                                            // may have
            mov_reg_mem64(code, REG_SP, REG_CTX, OFF_VSP);  // clobbered r8-r11
            break;

        case 0x46: // VMEXIT_REL: i64 delta operand -> ctx->exit_target =
                   // ctx->anchor + delta, then exit (same epilogue path as
                   // plain VMEXIT, just with an explicit target instead of
                   // relying on whatever vm_thunk.S pre-filled exit_target
                   // with).
        {
            mov_reg_mem64(code, REG_T0, REG_IP, 0); // delta
            decrypt_operand(REG_T0, 8);
            J();
            alu_reg_imm32(code, AluOp::Add, REG_IP, 8);
            J();
            mov_reg_mem64(code, REG_T1, REG_CTX, OFF_ANCHOR);
            J();
            alu_reg_reg(code, AluOp::Add, REG_T0, REG_T1);
            J();
            mov_mem64_reg(code, REG_CTX, OFF_EXIT_TARGET, REG_T0);
            J();
            size_t j = jmp_rel32(code);
            labels.ref("epilogue", j, code);
            continue; // no fallthrough jmp-to-dispatch
        }

        case 0x41: // JMP
            mov_reg_mem64(code, REG_T0, REG_IP, 0);
            decrypt_operand(REG_T0, 8);
            J();
            alu_reg_imm32(code, AluOp::Add, REG_IP, 8);
            J();
            alu_reg_reg(code, AluOp::Add, REG_IP, REG_T0);
            break;

        case 0x42: // JCC_NZ
        {
            mov_reg_mem64(code, REG_T0, REG_SP, 0); // cond
            J();
            alu_reg_imm32(code, AluOp::Add, REG_SP, 8);
            J();
            mov_reg_mem64(code, REG_T1, REG_IP, 0); // rel
            decrypt_operand(REG_T1, 8);
            J();
            alu_reg_imm32(code, AluOp::Add, REG_IP, 8);
            test_reg_reg(code, REG_T0, REG_T0);
            size_t j = jne_rel32(code);
            labels.ref("jcc_taken", j, code);
            J();
            {
                size_t jd = jmp_rel32(code);
                labels.ref("dispatch", jd, code);
            }
            labels.mark("jcc_taken", code);
            alu_reg_reg(code, AluOp::Add, REG_IP, REG_T1);
            break;
        }

        case 0x43: // JCC: u8 cc + i64 rel; branch if ctx->vflags satisfies cc
        {
            // The 16 x86 condition codes pair up as (cc, cc^1) exact logical
            // negations of each other, and split into 8 distinct underlying
            // boolean tests keyed by cc>>1: O, B, E, BE, S, P, L, LE (odd cc
            // is the same test, negated). So: dispatch on cc>>1 to compute
            // the *positive* group boolean into T0, then XOR with cc&1
            // (reloaded fresh from the bytecode -- cheaper than keeping it
            // alive in a register across the whole group dispatch).
            movzx_reg_mem8(code, REG_T0, REG_IP, 0); // T0 = cc
            decrypt_operand(REG_T0, 1);
            push_reg(code, REG_T0); // stash the decrypted cc byte on the real stack --
                                     // T0 gets reused as scratch all through the flag-
                                     // group dispatch below, so it can't survive there on
                                     // its own; popped back at jcc_flags_apply below,
                                     // the single convergence point every group-dispatch
                                     // path jumps to, so the stack stays balanced no
                                     // matter which path is taken (no push/pop/call
                                     // anywhere else in between)
            J();
            alu_reg_imm32(code, AluOp::Add, REG_IP, 1);
            J();
            mov_reg_mem64(code, REG_T1, REG_IP, 0); // T1 = rel (persists to the end)
            decrypt_operand(REG_T1, 8);
            J();
            alu_reg_imm32(code, AluOp::Add, REG_IP, 8);
            J();
            shr_reg_imm8(code, REG_T0, 1); // T0 = cc >> 1 (group index 0..7)

            for (int g = 0; g < 8; g++) {
                J();
                cmp_reg_imm32(code, REG_T0, static_cast<uint32_t>(g));
                size_t j = je_rel32(code);
                labels.ref("jcc_grp" + std::to_string(g), j, code);
            }
            J();
            { // unreachable for well-formed bytecode (cc is always 0..15)
                size_t j = jmp_rel32(code);
                labels.ref("jcc_flags_apply", j, code);
            }

            // Group 0 (O / NO): OF
            labels.mark("jcc_grp0", code);
            mov_reg_mem64(code, REG_T0, REG_CTX, OFF_VFLAGS);
            shr_reg_imm8(code, REG_T0, 11);
            alu_reg_imm32(code, AluOp::And, REG_T0, 1);
            { size_t j = jmp_rel32(code); labels.ref("jcc_flags_apply", j, code); }

            // Group 1 (B / AE): CF (bit 0, no shift needed)
            labels.mark("jcc_grp1", code);
            mov_reg_mem64(code, REG_T0, REG_CTX, OFF_VFLAGS);
            alu_reg_imm32(code, AluOp::And, REG_T0, 1);
            { size_t j = jmp_rel32(code); labels.ref("jcc_flags_apply", j, code); }

            // Group 2 (E / NE): ZF
            labels.mark("jcc_grp2", code);
            mov_reg_mem64(code, REG_T0, REG_CTX, OFF_VFLAGS);
            shr_reg_imm8(code, REG_T0, 6);
            alu_reg_imm32(code, AluOp::And, REG_T0, 1);
            { size_t j = jmp_rel32(code); labels.ref("jcc_flags_apply", j, code); }

            // Group 3 (BE / A): CF | ZF
            labels.mark("jcc_grp3", code);
            mov_reg_mem64(code, REG_RDX, REG_CTX, OFF_VFLAGS);
            mov_reg_reg(code, REG_T0, REG_RDX);
            alu_reg_imm32(code, AluOp::And, REG_T0, 1); // T0 = CF
            mov_reg_reg(code, REG_RCX, REG_RDX);
            shr_reg_imm8(code, REG_RCX, 6);
            alu_reg_imm32(code, AluOp::And, REG_RCX, 1); // RCX = ZF
            alu_reg_reg(code, AluOp::Or, REG_T0, REG_RCX);
            { size_t j = jmp_rel32(code); labels.ref("jcc_flags_apply", j, code); }

            // Group 4 (S / NS): SF
            labels.mark("jcc_grp4", code);
            mov_reg_mem64(code, REG_T0, REG_CTX, OFF_VFLAGS);
            shr_reg_imm8(code, REG_T0, 7);
            alu_reg_imm32(code, AluOp::And, REG_T0, 1);
            { size_t j = jmp_rel32(code); labels.ref("jcc_flags_apply", j, code); }

            // Group 5 (P / NP): PF
            labels.mark("jcc_grp5", code);
            mov_reg_mem64(code, REG_T0, REG_CTX, OFF_VFLAGS);
            shr_reg_imm8(code, REG_T0, 2);
            alu_reg_imm32(code, AluOp::And, REG_T0, 1);
            { size_t j = jmp_rel32(code); labels.ref("jcc_flags_apply", j, code); }

            // Group 6 (L / GE): SF ^ OF
            labels.mark("jcc_grp6", code);
            mov_reg_mem64(code, REG_RDX, REG_CTX, OFF_VFLAGS);
            mov_reg_reg(code, REG_T0, REG_RDX);
            shr_reg_imm8(code, REG_T0, 7);
            alu_reg_imm32(code, AluOp::And, REG_T0, 1); // T0 = SF
            mov_reg_reg(code, REG_RCX, REG_RDX);
            shr_reg_imm8(code, REG_RCX, 11);
            alu_reg_imm32(code, AluOp::And, REG_RCX, 1); // RCX = OF
            alu_reg_reg(code, AluOp::Xor, REG_T0, REG_RCX);
            { size_t j = jmp_rel32(code); labels.ref("jcc_flags_apply", j, code); }

            // Group 7 (LE / G): ZF | (SF ^ OF)
            labels.mark("jcc_grp7", code);
            mov_reg_mem64(code, REG_RDX, REG_CTX, OFF_VFLAGS);
            mov_reg_reg(code, REG_T0, REG_RDX);
            shr_reg_imm8(code, REG_T0, 6);
            alu_reg_imm32(code, AluOp::And, REG_T0, 1); // T0 = ZF
            mov_reg_reg(code, REG_RCX, REG_RDX);
            shr_reg_imm8(code, REG_RCX, 7);
            alu_reg_imm32(code, AluOp::And, REG_RCX, 1); // RCX = SF
            shr_reg_imm8(code, REG_RDX, 11);
            alu_reg_imm32(code, AluOp::And, REG_RDX, 1); // RDX = OF
            alu_reg_reg(code, AluOp::Xor, REG_RCX, REG_RDX); // RCX = SF ^ OF
            alu_reg_reg(code, AluOp::Or, REG_T0, REG_RCX);
            // falls through to jcc_flags_apply

            labels.mark("jcc_flags_apply", code);
            pop_reg(code, REG_RCX); // RCX = decrypted cc, popped back from the stash above
                                     // (no raw memory reread needed anymore -- that
                                     // memory holds ciphertext, not cc)
            alu_reg_imm32(code, AluOp::And, REG_RCX, 1); // RCX = parity bit (1 = negated condition)
            alu_reg_reg(code, AluOp::Xor, REG_T0, REG_RCX); // T0 = final taken boolean
            J();
            test_reg_reg(code, REG_T0, REG_T0);
            {
                size_t j = jne_rel32(code);
                labels.ref("jcc_flags_taken", j, code);
            }
            J();
            {
                size_t jd = jmp_rel32(code);
                labels.ref("dispatch", jd, code);
            }
            labels.mark("jcc_flags_taken", code);
            alu_reg_reg(code, AluOp::Add, REG_IP, REG_T1);
            break;
        }

        case 0x4A: // MOVZX: u8 src_size operand (1=byte,2=word); in-place on
                   // top-of-stack. Dst-width-independent (see isa.h), so
                   // there's no separate dst_size to read. Never touches
                   // vflags (matches native MOVZX). src_size is itself a
                   // bytecode-supplied runtime value (not known when this
                   // interpreter is generated), so the mask can't be
                   // hardcoded -- instead this computes shift = 64 -
                   // src_size*8 at runtime and does shl-by-CL then
                   // logical-shr-by-CL, which zero-extends whatever the low
                   // src_size bytes are exactly like a lookup-table mask
                   // would, without needing one.
        {
            movzx_reg_mem8(code, REG_T0, REG_IP, 0); // T0 = src_size
            decrypt_operand(REG_T0, 1);
            J();
            alu_reg_imm32(code, AluOp::Add, REG_IP, 1);
            J();
            mov_reg_reg(code, REG_RCX, REG_T0);
            shl_reg_imm8(code, REG_RCX, 3); // RCX = src_size*8
            J();
            mov_reg_imm32(code, REG_T1, 64);
            alu_reg_reg(code, AluOp::Sub, REG_T1, REG_RCX); // T1 = 64 - src_size*8
            J();
            mov_reg_reg(code, REG_RCX, REG_T1); // RCX = shift amount
            J();
            mov_reg_mem64(code, REG_T0, REG_SP, 0); // T0 = a (peek, still on top)
            J();
            shl_reg_cl(code, REG_T0);
            J();
            shr_reg_cl(code, REG_T0); // logical: zero-fills the vacated high bits
            J();
            mov_mem64_reg(code, REG_SP, 0, REG_T0);
            break;
        }

        case 0x4C: // MOVSX/MOVSXD: u8 src_size (1/2/4) + u8 dst_size (4 or 8)
                   // operands; in-place on top-of-stack. Same runtime
                   // shift-by-CL trick as MOVZX above, but arithmetic
                   // (sign-replicating) instead of logical, so it always
                   // produces the full 64-bit sign extension first; if
                   // dst_size == 4, an extra mask truncates that down to 32
                   // bits afterward -- see isa.h for why that's NOT the same
                   // value as skipping the truncation. Never touches vflags
                   // (matches native MOVSX/MOVSXD).
        {
            movzx_reg_mem8(code, REG_T0, REG_IP, 0); // T0 = src_size
            decrypt_operand(REG_T0, 1);
            J();
            movzx_reg_mem8(code, REG_T1, REG_IP, 1); // T1 = dst_size
            decrypt_operand(REG_T1, 1, 1); // disp=1: this byte is [REG_IP+1], REG_IP hasn't advanced yet
            J();
            alu_reg_imm32(code, AluOp::Add, REG_IP, 2);
            J();
            mov_reg_reg(code, REG_RCX, REG_T0);
            shl_reg_imm8(code, REG_RCX, 3); // RCX = src_size*8
            J();
            mov_reg_reg(code, REG_RDX, REG_T1); // stash dst_size across the T0/T1 reuse below
            J();
            mov_reg_imm32(code, REG_T0, 64);
            alu_reg_reg(code, AluOp::Sub, REG_T0, REG_RCX); // T0 = 64 - src_size*8
            J();
            mov_reg_reg(code, REG_RCX, REG_T0); // RCX = shift amount
            J();
            mov_reg_mem64(code, REG_T0, REG_SP, 0); // T0 = a (peek, still on top)
            J();
            shl_reg_cl(code, REG_T0);
            J();
            sar_reg_cl(code, REG_T0); // arithmetic: sign-extends to a full 64 bits
            J();
            cmp_reg_imm32(code, REG_RDX, 4);
            {
                std::string skip_label = e.label + std::string("_skip_mask");
                size_t j = jne_rel32(code);
                labels.ref(skip_label, j, code);
                J();
                mov_reg_imm32(code, REG_T1, 0xFFFFFFFFu); // zero-extends to 64 (mov_reg_imm32's own contract)
                alu_reg_reg(code, AluOp::And, REG_T0, REG_T1);
                J();
                labels.mark(skip_label, code);
            }
            mov_mem64_reg(code, REG_SP, 0, REG_T0);
            break;
        }

        case 0x50: // PUSH_XREG: u8 idx operand -> vstack. idx*8 is computed
                   // into a scratch GPR and added to ctx + OFF_XREG_SCRATCH
                   // (see above), exactly the same "index times element
                   // size, plus base" shape as PUSH_VREG's own REG_CTX-
                   // relative addressing just above -- these xreg slots are
                   // plain memory, not real hardware XMM registers, so no
                   // SSE instruction is involved here at all.
        {
            movzx_reg_mem8(code, REG_T0, REG_IP, 0); // T0 = idx
            decrypt_operand(REG_T0, 1);
            J();
            alu_reg_imm32(code, AluOp::Add, REG_IP, 1);
            J();
            shl_reg_imm8(code, REG_T0, 3); // T0 = idx*8
            J();
            alu_reg_imm32(code, AluOp::Add, REG_T0, OFF_XREG_SCRATCH); // T0 = idx*8 + scratch offset
            J();
            alu_reg_reg(code, AluOp::Add, REG_T0, REG_CTX); // T0 = &xreg_scratch[idx]
            J();
            mov_reg_mem64(code, REG_T1, REG_T0, 0); // T1 = xreg_scratch[idx]
            J();
            alu_reg_imm32(code, AluOp::Sub, REG_SP, 8);
            guard_vstack_overflow();
            J();
            mov_mem64_reg(code, REG_SP, 0, REG_T1);
            break;
        }

        case 0x51: // POP_XREG: same addressing as PUSH_XREG, opposite direction
        {
            movzx_reg_mem8(code, REG_T0, REG_IP, 0); // T0 = idx
            decrypt_operand(REG_T0, 1);
            J();
            alu_reg_imm32(code, AluOp::Add, REG_IP, 1);
            J();
            shl_reg_imm8(code, REG_T0, 3);
            J();
            alu_reg_imm32(code, AluOp::Add, REG_T0, OFF_XREG_SCRATCH); // T0 = idx*8 + scratch offset
            J();
            alu_reg_reg(code, AluOp::Add, REG_T0, REG_CTX); // T0 = &xreg_scratch[idx]
            J();
            mov_reg_mem64(code, REG_T1, REG_SP, 0); // T1 = popped value
            J();
            mov_mem64_reg(code, REG_T0, 0, REG_T1); // xreg_scratch[idx] = T1
            J();
            alu_reg_imm32(code, AluOp::Add, REG_SP, 8);
            break;
        }

        case 0x52: case 0x53: case 0x54: case 0x55: // ADDSD/SUBSD/MULSD/DIVSD:
                   // pop b, pop a, push a OP b as raw double bit patterns.
                   // Real SSE arithmetic never touches integer RFLAGS, so
                   // unlike the GPR ALU ops above there's no pushfq capture
                   // here at all. PHYS_XMM0/1 are pure scratch (never the
                   // persistent xreg slots, which live in memory, not real
                   // XMM registers -- see PUSH_XREG/POP_XREG above), so no
                   // save/restore around them is needed either.
        {
            SseOp op = e.opcode == 0x52 ? SseOp::Add
                     : e.opcode == 0x53 ? SseOp::Sub
                     : e.opcode == 0x54 ? SseOp::Mul
                                         : SseOp::Div;
            movq_xmm_mem64(code, PHYS_XMM0, REG_SP, 0); // xmm0 = b (top)
            J();
            alu_reg_imm32(code, AluOp::Add, REG_SP, 8); // pop b
            J();
            movq_xmm_mem64(code, PHYS_XMM1, REG_SP, 0); // xmm1 = a (new top, peek)
            J();
            sse_arith_sd_reg_reg(code, op, PHYS_XMM1, PHYS_XMM0); // xmm1 = a OP b
            J();
            movq_mem64_xmm(code, REG_SP, 0, PHYS_XMM1); // store result over a's slot
            break;
        }

        case 0x56: case 0x57: case 0x58: case 0x59: // ADDSS/SUBSS/MULSS/DIVSS:
                   // same shape as the SD family above, but native scalar-
                   // single arithmetic only ever defines the destination's
                   // low 32 bits and leaves its upper 96 bits exactly as
                   // they were (real hardware semantics, not something this
                   // code chooses) -- since PHYS_XMM1 was just loaded via a
                   // 64-bit MOVQ, those upper bits are whatever garbage sat
                   // in b's memory slot's own upper 32 bits, not anything
                   // meaningful. Explicitly zeroing the vstack slot before
                   // writing just the low 32 bits back (instead of storing
                   // xmm1 verbatim) keeps every SS producer agreeing on the
                   // full 64-bit slot contents, matching runtime/vm_interp.c.
        {
            SseOp op = e.opcode == 0x56 ? SseOp::Add
                     : e.opcode == 0x57 ? SseOp::Sub
                     : e.opcode == 0x58 ? SseOp::Mul
                                         : SseOp::Div;
            movq_xmm_mem64(code, PHYS_XMM0, REG_SP, 0); // xmm0 = b bits (low32 meaningful)
            J();
            alu_reg_imm32(code, AluOp::Add, REG_SP, 8); // pop b
            J();
            movq_xmm_mem64(code, PHYS_XMM1, REG_SP, 0); // xmm1 = a bits (low32 meaningful)
            J();
            sse_arith_ss_reg_reg(code, op, PHYS_XMM1, PHYS_XMM0); // xmm1.low32 = a OP b
            J();
            alu_reg_reg(code, AluOp::Xor, REG_T0, REG_T0);
            J();
            mov_mem64_reg(code, REG_SP, 0, REG_T0); // zero the full slot first
            J();
            movd_mem32_xmm(code, REG_SP, 0, PHYS_XMM1); // then write the low 32 bits = result
            break;
        }

        case 0x5A: // CVTSI2SD
        case 0x5C: // CVTSI2SS: pop a (int64), push (double)/(float)a. The
                   // float form zero-extends into the full slot just like
                   // ADDSS/etc above; the double form is a plain 8-byte
                   // store, since the result already fills the whole slot.
        {
            mov_reg_mem64(code, REG_T0, REG_SP, 0); // T0 = a, peek
            J();
            if (e.opcode == 0x5A) cvtsi2sd_reg_reg(code, PHYS_XMM0, REG_T0);
            else cvtsi2ss_reg_reg(code, PHYS_XMM0, REG_T0);
            J();
            if (e.opcode == 0x5A) {
                movq_mem64_xmm(code, REG_SP, 0, PHYS_XMM0);
            } else {
                alu_reg_reg(code, AluOp::Xor, REG_T1, REG_T1);
                J();
                mov_mem64_reg(code, REG_SP, 0, REG_T1); // zero the full slot first
                J();
                movd_mem32_xmm(code, REG_SP, 0, PHYS_XMM0);
            }
            break;
        }

        case 0x5B: // CVTTSD2SI
        case 0x5D: // CVTTSS2SI: pop a (double/float bits), push (int64_t)a,
                   // truncating -- real hardware cvttsd2si/cvttss2si, so
                   // overflow/NaN naturally produces the genuine "integer
                   // indefinite" value here (see isa.h for how the C
                   // reference interpreter differs on that same input).
        {
            movq_xmm_mem64(code, PHYS_XMM0, REG_SP, 0); // xmm0 = a bits, peek
            J();
            if (e.opcode == 0x5B) cvttsd2si_reg_reg(code, REG_T0, PHYS_XMM0);
            else cvttss2si_reg_reg(code, REG_T0, PHYS_XMM0);
            J();
            mov_mem64_reg(code, REG_SP, 0, REG_T0);
            break;
        }

        default:
            break;
        }

        J();
        size_t j = jmp_rel32(code);
        labels.ref("dispatch", j, code);
    }

    // --- epilogue: ctx->vip/vsp = ip/sp; restore RBX; return ----------------
    labels.mark("epilogue", code);
    mov_mem64_reg(code, REG_CTX, OFF_VIP, REG_IP);
    J();
    mov_mem64_reg(code, REG_CTX, OFF_VSP, REG_SP);
    // restore the caller's real RBX from ctx's own static scratch -- REG_CTX
    // (== rbx) is both the base of this load and its destination, which is
    // fine: the memory read happens before the register is overwritten.
    mov_reg_mem64(code, REG_CTX, REG_CTX, OFF_SAVED_RBX);
    pop_reg(code, PHYS_RBP); // undoes the prologue's `push rbp` (see above)
    ret(code);

    // --- vstack overflow: fail closed, deliberately, right here -------------
    // Reached only via guard_vstack_overflow's jb above, from one of the four
    // "push" opcode handlers (PUSH_IMM/PUSH_VREG/PUSH_REL/PUSH_XREG). Some of
    // this virtualized block's effects on vreg[] may not be applied yet, so
    // jumping to the epilogue and resuming native execution at exit_target --
    // as if the block had actually finished -- would silently run the
    // original program from a point it never legitimately reaches. A trap
    // right where the problem was detected is strictly safer than either
    // that or writing outside the private vstack buffer (see vm_thunk.S's
    // header for what used to sit there and get corrupted).
    labels.mark("vstack_overflow", code);
    ud2(code);

    return code;
}

} // namespace karity
