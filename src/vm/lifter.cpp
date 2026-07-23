#include "lifter.h"

#include <algorithm>
#include <deque>
#include <random>
#include <set>
#include <unordered_map>
#include <utility>

#include <Zydis/Zydis.h>

#include "emitter.h"
#include "karity/isa.h"
#include "obfuscate.h"

namespace karity {

namespace {

int reg_to_vreg(ZydisRegister reg)
{
    if (reg >= ZYDIS_REGISTER_RAX && reg <= ZYDIS_REGISTER_R15) {
        return static_cast<int>(reg - ZYDIS_REGISTER_RAX);
    }
    return -1;
}

bool is_reg64(const ZydisDecodedOperand &o)
{
    return o.type == ZYDIS_OPERAND_TYPE_REGISTER && o.size == 64 && reg_to_vreg(o.reg.value) >= 0;
}

// Same idea as reg_to_vreg, but accepts any GPR width (used only by
// MOVZX/MOVSX/MOVSXD, whose source -- and, for MOVSX, destination -- can
// legitimately be a 32/16/8-bit sub-register instead of the 64-bit-only
// operands every other case in this file deals with). Zydis lays out each
// width's registers in its own contiguous block in the same RAX..R15
// relative order, so this is one range check per width. Deliberately
// returns -1 for the four legacy high-byte registers (AH/CH/DH/BH): they
// alias bits 8-15 of RAX/RCX/RDX/RBX rather than bits 0-7, which none of
// this VM's load/shift-based value handling is built to reach -- rare
// enough in real (non-hand-written) code that it's simpler to just not
// model it, per this file's usual "wrong thing is worse than nothing" rule.
int reg_to_vreg_any_width(ZydisRegister reg)
{
    if (reg >= ZYDIS_REGISTER_RAX && reg <= ZYDIS_REGISTER_R15) {
        return static_cast<int>(reg - ZYDIS_REGISTER_RAX);
    }
    if (reg >= ZYDIS_REGISTER_EAX && reg <= ZYDIS_REGISTER_R15D) {
        return static_cast<int>(reg - ZYDIS_REGISTER_EAX);
    }
    if (reg >= ZYDIS_REGISTER_AX && reg <= ZYDIS_REGISTER_R15W) {
        return static_cast<int>(reg - ZYDIS_REGISTER_AX);
    }
    if (reg >= ZYDIS_REGISTER_AL && reg <= ZYDIS_REGISTER_BL) {
        return static_cast<int>(reg - ZYDIS_REGISTER_AL); // AL/CL/DL/BL -> 0-3
    }
    if (reg >= ZYDIS_REGISTER_SPL && reg <= ZYDIS_REGISTER_R15B) {
        return static_cast<int>(reg - ZYDIS_REGISTER_SPL) + 4; // SPL..R15B -> 4-15
    }
    return -1; // AH/CH/DH/BH, or an APX register beyond R15
}

// Maps an XMM register operand to one of the KARITY_XREG_COUNT execution-
// local scalar-float slots (see isa.h's comment above VOP_PUSH_XREG).
// XMM8-15 deliberately return -1 and fall back to "unliftable" -- this VM's
// scratch slots only cover XMM0-7 (KARITY_XREG_COUNT == 8), rare enough for
// real (non-hand-written) scalar FP code to reach beyond XMM7 that it's
// simpler to just not model it, same "wrong thing is worse than nothing"
// rule as reg_to_vreg_any_width's AH/CH/DH/BH rejection above.
int reg_to_xmm(ZydisRegister reg)
{
    if (reg >= ZYDIS_REGISTER_XMM0 && reg <= ZYDIS_REGISTER_XMM7) {
        return static_cast<int>(reg - ZYDIS_REGISTER_XMM0);
    }
    return -1;
}

// Pushes the effective address of a memory operand onto the vstack.
// Supports [base+disp] with a plain GPR base (delta added at runtime, since
// the base register's value is only known then) and RIP-relative operands
// (resolved to an anchor-relative delta at lift time, since both the
// instruction and its target are static). No SIB/index-register addressing.
//
// Accepts both ZYDIS_MEMOP_TYPE_MEM (an actual dereference, e.g. MOV/CVTSI2SD/
// CALL's memory forms) and ZYDIS_MEMOP_TYPE_AGEN (LEA's own memory operand --
// Zydis tags it AGEN, not MEM, since LEA computes the address without ever
// reading through it). Excluding AGEN here was a real, reproducible lift-time
// bug found while adding SSE support: every LEA case in this switch (and
// every existing example that uses `lea reg, [rip+X]`) has been silently
// failing this check and falling back to native execution for the LEA
// instruction onward ever since it was added -- invisible until now because
// GPR-only fallback code still produces correct results (vreg[]/real
// registers are always faithfully restored at a VMEXIT, regardless of why it
// happened), whereas an XMM value computed just before a fallback exit has no
// such hardware-backed restoration (see isa.h's note above VOP_PUSH_XREG),
// so an SSE demo whose LEA happened to fall right before a MOVSD [mem] was
// what actually exposed the corruption.
bool try_emit_address(const ZydisDecodedInstruction &insn, const ZydisDecodedOperand &mem_op,
                       uint64_t insn_va, uint64_t anchor_va, BytecodeEmitter &out)
{
    if (mem_op.type != ZYDIS_OPERAND_TYPE_MEMORY) return false;
    if (mem_op.mem.type != ZYDIS_MEMOP_TYPE_MEM && mem_op.mem.type != ZYDIS_MEMOP_TYPE_AGEN) return false;
    if (mem_op.mem.index != ZYDIS_REGISTER_NONE) return false;

    if (mem_op.mem.base == ZYDIS_REGISTER_RIP) {
        ZyanU64 abs_addr = 0;
        if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&insn, &mem_op, insn_va, &abs_addr))) return false;
        out.push_rel(static_cast<int64_t>(abs_addr - anchor_va));
        return true;
    }

    int base_vreg = reg_to_vreg(mem_op.mem.base);
    if (base_vreg < 0) return false; // e.g. absolute [disp32]-only addressing, no base register
    out.push_vreg(static_cast<uint8_t>(base_vreg));
    if (mem_op.mem.disp.value != 0) {
        out.push_imm(static_cast<uint64_t>(mem_op.mem.disp.value));
        out.op(VOP_ADD);
    }
    return true;
}

bool lift_one(const ZydisDecodedInstruction &insn, const ZydisDecodedOperand *ops,
              uint64_t insn_va, uint64_t anchor_va, BytecodeEmitter &out)
{
    switch (insn.mnemonic) {
    case ZYDIS_MNEMONIC_MOV: {
        const auto &dst = ops[0];
        const auto &src = ops[1];

        if (is_reg64(dst) && src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && src.size <= 64) {
            out.push_imm(src.imm.value.u);
            out.pop_vreg(static_cast<uint8_t>(reg_to_vreg(dst.reg.value)));
            return true;
        }
        if (is_reg64(dst) && is_reg64(src)) {
            out.push_vreg(static_cast<uint8_t>(reg_to_vreg(src.reg.value)));
            out.pop_vreg(static_cast<uint8_t>(reg_to_vreg(dst.reg.value)));
            return true;
        }
        if (is_reg64(dst) && src.type == ZYDIS_OPERAND_TYPE_MEMORY &&
            (src.size == 8 || src.size == 16 || src.size == 32 || src.size == 64)) {
            if (!try_emit_address(insn, src, insn_va, anchor_va, out)) return false;
            out.load(src.size);
            out.pop_vreg(static_cast<uint8_t>(reg_to_vreg(dst.reg.value)));
            return true;
        }
        if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY && is_reg64(src) &&
            (dst.size == 8 || dst.size == 16 || dst.size == 32 || dst.size == 64)) {
            if (!try_emit_address(insn, dst, insn_va, anchor_va, out)) return false;
            out.push_vreg(static_cast<uint8_t>(reg_to_vreg(src.reg.value)));
            out.store(dst.size);
            return true;
        }
        if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY && src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
            (dst.size == 8 || dst.size == 16 || dst.size == 32 || dst.size == 64)) {
            if (!try_emit_address(insn, dst, insn_va, anchor_va, out)) return false;
            out.push_imm(src.imm.value.u);
            out.store(dst.size);
            return true;
        }
        return false;
    }
    case ZYDIS_MNEMONIC_ADD:
    case ZYDIS_MNEMONIC_SUB:
    case ZYDIS_MNEMONIC_XOR:
    case ZYDIS_MNEMONIC_AND:
    case ZYDIS_MNEMONIC_OR: {
        const auto &dst = ops[0];
        const auto &src = ops[1];
        if (!is_reg64(dst)) return false;
        if (!is_reg64(src) && !(src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && src.size <= 64)) return false;

        karity_vop vop = insn.mnemonic == ZYDIS_MNEMONIC_ADD ? VOP_ADD
                        : insn.mnemonic == ZYDIS_MNEMONIC_SUB ? VOP_SUB
                        : insn.mnemonic == ZYDIS_MNEMONIC_XOR ? VOP_XOR
                        : insn.mnemonic == ZYDIS_MNEMONIC_AND ? VOP_AND
                                                               : VOP_OR;
        out.push_vreg(static_cast<uint8_t>(reg_to_vreg(dst.reg.value)));
        if (src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            out.push_imm(src.imm.value.u);
        } else {
            out.push_vreg(static_cast<uint8_t>(reg_to_vreg(src.reg.value)));
        }
        out.op(vop);
        out.pop_vreg(static_cast<uint8_t>(reg_to_vreg(dst.reg.value)));
        return true;
    }
    case ZYDIS_MNEMONIC_LEA: {
        // Effective-address computation only, no dereference: exactly what
        // try_emit_address already builds for memory operands elsewhere.
        const auto &dst = ops[0];
        const auto &src = ops[1];
        if (!is_reg64(dst)) return false;
        if (!try_emit_address(insn, src, insn_va, anchor_va, out)) return false;
        out.pop_vreg(static_cast<uint8_t>(reg_to_vreg(dst.reg.value)));
        return true;
    }
    case ZYDIS_MNEMONIC_PUSH: {
        // Register, imm32(sign-extended), or [mem] operand. Native stack,
        // via the vreg[RSP] this VM already mirrors faithfully for
        // VOP_CALL: rsp -= 8; [rsp] = src.
        //
        // rsp is decremented *first* (matching the register case, and
        // matching real hardware for [mem] too: the source address, if it
        // doesn't reference RSP itself, is unaffected either way) so the
        // destination "push slot" address is ready before src's value is
        // computed. A [mem] source that *does* use RSP as its base is
        // rejected outright: real hardware evaluates that address before
        // decrementing, which would require reordering this around the
        // decrement -- rare enough in real code (nobody pushes relative to
        // the stack pointer itself) that it's simpler to just not model it,
        // per this file's usual "wrong thing is worse than nothing" rule.
        const auto &src = ops[0];
        int rsp_vreg = reg_to_vreg(ZYDIS_REGISTER_RSP);

        if (src.type == ZYDIS_OPERAND_TYPE_MEMORY && src.mem.base == ZYDIS_REGISTER_RSP) return false;

        out.push_vreg(static_cast<uint8_t>(rsp_vreg));
        out.push_imm(8);
        out.op(VOP_SUB);
        out.pop_vreg(static_cast<uint8_t>(rsp_vreg));

        out.push_vreg(static_cast<uint8_t>(rsp_vreg));
        if (is_reg64(src)) {
            out.push_vreg(static_cast<uint8_t>(reg_to_vreg(src.reg.value)));
        } else if (src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && src.size <= 64) {
            out.push_imm(src.imm.value.u);
        } else if (src.type == ZYDIS_OPERAND_TYPE_MEMORY && src.size == 64) {
            if (!try_emit_address(insn, src, insn_va, anchor_va, out)) return false;
            out.load(64);
        } else {
            return false;
        }
        out.store(64);
        return true;
    }
    case ZYDIS_MNEMONIC_POP: {
        // Register or [mem] destination: dst = [rsp]; rsp += 8.
        //
        // A [mem] destination that uses RSP as its base is rejected for the
        // same reason as PUSH above: real hardware evaluates that address
        // *after* incrementing RSP, which this emission order doesn't
        // model (dst's address is computed independently of rsp's own
        // update here, which is only correct when dst doesn't reference
        // RSP at all).
        const auto &dst = ops[0];
        int rsp_vreg = reg_to_vreg(ZYDIS_REGISTER_RSP);

        if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY && dst.mem.base == ZYDIS_REGISTER_RSP) return false;

        if (is_reg64(dst)) {
            out.push_vreg(static_cast<uint8_t>(rsp_vreg));
            out.load(64);
            out.pop_vreg(static_cast<uint8_t>(reg_to_vreg(dst.reg.value)));
        } else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY && dst.size == 64) {
            if (!try_emit_address(insn, dst, insn_va, anchor_va, out)) return false;
            out.push_vreg(static_cast<uint8_t>(rsp_vreg));
            out.load(64);
            out.store(64);
        } else {
            return false;
        }

        out.push_vreg(static_cast<uint8_t>(rsp_vreg));
        out.push_imm(8);
        out.op(VOP_ADD);
        out.pop_vreg(static_cast<uint8_t>(rsp_vreg));
        return true;
    }
    case ZYDIS_MNEMONIC_CMP:
    case ZYDIS_MNEMONIC_TEST: {
        // Same operand shape as ADD/SUB, but consumes both operands and
        // writes only ctx->vflags -- no destination write-back.
        const auto &dst = ops[0];
        const auto &src = ops[1];
        if (!is_reg64(dst)) return false;
        if (!is_reg64(src) && !(src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && src.size <= 64)) return false;

        out.push_vreg(static_cast<uint8_t>(reg_to_vreg(dst.reg.value)));
        if (src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            out.push_imm(src.imm.value.u);
        } else {
            out.push_vreg(static_cast<uint8_t>(reg_to_vreg(src.reg.value)));
        }
        out.op(insn.mnemonic == ZYDIS_MNEMONIC_CMP ? VOP_CMP : VOP_TEST);
        return true;
    }
    case ZYDIS_MNEMONIC_NEG:
    case ZYDIS_MNEMONIC_NOT:
    case ZYDIS_MNEMONIC_INC:
    case ZYDIS_MNEMONIC_DEC: {
        const auto &dst = ops[0];
        if (!is_reg64(dst)) return false;
        karity_vop vop = insn.mnemonic == ZYDIS_MNEMONIC_NEG ? VOP_NEG
                        : insn.mnemonic == ZYDIS_MNEMONIC_NOT ? VOP_NOT
                        : insn.mnemonic == ZYDIS_MNEMONIC_INC ? VOP_INC
                                                               : VOP_DEC;
        out.push_vreg(static_cast<uint8_t>(reg_to_vreg(dst.reg.value)));
        out.op(vop);
        out.pop_vreg(static_cast<uint8_t>(reg_to_vreg(dst.reg.value)));
        return true;
    }
    case ZYDIS_MNEMONIC_SHL:
    case ZYDIS_MNEMONIC_SHR:
    case ZYDIS_MNEMONIC_SAR:
    case ZYDIS_MNEMONIC_ROL:
    case ZYDIS_MNEMONIC_ROR: {
        // Count operand is either an immediate (imm8, including the
        // implicit "1" of the single-bit D0/D1 encodings) or CL -- the
        // only register real x86 allows there at all.
        const auto &dst = ops[0];
        const auto &src = ops[1];
        if (!is_reg64(dst)) return false;
        bool count_imm = src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && src.size <= 64;
        bool count_cl = src.type == ZYDIS_OPERAND_TYPE_REGISTER && src.reg.value == ZYDIS_REGISTER_CL;
        if (!count_imm && !count_cl) return false;

        karity_vop vop = insn.mnemonic == ZYDIS_MNEMONIC_SHL ? VOP_SHL
                        : insn.mnemonic == ZYDIS_MNEMONIC_SHR ? VOP_SHR
                        : insn.mnemonic == ZYDIS_MNEMONIC_SAR ? VOP_SAR
                        : insn.mnemonic == ZYDIS_MNEMONIC_ROL ? VOP_ROL
                                                               : VOP_ROR;
        out.push_vreg(static_cast<uint8_t>(reg_to_vreg(dst.reg.value)));
        if (count_imm) {
            out.push_imm(src.imm.value.u);
        } else {
            out.push_vreg(static_cast<uint8_t>(reg_to_vreg(ZYDIS_REGISTER_RCX))); // CL is RCX's low byte
        }
        out.op(vop);
        out.pop_vreg(static_cast<uint8_t>(reg_to_vreg(dst.reg.value)));
        return true;
    }
    case ZYDIS_MNEMONIC_MUL:
    case ZYDIS_MNEMONIC_DIV:
    case ZYDIS_MNEMONIC_IDIV: {
        // One-operand unsigned MUL, or unsigned/signed DIV: the sole
        // explicit operand is the multiplier/divisor. RAX (and, for
        // DIV/IDIV, RDX too) are implicit and handled entirely inside the
        // opcode handler -- see isa.h -- so there's nothing to push/pop for
        // them here, unlike ADD/SUB's explicit dst operand. Register
        // operands only, same as every other ALU case above (no memory
        // support anywhere in this switch outside MOV/LEA/PUSH/POP/CALL).
        const auto &src = ops[0];
        if (!is_reg64(src)) return false;
        karity_vop vop = insn.mnemonic == ZYDIS_MNEMONIC_MUL ? VOP_MUL
                        : insn.mnemonic == ZYDIS_MNEMONIC_DIV ? VOP_DIV
                                                               : VOP_IDIV;
        out.push_vreg(static_cast<uint8_t>(reg_to_vreg(src.reg.value)));
        out.op(vop);
        return true;
    }
    case ZYDIS_MNEMONIC_IMUL: {
        // Signed multiply has three distinct operand shapes in real x86,
        // and the one-operand form needs the same implicit-RAX/RDX
        // treatment as VOP_MUL above, while the two/three-operand forms
        // are an ordinary "pop b, pop a, push a*b" op with an explicit
        // destination -- different enough in stack shape that they need
        // distinct opcodes (VOP_IMUL1 vs VOP_IMUL2, see isa.h).
        if (insn.operand_count_visible == 1) {
            const auto &src = ops[0];
            if (!is_reg64(src)) return false;
            out.push_vreg(static_cast<uint8_t>(reg_to_vreg(src.reg.value)));
            out.op(VOP_IMUL1);
            return true;
        }
        if (insn.operand_count_visible == 2) {
            const auto &dst = ops[0];
            const auto &src = ops[1];
            if (!is_reg64(dst)) return false;
            if (!is_reg64(src) && !(src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && src.size <= 64)) return false;
            out.push_vreg(static_cast<uint8_t>(reg_to_vreg(dst.reg.value)));
            if (src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                out.push_imm(src.imm.value.u);
            } else {
                out.push_vreg(static_cast<uint8_t>(reg_to_vreg(src.reg.value)));
            }
            out.op(VOP_IMUL2);
            out.pop_vreg(static_cast<uint8_t>(reg_to_vreg(dst.reg.value)));
            return true;
        }
        if (insn.operand_count_visible == 3) {
            // imul dst, src, imm32: dst is write-only, src is the real "a"
            // operand (dst's own prior value is irrelevant, unlike the
            // two-operand form).
            const auto &dst = ops[0];
            const auto &src = ops[1];
            const auto &imm = ops[2];
            if (!is_reg64(dst) || !is_reg64(src)) return false;
            if (imm.type != ZYDIS_OPERAND_TYPE_IMMEDIATE || imm.size > 64) return false;
            out.push_vreg(static_cast<uint8_t>(reg_to_vreg(src.reg.value)));
            out.push_imm(imm.imm.value.u);
            out.op(VOP_IMUL2);
            out.pop_vreg(static_cast<uint8_t>(reg_to_vreg(dst.reg.value)));
            return true;
        }
        return false;
    }
    case ZYDIS_MNEMONIC_MOVZX:
    case ZYDIS_MNEMONIC_MOVSX:
    case ZYDIS_MNEMONIC_MOVSXD: {
        // dst is always a plain 32- or 64-bit GPR (never memory); src is an
        // 8/16/32-bit GPR or memory operand narrower than dst. reg_to_vreg_
        // any_width (not is_reg64) is needed on both sides here since dst
        // can legitimately be 32-bit and src is by definition narrower than
        // 64-bit.
        const auto &dst = ops[0];
        const auto &src = ops[1];
        if (dst.type != ZYDIS_OPERAND_TYPE_REGISTER || (dst.size != 32 && dst.size != 64)) return false;
        int dst_vreg = reg_to_vreg_any_width(dst.reg.value);
        if (dst_vreg < 0) return false;

        int src_size_bytes;
        if (src.type == ZYDIS_OPERAND_TYPE_REGISTER &&
            (src.size == 8 || src.size == 16 || src.size == 32)) {
            int src_vreg = reg_to_vreg_any_width(src.reg.value);
            if (src_vreg < 0) return false;
            out.push_vreg(static_cast<uint8_t>(src_vreg));
            src_size_bytes = src.size / 8;
        } else if (src.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                   (src.size == 8 || src.size == 16 || src.size == 32)) {
            if (!try_emit_address(insn, src, insn_va, anchor_va, out)) return false;
            out.load(src.size);
            src_size_bytes = src.size / 8;
        } else {
            return false;
        }

        if (insn.mnemonic == ZYDIS_MNEMONIC_MOVZX) {
            out.movzx(src_size_bytes);
        } else {
            // MOVSXD (opcode 0x63) decodes under its own Zydis mnemonic
            // rather than MOVSX, but it's the exact same sign-extend-with-
            // optional-32-bit-truncation shape (src_size_bytes==4 here),
            // so both share VOP_MOVSX.
            out.movsx(src_size_bytes, dst.size / 8);
        }
        out.pop_vreg(static_cast<uint8_t>(dst_vreg));
        return true;
    }
    case ZYDIS_MNEMONIC_CALL: {
        const auto &target = ops[0];
        if (target.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && target.imm.is_relative) {
            ZyanU64 abs_addr = 0;
            if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&insn, &target, insn_va, &abs_addr))) return false;
            out.call(static_cast<int64_t>(abs_addr - anchor_va));
            return true;
        }
        if (is_reg64(target)) {
            // Register-indirect call (`call reg`): target value is a
            // runtime-only quantity, so push it and let VOP_CALL_IND resolve
            // it at native-call time instead of the direct case's lift-time
            // anchor+delta.
            out.push_vreg(static_cast<uint8_t>(reg_to_vreg(target.reg.value)));
            out.call_indirect();
            return true;
        }
        if (target.type == ZYDIS_OPERAND_TYPE_MEMORY && target.size == 64) {
            // Memory-indirect call (`call [rip+X]` for IAT thunks, or
            // `call [reg(+disp)]` for vtable-style calls): try_emit_address
            // pushes the *slot* address (anchor-relative for [rip+X], so it
            // survives ASLR the same way LEA/MOV already do), then a LOAD64
            // dereferences it to the actual runtime target.
            if (!try_emit_address(insn, target, insn_va, anchor_va, out)) return false;
            out.load(64);
            out.call_indirect();
            return true;
        }
        return false; // e.g. SIB/index addressing, or a <64-bit target
    }
    case ZYDIS_MNEMONIC_MOVSD:
    case ZYDIS_MNEMONIC_MOVSS: {
        // Scalar SSE2/SSE move: xmm<-xmm, xmm<-mem, or mem<-xmm. Flag-
        // transparent (matches native MOVSD/MOVSS). mem_size doubles as the
        // LOAD/STORE width: 64 for MOVSD reads/writes the double bit-for-
        // bit, 32 for MOVSS reads/writes just the float and relies on
        // VOP_LOAD32's existing zero-extension to fill in the upper 32 bits
        // of the vstack slot the same way every other SS producer does (see
        // isa.h) -- no new memory opcode needed for either width.
        const auto &dst = ops[0];
        const auto &src = ops[1];
        const bool is_sd = insn.mnemonic == ZYDIS_MNEMONIC_MOVSD;
        const int mem_size = is_sd ? 64 : 32;

        if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER && reg_to_xmm(dst.reg.value) >= 0 &&
            src.type == ZYDIS_OPERAND_TYPE_REGISTER && reg_to_xmm(src.reg.value) >= 0) {
            out.push_xreg(static_cast<uint8_t>(reg_to_xmm(src.reg.value)));
            out.pop_xreg(static_cast<uint8_t>(reg_to_xmm(dst.reg.value)));
            return true;
        }
        if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER && reg_to_xmm(dst.reg.value) >= 0 &&
            src.type == ZYDIS_OPERAND_TYPE_MEMORY && src.size == mem_size) {
            if (!try_emit_address(insn, src, insn_va, anchor_va, out)) return false;
            out.load(mem_size);
            out.pop_xreg(static_cast<uint8_t>(reg_to_xmm(dst.reg.value)));
            return true;
        }
        if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY && dst.size == mem_size &&
            src.type == ZYDIS_OPERAND_TYPE_REGISTER && reg_to_xmm(src.reg.value) >= 0) {
            if (!try_emit_address(insn, dst, insn_va, anchor_va, out)) return false;
            out.push_xreg(static_cast<uint8_t>(reg_to_xmm(src.reg.value)));
            out.store(mem_size);
            return true;
        }
        return false;
    }
    case ZYDIS_MNEMONIC_ADDSD:
    case ZYDIS_MNEMONIC_SUBSD:
    case ZYDIS_MNEMONIC_MULSD:
    case ZYDIS_MNEMONIC_DIVSD:
    case ZYDIS_MNEMONIC_ADDSS:
    case ZYDIS_MNEMONIC_SUBSS:
    case ZYDIS_MNEMONIC_MULSS:
    case ZYDIS_MNEMONIC_DIVSS: {
        // dst (also the first source operand) must be an xreg-mapped XMM
        // register; the second source is either another such register or a
        // same-width memory operand (register-only ALU precedent elsewhere
        // in this file doesn't apply here since try_emit_address already
        // handles the memory case for free). Never touches vflags (matches
        // native scalar SSE arithmetic).
        const auto &dst = ops[0];
        const auto &src = ops[1];
        if (!(dst.type == ZYDIS_OPERAND_TYPE_REGISTER && reg_to_xmm(dst.reg.value) >= 0)) return false;

        const bool is_ss = insn.mnemonic == ZYDIS_MNEMONIC_ADDSS || insn.mnemonic == ZYDIS_MNEMONIC_SUBSS ||
                            insn.mnemonic == ZYDIS_MNEMONIC_MULSS || insn.mnemonic == ZYDIS_MNEMONIC_DIVSS;
        const int mem_size = is_ss ? 32 : 64;

        karity_vop vop = insn.mnemonic == ZYDIS_MNEMONIC_ADDSD ? VOP_ADDSD
                        : insn.mnemonic == ZYDIS_MNEMONIC_SUBSD ? VOP_SUBSD
                        : insn.mnemonic == ZYDIS_MNEMONIC_MULSD ? VOP_MULSD
                        : insn.mnemonic == ZYDIS_MNEMONIC_DIVSD ? VOP_DIVSD
                        : insn.mnemonic == ZYDIS_MNEMONIC_ADDSS ? VOP_ADDSS
                        : insn.mnemonic == ZYDIS_MNEMONIC_SUBSS ? VOP_SUBSS
                        : insn.mnemonic == ZYDIS_MNEMONIC_MULSS ? VOP_MULSS
                                                                 : VOP_DIVSS;

        out.push_xreg(static_cast<uint8_t>(reg_to_xmm(dst.reg.value)));
        if (src.type == ZYDIS_OPERAND_TYPE_REGISTER && reg_to_xmm(src.reg.value) >= 0) {
            out.push_xreg(static_cast<uint8_t>(reg_to_xmm(src.reg.value)));
        } else if (src.type == ZYDIS_OPERAND_TYPE_MEMORY && src.size == mem_size) {
            if (!try_emit_address(insn, src, insn_va, anchor_va, out)) return false;
            out.load(mem_size);
        } else {
            return false;
        }
        out.op(vop);
        out.pop_xreg(static_cast<uint8_t>(reg_to_xmm(dst.reg.value)));
        return true;
    }
    case ZYDIS_MNEMONIC_CVTSI2SD:
    case ZYDIS_MNEMONIC_CVTSI2SS: {
        // xmm <- (double)/(float)(int64_t)r64. Only a 64-bit GPR source is
        // modeled (the REX.W encoding) -- same "register operands only, no
        // 32-bit variant" restriction as every other ALU case in this file.
        const auto &dst = ops[0];
        const auto &src = ops[1];
        if (!(dst.type == ZYDIS_OPERAND_TYPE_REGISTER && reg_to_xmm(dst.reg.value) >= 0)) return false;
        if (!is_reg64(src)) return false;
        karity_vop vop = insn.mnemonic == ZYDIS_MNEMONIC_CVTSI2SD ? VOP_CVTSI2SD : VOP_CVTSI2SS;
        out.push_vreg(static_cast<uint8_t>(reg_to_vreg(src.reg.value)));
        out.op(vop);
        out.pop_xreg(static_cast<uint8_t>(reg_to_xmm(dst.reg.value)));
        return true;
    }
    case ZYDIS_MNEMONIC_CVTTSD2SI:
    case ZYDIS_MNEMONIC_CVTTSS2SI: {
        // r64 <- (int64_t)(double)/(float)xmm, truncating. Only a 64-bit
        // GPR destination is modeled (the REX.W encoding), same restriction
        // as CVTSI2SD/CVTSI2SS above.
        const auto &dst = ops[0];
        const auto &src = ops[1];
        if (!is_reg64(dst)) return false;
        if (!(src.type == ZYDIS_OPERAND_TYPE_REGISTER && reg_to_xmm(src.reg.value) >= 0)) return false;
        karity_vop vop = insn.mnemonic == ZYDIS_MNEMONIC_CVTTSD2SI ? VOP_CVTTSD2SI : VOP_CVTTSS2SI;
        out.push_xreg(static_cast<uint8_t>(reg_to_xmm(src.reg.value)));
        out.op(vop);
        out.pop_vreg(static_cast<uint8_t>(reg_to_vreg(dst.reg.value)));
        return true;
    }
    case ZYDIS_MNEMONIC_NOP:
        out.nop();
        return true;
    default:
        return false;
    }
}

// Emits one already-decoded, already-verified-liftable instruction for
// real, then the same obfuscation filler try_lift always inserted after a
// real instruction (see the original single-block loop this replaced).
void lift_and_obfuscate(const ZydisDecodedInstruction &insn, const ZydisDecodedOperand *ops,
                         uint64_t insn_va, uint64_t anchor_va, BytecodeEmitter &out, std::mt19937_64 &rng)
{
    bool ok = lift_one(insn, ops, insn_va, anchor_va, out);
    (void)ok; // must succeed: caller already proved liftability via can_lift_plain

    int carrier = ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER ? reg_to_vreg(ops[0].reg.value) : -1;
    insert_obfuscation(out, carrier >= 0 ? static_cast<uint8_t>(carrier) : 0, rng);
}

// ---- CFG discovery (branches/loops past the mandatory entry prefix) ------
//
// This mirrors src/native/nanomite_scan.cpp's worklist-driven walk: same
// problem shape (follow Jcc taken/fallthrough and direct JMP through a
// bounded probe buffer, let CALL/RET/plain instructions fall through or
// terminate appropriately, detect two runs disagreeing about instruction
// boundaries over the same physical bytes) but producing karity bytecode
// blocks wired together with VOP_JCC/VOP_JMP instead of nanomite's in-place
// trap+ciphertext blocks.

bool is_real_jcc(const ZydisDecodedInstruction &insn)
{
    // Only the 16 real, flags-tested Jcc encodings -- short 0x70-0x7F or
    // two-byte 0x0F 0x80-0x8F -- map onto KARITY_CC_*. JCXZ/LOOP/LOOPE/LOOPNE
    // also decode under ZYDIS_CATEGORY_COND_BR but test an implicit counter
    // register (and decrement it) instead of vflags alone, so they don't fit
    // VOP_JCC and are left unsupported: they simply fail classify_for_lift
    // below and become a natural (unliftable-next-instruction) block exit,
    // same as any other unmodeled instruction.
    return insn.meta.category == ZYDIS_CATEGORY_COND_BR &&
           ((insn.opcode_map == ZYDIS_OPCODE_MAP_DEFAULT && insn.opcode >= 0x70 && insn.opcode <= 0x7F) ||
            (insn.opcode_map == ZYDIS_OPCODE_MAP_0F && insn.opcode >= 0x80 && insn.opcode <= 0x8F));
}

// Whether lift_one can translate this instruction on its own. Jcc/direct-JMP
// are deliberately excluded from this path -- they need block/edge
// awareness lift_one doesn't have, so the CFG walker below classifies them
// itself. lift_one is side-effect-free except for appending to whichever
// BytecodeEmitter it's given, so probing into a throwaway instance is a
// safe, single-source-of-truth way to ask "would this succeed" during
// discovery, before the real emission pass (emit_program below) commits to
// it for real.
bool can_lift_plain(const ZydisDecodedInstruction &insn, const ZydisDecodedOperand *ops,
                     uint64_t insn_va, uint64_t anchor_va)
{
    BytecodeEmitter scratch;
    return lift_one(insn, ops, insn_va, anchor_va, scratch);
}

struct AcceptedInsn {
    size_t start_offset = 0;
    size_t end_offset = 0;
    enum class Kind { Plain, Jcc, Jmp } kind = Kind::Plain;
    uint8_t cc = 0;              // Jcc only (KARITY_CC_*)
    uint64_t taken_va = 0;       // Jcc (taken target) / Jmp (target)
    uint64_t fallthrough_va = 0; // Jcc only
};

struct Run {
    size_t start_offset = 0;
    std::vector<AcceptedInsn> insns; // empty => this address can never be a
                                      // lifted block (its very first
                                      // instruction was already undecodable
                                      // or unliftable) -- any edge that
                                      // pointed here resolves to a
                                      // VOP_VMEXIT_REL at emission time
                                      // instead, once that becomes visible
                                      // (see emit_program's block_by_va).
};

// Byte/edge bookkeeping shared across one discovery walk.
struct DiscoverState {
    size_t max_len = 0;
    uint64_t code_va = 0;
    size_t reserved_prefix_len = 0; // [0, this) is the mandatory entry
                                     // prefix the OEP patch unconditionally
                                     // overwrites with jmp+junk -- off-limits
                                     // to every edge (see resolve_edge)
    std::vector<int32_t> owner;         // run index owning each byte, -1 if free
    std::vector<uint8_t> insn_boundary; // true at instruction-start offsets
    std::set<size_t> forced_boundaries; // offsets that must start a fresh
                                         // lifted block despite not being
                                         // some run's own start_offset (a
                                         // different edge landed cleanly here)
    std::deque<size_t> worklist;
    std::vector<Run> runs;
};

// Tries to make `target_va` a valid edge endpoint. Out-of-window targets
// need nothing from the discovery walk -- they resolve to a VOP_VMEXIT_REL
// automatically at emission time, exactly like an out-of-window CALL target
// elsewhere in this file: bytes this lift never touches stay correct on
// their own. An in-window target that's unclaimed becomes a new worklist
// entry (its own run); one that already sits exactly on some run's
// instruction boundary is a clean shared merge point. Landing inside the
// mandatory entry prefix, or in the *interior* of an instruction some other
// run already claimed, is unsafe either way (about to become jmp+junk, or
// ambiguous about what would actually execute there) -- the caller must
// reject the whole branch instruction rather than resolve just this edge.
bool resolve_edge(DiscoverState &st, uint64_t target_va)
{
    int64_t off_signed = static_cast<int64_t>(target_va) - static_cast<int64_t>(st.code_va);
    if (off_signed < 0 || static_cast<uint64_t>(off_signed) >= st.max_len) return true; // out of window: ok, becomes an exit

    size_t off = static_cast<size_t>(off_signed);
    if (off < st.reserved_prefix_len) return false; // would land inside the soon-to-be-overwritten OEP prefix

    if (st.owner[off] == -1) {
        st.worklist.push_back(off);
        return true;
    }
    if (st.insn_boundary[off]) {
        st.forced_boundaries.insert(off);
        return true;
    }
    return false; // mid-instruction of a run that already claimed these bytes
}

// Decodes and classifies one instruction at `offset`. Returns false if it
// can't be part of any run at all -- undecodable, or lift_one can't handle
// it and it isn't a real Jcc/direct-JMP either, or (for Jcc/JMP) one of its
// edges is unsafe per resolve_edge -- in which case the caller stops the
// run right before it, same "wrong thing is worse than nothing" rule as
// everywhere else in this project. is_terminator is true for Jcc/JMP
// (nothing after them is reachable by straight-line fallthrough within this
// run) and false for everything else, CALL included: VOP_CALL already
// returns control to the very next bytecode instruction, so from the CFG's
// point of view a CALL is just another plain, liftable instruction.
bool classify_for_lift(DiscoverState &st, ZydisDecoder &decoder, const uint8_t *code, uint64_t anchor_va,
                        size_t offset, AcceptedInsn &out, bool &is_terminator)
{
    is_terminator = false;

    ZydisDecodedInstruction insn;
    ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
    ZyanStatus status = ZydisDecoderDecodeFull(&decoder, code + offset, st.max_len - offset, &insn, ops);
    if (!ZYAN_SUCCESS(status)) return false;

    const uint64_t insn_va = st.code_va + offset;

    if (is_real_jcc(insn)) {
        const ZydisDecodedOperand &target = ops[0];
        if (target.type != ZYDIS_OPERAND_TYPE_IMMEDIATE || !target.imm.is_relative) return false;
        ZyanU64 abs_addr = 0;
        if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&insn, &target, insn_va, &abs_addr))) return false;

        const uint64_t fallthrough_va = insn_va + insn.length;
        const bool taken_ok = resolve_edge(st, abs_addr);
        const bool fall_ok = resolve_edge(st, fallthrough_va);
        if (!taken_ok || !fall_ok) return false; // can't safely land on either edge -- drop the whole Jcc

        out.start_offset = offset;
        out.end_offset = offset + insn.length;
        out.kind = AcceptedInsn::Kind::Jcc;
        out.cc = static_cast<uint8_t>(insn.opcode & 0x0F);
        out.taken_va = abs_addr;
        out.fallthrough_va = fallthrough_va;
        is_terminator = true;
        return true;
    }

    if (insn.meta.category == ZYDIS_CATEGORY_UNCOND_BR) {
        const ZydisDecodedOperand &target = ops[0];
        if (target.type != ZYDIS_OPERAND_TYPE_IMMEDIATE || !target.imm.is_relative) {
            return false; // indirect jmp (register or [mem] target) -- out of scope
        }
        ZyanU64 abs_addr = 0;
        if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&insn, &target, insn_va, &abs_addr))) return false;
        if (!resolve_edge(st, abs_addr)) return false;

        out.start_offset = offset;
        out.end_offset = offset + insn.length;
        out.kind = AcceptedInsn::Kind::Jmp;
        out.taken_va = abs_addr;
        is_terminator = true;
        return true;
    }

    if (!can_lift_plain(insn, ops, insn_va, anchor_va)) return false; // e.g. RET, SSE, JCXZ/LOOP*, ...

    out.start_offset = offset;
    out.end_offset = offset + insn.length;
    out.kind = AcceptedInsn::Kind::Plain;
    return true;
}

// Phase 1: worklist-driven walk of the region's CFG, starting at
// `start_offset` (right where the mandatory entry prefix left off). Mirrors
// nanomite_scan.cpp's Phase 1 exactly: claim bytes into `owner` as they're
// decoded, so resolve_edge above can detect two runs (including a run
// looping back into its own earlier bytes) disagreeing over the same
// physical bytes.
void discover_cfg(DiscoverState &st, ZydisDecoder &decoder, const uint8_t *code, uint64_t anchor_va,
                   size_t start_offset)
{
    st.worklist.push_back(start_offset);

    while (!st.worklist.empty()) {
        const size_t start = st.worklist.front();
        st.worklist.pop_front();
        if (start >= st.max_len || st.owner[start] != -1) continue; // already covered

        const auto run_id = static_cast<int32_t>(st.runs.size());
        Run run;
        run.start_offset = start;

        size_t offset = start;
        while (offset < st.max_len) {
            if (st.owner[offset] != -1) {
                if (st.insn_boundary[offset]) st.forced_boundaries.insert(offset);
                break; // ran into territory another run (or this one, looping back) already owns
            }

            AcceptedInsn ai;
            bool is_terminator = false;
            if (!classify_for_lift(st, decoder, code, anchor_va, offset, ai, is_terminator)) break;

            for (size_t b = offset; b < ai.end_offset; b++) st.owner[b] = run_id;
            st.insn_boundary[offset] = 1;
            run.insns.push_back(ai);
            offset = ai.end_offset;

            if (is_terminator) break;
        }

        st.runs.push_back(std::move(run));
    }
}

// A lifted bytecode block: some plain instructions (possibly none, if a
// Jcc/JMP is the block's very first thing), followed by exactly one
// terminator. `natural_target_va` covers the two cases where a run's own
// straight-line decode simply stopped without a Jcc/JMP: either it merged
// cleanly into a forced boundary (another edge's target, i.e. this really
// is a Block-continuation) or it ran out of window/hit something
// unliftable (a true native exit) -- emit_program can't tell which just
// from this struct, and doesn't need to: see block_by_va there.
struct LiftedBlock {
    size_t start_offset = 0;
    std::vector<AcceptedInsn> plain;
    bool has_jcc = false;
    uint8_t jcc_cc = 0;
    uint64_t jcc_taken_va = 0;
    uint64_t jcc_fallthrough_va = 0;
    bool has_jmp = false;
    uint64_t jmp_target_va = 0;
    uint64_t natural_target_va = 0; // valid iff !has_jcc && !has_jmp
};

// Phase 2: cuts each run into one or more LiftedBlocks at every
// forced_boundaries offset that falls strictly inside it (a different
// edge's target landed cleanly mid-run) -- same idea as
// nanomite_scan.cpp's group_and_emit, minus the trap-density grouping
// (irrelevant here: bytecode blocks have no size cap to balance against).
std::vector<LiftedBlock> split_runs(const std::vector<Run> &runs, const std::set<size_t> &forced_boundaries,
                                     uint64_t code_va)
{
    std::vector<LiftedBlock> blocks;

    for (const Run &run : runs) {
        if (run.insns.empty()) continue; // doomed start address -- produces no block

        LiftedBlock cur;
        cur.start_offset = run.start_offset;
        size_t cur_start = run.start_offset;

        for (const AcceptedInsn &ai : run.insns) {
            if (ai.start_offset != cur_start && forced_boundaries.count(ai.start_offset)) {
                cur.natural_target_va = code_va + ai.start_offset; // falls into the block starting here
                blocks.push_back(cur);
                cur = LiftedBlock{};
                cur.start_offset = ai.start_offset;
                cur_start = ai.start_offset;
            }

            if (ai.kind == AcceptedInsn::Kind::Jcc) {
                cur.has_jcc = true;
                cur.jcc_cc = ai.cc;
                cur.jcc_taken_va = ai.taken_va;
                cur.jcc_fallthrough_va = ai.fallthrough_va;
            } else if (ai.kind == AcceptedInsn::Kind::Jmp) {
                cur.has_jmp = true;
                cur.jmp_target_va = ai.taken_va;
            } else {
                cur.plain.push_back(ai);
            }
        }

        if (!cur.has_jcc && !cur.has_jmp) {
            cur.natural_target_va = code_va + run.insns.back().end_offset;
        }
        blocks.push_back(cur);
    }

    return blocks;
}

// Phase 3: emits every block into `out`, wiring edges together with
// VOP_JCC/VOP_JMP for in-VM continuations and VOP_VMEXIT_REL for anything
// that leaves the lifted CFG. Every edge (Jcc taken, Jcc fallthrough, Jmp
// target, a block's natural falloff, or the caller-supplied `prefix_patch`
// -- the mandatory entry prefix's own jump into wherever discovery started)
// goes through the exact same deferred-patch pipeline: emit a jmp/jcc
// placeholder now, record which native VA it should reach, and resolve all
// of them in one final pass once every block (and therefore every block's
// own bytecode-stream position) is known. That resolution pass also lazily
// creates (and dedupes, by target VA) the small VOP_VMEXIT_REL trampolines
// that out-of-CFG edges land on.
struct PendingPatch {
    size_t operand_pos;
    uint64_t target_va;
};

void emit_program(BytecodeEmitter &out, const std::vector<LiftedBlock> &blocks, ZydisDecoder &decoder,
                   const uint8_t *code, size_t max_len, uint64_t code_va, uint64_t anchor_va,
                   const PendingPatch &prefix_patch, std::mt19937_64 &rng)
{
    std::vector<PendingPatch> pending{prefix_patch};
    std::unordered_map<uint64_t, size_t> block_by_va; // block start VA -> bytecode offset

    for (const LiftedBlock &block : blocks) {
        block_by_va[code_va + block.start_offset] = out.size();

        for (const AcceptedInsn &ai : block.plain) {
            ZydisDecodedInstruction insn;
            ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
            ZyanStatus status =
                ZydisDecoderDecodeFull(&decoder, code + ai.start_offset, max_len - ai.start_offset, &insn, ops);
            (void)status; // must succeed: discovery already decoded this exact instruction once

            if (block.has_jcc) {
                // insert_obfuscation's junk runs real VOP_ADD/SUB/XOR/AND/OR
                // (same opcodes real arithmetic uses, so it sets ctx->vflags
                // exactly like they would) -- harmless everywhere nothing
                // reads vflags afterward, but this block's own VOP_JCC does,
                // right after its last plain instruction. Whichever of
                // these instructions is the original CMP/TEST/etc that the
                // native Jcc actually depended on, junk between it and the
                // branch would silently overwrite the real condition, so no
                // obfuscation gets interleaved anywhere in a Jcc-terminated
                // block -- correctness over junk density here.
                bool ok = lift_one(insn, ops, code_va + ai.start_offset, anchor_va, out);
                (void)ok; // must succeed: discovery already proved liftability
            } else {
                lift_and_obfuscate(insn, ops, code_va + ai.start_offset, anchor_va, out, rng);
            }
        }

        if (block.has_jcc) {
            pending.push_back({out.emit_jcc_placeholder(block.jcc_cc), block.jcc_taken_va});
            pending.push_back({out.emit_jmp_placeholder(), block.jcc_fallthrough_va});
        } else if (block.has_jmp) {
            pending.push_back({out.emit_jmp_placeholder(), block.jmp_target_va});
        } else {
            pending.push_back({out.emit_jmp_placeholder(), block.natural_target_va});
        }
    }

    std::unordered_map<uint64_t, size_t> trampoline_by_va;
    for (const PendingPatch &p : pending) {
        auto blk_it = block_by_va.find(p.target_va);
        size_t target_bc;
        if (blk_it != block_by_va.end()) {
            target_bc = blk_it->second;
        } else {
            auto tr_it = trampoline_by_va.find(p.target_va);
            if (tr_it != trampoline_by_va.end()) {
                target_bc = tr_it->second;
            } else {
                target_bc = out.size();
                out.vmexit_rel(static_cast<int64_t>(p.target_va - anchor_va));
                trampoline_by_va[p.target_va] = target_bc;
            }
        }
        out.patch_rel(p.operand_pos, target_bc);
    }
}

} // namespace

std::optional<LiftResult> try_lift(const uint8_t *code, size_t max_len, size_t min_bytes,
                                    uint64_t code_va, uint64_t anchor_va,
                                    const OpcodeMap &opcode_map)
{
    ZydisDecoder decoder;
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64))) {
        return std::nullopt;
    }

    BytecodeEmitter emitter(opcode_map);
    size_t offset = 0;

    std::mt19937_64 rng(std::random_device{}());

    // Mandatory straight-line entry prefix: no branches considered here at
    // all (see lifter.h) -- this exact loop is what try_lift always did
    // before branch/loop support existed, kept byte-for-byte so the OEP
    // patch's contiguous-overwrite guarantee never has to reason about
    // branches landing inside it.
    while (offset < min_bytes && offset < max_len) {
        ZydisDecodedInstruction insn;
        ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
        ZyanStatus status = ZydisDecoderDecodeFull(&decoder, code + offset, max_len - offset, &insn, ops);
        if (!ZYAN_SUCCESS(status)) return std::nullopt;
        if (!lift_one(insn, ops, code_va + offset, anchor_va, emitter)) return std::nullopt;
        offset += insn.length;

        int carrier = ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER ? reg_to_vreg(ops[0].reg.value) : -1;
        insert_obfuscation(emitter, carrier >= 0 ? static_cast<uint8_t>(carrier) : 0, rng);
    }

    if (offset < min_bytes) return std::nullopt; // ran out of buffer before reaching min_bytes

    const size_t prefix_len = offset;

    // What happens right after the prefix is just another edge, resolved
    // through the exact same deferred-patch pipeline as everything else
    // discovered below (see emit_program): if discovery finds a real block
    // starting exactly at prefix_len, this jump lands directly on it with
    // no extra indirection; if it doesn't (no branch anywhere in the probed
    // window -- the common case), it resolves to a single VOP_VMEXIT_REL,
    // functionally identical to what plain VOP_VMEXIT used to do here.
    const size_t prefix_jmp_pos = emitter.emit_jmp_placeholder();
    const PendingPatch prefix_patch{prefix_jmp_pos, code_va + prefix_len};

    DiscoverState st;
    st.max_len = max_len;
    st.code_va = code_va;
    st.reserved_prefix_len = prefix_len;
    st.owner.assign(max_len, -1);
    st.insn_boundary.assign(max_len, 0);
    discover_cfg(st, decoder, code, anchor_va, prefix_len);

    std::vector<LiftedBlock> blocks = split_runs(st.runs, st.forced_boundaries, code_va);
    emit_program(emitter, blocks, decoder, code, max_len, code_va, anchor_va, prefix_patch, rng);

    size_t max_probe_offset = prefix_len;
    for (const Run &run : st.runs) {
        if (!run.insns.empty()) max_probe_offset = std::max(max_probe_offset, run.insns.back().end_offset);
    }

    LiftResult result;
    result.bytecode = emitter.finalize();
    result.consumed_bytes = prefix_len;
    result.max_probe_offset = max_probe_offset;
    return result;
}

} // namespace karity
