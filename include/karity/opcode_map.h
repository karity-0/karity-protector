#ifndef KARITY_OPCODE_MAP_H
#define KARITY_OPCODE_MAP_H

#include <array>
#include <algorithm>
#include <cstdint>
#include <random>
#include <vector>

#include "karity/isa.h"

namespace karity {

// One entry per opcode that is actually emitted/dispatched anywhere in this
// VM -- every VOP_* in isa.h except the deliberately-skipped decoy-byte gaps
// (0x28/0x3E/0x44/0x47/0x4B, see isa.h). `label` is only meaningful to
// src/native/interp_codegen.cpp's hand-generated interpreter (its
// dispatch/handler label names); OpcodeMap below ignores it entirely. This
// table is the single source of truth for "the full set of real opcodes" --
// both interp_codegen.cpp's dispatch-table generator and OpcodeMap's
// per-protect randomization are built from exactly this array, so the two
// can never drift out of sync with isa.h or each other.
struct OpcodeTableEntry {
    karity_vop opcode;
    const char *label;
};

inline const std::vector<OpcodeTableEntry> &opcode_table()
{
    static const std::vector<OpcodeTableEntry> kOps = {
        {VOP_NOP, "op_nop"}, {VOP_VMEXIT, "op_vmexit"},
        {VOP_PUSH_IMM, "op_push_imm"}, {VOP_PUSH_VREG, "op_push_vreg"}, {VOP_POP_VREG, "op_pop_vreg"},
        {VOP_PUSH_REL, "op_push_rel"}, {VOP_DROP, "op_drop"},
        {VOP_ADD, "op_add"}, {VOP_SUB, "op_sub"}, {VOP_XOR, "op_xor"}, {VOP_AND, "op_and"}, {VOP_OR, "op_or"},
        {VOP_CMP, "op_cmp"}, {VOP_TEST, "op_test"}, {VOP_NEG, "op_neg"}, {VOP_NOT, "op_not"},
        {VOP_INC, "op_inc"}, {VOP_DEC, "op_dec"},
        {VOP_SHL, "op_shl"}, {VOP_SHR, "op_shr"}, {VOP_SAR, "op_sar"}, {VOP_ROL, "op_rol"}, {VOP_ROR, "op_ror"},
        {VOP_MUL, "op_mul"}, {VOP_IMUL1, "op_imul1"}, {VOP_IMUL2, "op_imul2"},
        {VOP_LOAD8, "op_load8"}, {VOP_LOAD16, "op_load16"}, {VOP_LOAD32, "op_load32"}, {VOP_LOAD64, "op_load64"},
        {VOP_STORE8, "op_store8"}, {VOP_STORE16, "op_store16"}, {VOP_STORE32, "op_store32"}, {VOP_STORE64, "op_store64"},
        {VOP_CALL, "op_call"}, {VOP_JMP, "op_jmp"}, {VOP_JCC_NZ, "op_jcc_nz"}, {VOP_JCC, "op_jcc"},
        {VOP_CALL_IND, "op_call_ind"}, {VOP_VMEXIT_REL, "op_vmexit_rel"}, {VOP_DIV, "op_div"}, {VOP_IDIV, "op_idiv"},
        {VOP_MOVZX, "op_movzx"}, {VOP_MOVSX, "op_movsx"},
        {VOP_PUSH_XREG, "op_push_xreg"}, {VOP_POP_XREG, "op_pop_xreg"},
        {VOP_ADDSD, "op_addsd"}, {VOP_SUBSD, "op_subsd"}, {VOP_MULSD, "op_mulsd"}, {VOP_DIVSD, "op_divsd"},
        {VOP_ADDSS, "op_addss"}, {VOP_SUBSS, "op_subss"}, {VOP_MULSS, "op_mulss"}, {VOP_DIVSS, "op_divss"},
        {VOP_CVTSI2SD, "op_cvtsi2sd"}, {VOP_CVTTSD2SI, "op_cvttsd2si"},
        {VOP_CVTSI2SS, "op_cvtsi2ss"}, {VOP_CVTTSS2SI, "op_cvttss2si"},
    };
    return kOps;
}

// Translates each semantic VOP_* value to a physical bytecode byte. The
// default (identity) mapping is what every hosted test and the portable
// reference interpreter (runtime/vm_interp.c, whose switch is keyed by the
// literal isa.h constants and is never regenerated per-protect) implicitly
// assume. The randomized constructor builds a fresh bijection -- same *set*
// of 58 byte values as isa.h (so bytecode size/shape is unaffected), just
// reassigned onto different VOP_* meanings -- seeded once per protect run
// (src/inject/injector.cpp) and shared between the bytecode emitter
// (src/vm/emitter.h, via BytecodeEmitter) and the generated interpreter's
// dispatch table (src/native/interp_codegen.cpp) so the two halves agree
// while a different protect run gets a different mapping: cracking which
// numeric opcode does what in one protected sample no longer tells you
// anything about another sample (see todo.md, section D).
class OpcodeMap {
public:
    OpcodeMap()
    {
        for (const auto &e : opcode_table()) to_physical_[static_cast<size_t>(e.opcode)] = static_cast<uint8_t>(e.opcode);
    }

    explicit OpcodeMap(std::mt19937_64 &rng) : OpcodeMap()
    {
        std::vector<uint8_t> physical;
        physical.reserve(opcode_table().size());
        for (const auto &e : opcode_table()) physical.push_back(static_cast<uint8_t>(e.opcode));
        std::shuffle(physical.begin(), physical.end(), rng);

        size_t i = 0;
        for (const auto &e : opcode_table()) to_physical_[static_cast<size_t>(e.opcode)] = physical[i++];
    }

    uint8_t encode(karity_vop op) const { return to_physical_[static_cast<size_t>(op)]; }

private:
    std::array<uint8_t, VOP__COUNT> to_physical_{};
};

} // namespace karity

#endif // KARITY_OPCODE_MAP_H
