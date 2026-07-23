#include "emitter.h"

#include <cstring>

namespace karity {

void BytecodeEmitter::byte(uint8_t b) { code_.push_back(b); }

void BytecodeEmitter::u64le(uint64_t v)
{
    for (int i = 0; i < 8; i++) code_.push_back(static_cast<uint8_t>(v >> (8 * i)));
}

void BytecodeEmitter::opcode(karity_vop op) { byte(map_.encode(op)); }

void BytecodeEmitter::push_imm(uint64_t imm)
{
    opcode(VOP_PUSH_IMM);
    u64le(imm);
}

void BytecodeEmitter::push_vreg(uint8_t idx)
{
    opcode(VOP_PUSH_VREG);
    byte(idx);
}

void BytecodeEmitter::pop_vreg(uint8_t idx)
{
    opcode(VOP_POP_VREG);
    byte(idx);
}

void BytecodeEmitter::push_rel(int64_t delta_from_anchor)
{
    opcode(VOP_PUSH_REL);
    u64le(static_cast<uint64_t>(delta_from_anchor));
}

void BytecodeEmitter::drop() { opcode(VOP_DROP); }

void BytecodeEmitter::op(karity_vop op_value)
{
    opcode(op_value);
}

void BytecodeEmitter::load(int size_bits)
{
    switch (size_bits) {
    case 8:  opcode(VOP_LOAD8);  break;
    case 16: opcode(VOP_LOAD16); break;
    case 32: opcode(VOP_LOAD32); break;
    default: opcode(VOP_LOAD64); break;
    }
}

void BytecodeEmitter::store(int size_bits)
{
    switch (size_bits) {
    case 8:  opcode(VOP_STORE8);  break;
    case 16: opcode(VOP_STORE16); break;
    case 32: opcode(VOP_STORE32); break;
    default: opcode(VOP_STORE64); break;
    }
}

void BytecodeEmitter::call(int64_t delta_from_anchor)
{
    opcode(VOP_CALL);
    u64le(static_cast<uint64_t>(delta_from_anchor));
}

void BytecodeEmitter::call_indirect() { opcode(VOP_CALL_IND); }

void BytecodeEmitter::nop() { opcode(VOP_NOP); }
void BytecodeEmitter::vmexit() { opcode(VOP_VMEXIT); }

void BytecodeEmitter::vmexit_rel(int64_t delta_from_anchor)
{
    opcode(VOP_VMEXIT_REL);
    u64le(static_cast<uint64_t>(delta_from_anchor));
}

void BytecodeEmitter::movzx(int src_size_bytes)
{
    opcode(VOP_MOVZX);
    byte(static_cast<uint8_t>(src_size_bytes));
}

void BytecodeEmitter::movsx(int src_size_bytes, int dst_size_bytes)
{
    opcode(VOP_MOVSX);
    byte(static_cast<uint8_t>(src_size_bytes));
    byte(static_cast<uint8_t>(dst_size_bytes));
}

void BytecodeEmitter::push_xreg(uint8_t idx)
{
    opcode(VOP_PUSH_XREG);
    byte(idx);
}

void BytecodeEmitter::pop_xreg(uint8_t idx)
{
    opcode(VOP_POP_XREG);
    byte(idx);
}

size_t BytecodeEmitter::emit_jmp_placeholder()
{
    opcode(VOP_JMP);
    size_t pos = code_.size();
    u64le(0);
    return pos;
}

size_t BytecodeEmitter::emit_jcc_nz_placeholder()
{
    opcode(VOP_JCC_NZ);
    size_t pos = code_.size();
    u64le(0);
    return pos;
}

size_t BytecodeEmitter::emit_jcc_placeholder(uint8_t cc)
{
    opcode(VOP_JCC);
    byte(cc);
    size_t pos = code_.size();
    u64le(0);
    return pos;
}

void BytecodeEmitter::patch_rel_to_here(size_t operand_pos) { patch_rel(operand_pos, code_.size()); }

void BytecodeEmitter::patch_rel(size_t operand_pos, size_t target_pos)
{
    int64_t rel = static_cast<int64_t>(target_pos) - static_cast<int64_t>(operand_pos + 8);
    uint64_t urel = static_cast<uint64_t>(rel);
    for (int i = 0; i < 8; i++) code_[operand_pos + i] = static_cast<uint8_t>(urel >> (8 * i));
}

std::vector<uint8_t> BytecodeEmitter::finalize(uint32_t entry_off) const
{
    karity_program_hdr hdr{};
    hdr.magic = KARITY_PROG_MAGIC;
    hdr.isa_ver = KARITY_ISA_VERSION;
    hdr.reserved = 0;
    hdr.code_size = static_cast<uint32_t>(code_.size());
    hdr.entry_off = entry_off;

    std::vector<uint8_t> out(sizeof(hdr) + code_.size());
    std::memcpy(out.data(), &hdr, sizeof(hdr));
    std::memcpy(out.data() + sizeof(hdr), code_.data(), code_.size());
    return out;
}

} // namespace karity
