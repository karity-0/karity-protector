#pragma once

#include <cstdint>
#include <vector>

#include "karity/isa.h"
#include "karity/opcode_map.h"

namespace karity {

// Builds a karity bytecode buffer opcode-by-opcode and prefixes it with
// karity_program_hdr on finalize().
class BytecodeEmitter {
public:
    BytecodeEmitter() = default;
    // Every opcode byte this emitter writes goes through `map` (default:
    // identity -- see opcode_map.h) so the resulting bytecode matches
    // whichever interpreter (reference or generated) was built against the
    // same map.
    explicit BytecodeEmitter(const OpcodeMap &map) : map_(map) {}

    void push_imm(uint64_t imm);
    void push_vreg(uint8_t idx);
    void pop_vreg(uint8_t idx);
    void push_rel(int64_t delta_from_anchor);
    void drop();
    void op(karity_vop opcode); // ADD/SUB/XOR/AND/OR/CMP/TEST
    void load(int size_bits);   // 8/16/32/64
    void store(int size_bits);  // 8/16/32/64
    void call(int64_t delta_from_anchor);
    void call_indirect(); // target address is already on top of the vstack
    void nop();
    void vmexit();
    void vmexit_rel(int64_t delta_from_anchor); // VOP_VMEXIT_REL
    void movzx(int src_size_bytes);                       // VOP_MOVZX: src_size is 1 or 2
    void movsx(int src_size_bytes, int dst_size_bytes);    // VOP_MOVSX: src_size is 1/2/4, dst_size is 4 or 8
    void push_xreg(uint8_t idx); // VOP_PUSH_XREG: xreg[idx] (0..KARITY_XREG_COUNT-1) -> vstack
    void pop_xreg(uint8_t idx);  // VOP_POP_XREG: vstack -> xreg[idx]

    // Two-pass forward jump support: emit a placeholder branch (operand
    // bytes are zero), keep building the block it should skip, then patch
    // once the skip distance is known. Returns the byte offset of the
    // (still-zero) i64 rel operand.
    size_t emit_jmp_placeholder();
    size_t emit_jcc_nz_placeholder();
    // Same as emit_jcc_nz_placeholder, but flags-driven: branches if
    // ctx->vflags satisfies cc (a KARITY_CC_* value) instead of popping a
    // stack condition.
    size_t emit_jcc_placeholder(uint8_t cc);
    void patch_rel_to_here(size_t operand_pos);
    // General form of patch_rel_to_here for a target that isn't necessarily
    // "wherever the emitter is right now" -- e.g. a CFG block emitted
    // earlier (a backward/loop edge). target_pos must be a valid position
    // already written into code_ (typically a label recorded via size()
    // at the start of some earlier emit_*).
    void patch_rel(size_t operand_pos, size_t target_pos);

    // Prefixes the accumulated opcodes with a karity_program_hdr and returns
    // the full blob. entry_off is relative to the end of the header (0 for
    // a program with no preamble).
    std::vector<uint8_t> finalize(uint32_t entry_off = 0) const;

    size_t size() const { return code_.size(); }

private:
    void byte(uint8_t b);
    void u64le(uint64_t v);
    void opcode(karity_vop op); // writes map_.encode(op) -- use for opcode bytes only, never operands

    std::vector<uint8_t> code_;
    OpcodeMap map_;
};

} // namespace karity
