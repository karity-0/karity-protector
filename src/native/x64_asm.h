#pragma once

#include <cstdint>
#include <vector>

namespace karity {

// A small, deliberately narrow x86-64 instruction encoder: just enough
// instructions, in just enough addressing-mode variants, to hand-generate
// the VM interpreter's dispatch loop and opcode handlers at protect time
// (see interp_codegen.h). Every register is passed as its plain 0-15
// encoding (RAX=0 .. R15=15); callers never write raw opcode/REX/ModRM
// bytes themselves.
//
// Deliberately avoids R12 and R13 as memory-operand *base* registers: R12's
// low 3 bits alias RSP's encoding (forces a SIB byte) and R13's alias RBP's
// (forces an explicit disp8 even for zero displacement) -- both are real
// gotchas, so interp_codegen.h's register assignment steers clear of them
// entirely rather than handling the special cases here.

namespace x64 {

void push_reg(std::vector<uint8_t> &out, int reg);
void pop_reg(std::vector<uint8_t> &out, int reg);

void mov_reg_imm64(std::vector<uint8_t> &out, int reg, uint64_t imm);   // movabs reg, imm64
void mov_reg_imm32(std::vector<uint8_t> &out, int reg, uint32_t imm);   // mov reg32, imm32 (zero-extends to 64)

void mov_reg_reg(std::vector<uint8_t> &out, int dst, int src);          // mov dst64, src64

// Memory operand = [base + disp32] (disp32 may be 0; encoded compactly
// when it fits in disp8). `base` must not be RSP/R12 or RBP/R13.
void mov_reg_mem64(std::vector<uint8_t> &out, int dst, int base, int32_t disp);   // dst = *(u64*)(base+disp)
void mov_reg_mem32(std::vector<uint8_t> &out, int dst, int base, int32_t disp);   // dst = *(u32*)(base+disp), zero-extended
void movzx_reg_mem16(std::vector<uint8_t> &out, int dst, int base, int32_t disp); // dst = *(u16*)(base+disp), zero-extended
void movzx_reg_mem8(std::vector<uint8_t> &out, int dst, int base, int32_t disp);  // dst = *(u8*)(base+disp), zero-extended

void mov_mem64_reg(std::vector<uint8_t> &out, int base, int32_t disp, int src);   // *(u64*)(base+disp) = src
void mov_mem32_reg(std::vector<uint8_t> &out, int base, int32_t disp, int src);   // *(u32*)(base+disp) = src (low 32 bits)
void mov_mem16_reg(std::vector<uint8_t> &out, int base, int32_t disp, int src);   // *(u16*)(base+disp) = src (low 16 bits)
void mov_mem8_reg(std::vector<uint8_t> &out, int base, int32_t disp, int src);    // *(u8*)(base+disp)  = src (low 8 bits)

enum class AluOp { Add, Or, Adc, Sbb, And, Sub, Xor, Cmp };

void alu_reg_reg(std::vector<uint8_t> &out, AluOp op, int dst, int src);              // dst = dst OP src
void alu_reg_imm32(std::vector<uint8_t> &out, AluOp op, int reg, uint32_t imm);       // reg = reg OP sext32(imm)
void alu_mem64_reg(std::vector<uint8_t> &out, AluOp op, int base, int32_t disp, int src); // *(u64*)(base+disp) OP= src

void not_reg(std::vector<uint8_t> &out, int reg);
void neg_reg(std::vector<uint8_t> &out, int reg);
void inc_reg(std::vector<uint8_t> &out, int reg);
void dec_reg(std::vector<uint8_t> &out, int reg);
void shl_reg_imm8(std::vector<uint8_t> &out, int reg, uint8_t imm);
void shr_reg_imm8(std::vector<uint8_t> &out, int reg, uint8_t imm);

// Shift/rotate by CL (the only register real x86 allows as a *variable*
// shift/rotate count) -- used to lift VOP_SHL/SHR/SAR/ROL/ROR, whose count
// is a runtime vstack value rather than a lift-time-known immediate.
void shl_reg_cl(std::vector<uint8_t> &out, int reg);
void shr_reg_cl(std::vector<uint8_t> &out, int reg);
void sar_reg_cl(std::vector<uint8_t> &out, int reg);
void rol_reg_cl(std::vector<uint8_t> &out, int reg);
void ror_reg_cl(std::vector<uint8_t> &out, int reg);

// Group-3 (0xF7 /digit) one-operand forms: implicit RDX:RAX operand(s),
// exactly like the native instructions they encode.
void mul_reg(std::vector<uint8_t> &out, int reg);  // RDX:RAX = RAX * reg (unsigned)
void imul_reg(std::vector<uint8_t> &out, int reg); // RDX:RAX = RAX * reg (signed)
void div_reg(std::vector<uint8_t> &out, int reg);  // RAX = RDX:RAX / reg, RDX = remainder (unsigned)
void idiv_reg(std::vector<uint8_t> &out, int reg); // same, signed

// Two-operand signed multiply (0F AF /r): dst = dst * src, truncated to 64
// bits; RDX/high64 untouched, unlike the one-operand forms above.
void imul_reg_reg(std::vector<uint8_t> &out, int dst, int src);

void test_reg_reg(std::vector<uint8_t> &out, int a, int b);
void test_mem64_reg(std::vector<uint8_t> &out, int base, int32_t disp, int src); // sets flags from *(base+disp) & src, no writeback
void cmp_reg_imm32(std::vector<uint8_t> &out, int reg, uint32_t imm);

// RFLAGS capture: pushfq then pop_reg(out, dst) reads it into a GPR.
void pushfq(std::vector<uint8_t> &out);
void popfq(std::vector<uint8_t> &out);

// Two-pass forward/backward branches: emit returns the offset of the (as-
// yet zero) rel32 operand; patch_rel32 fills it in once the target offset
// (an absolute index into the same buffer) is known.
size_t jmp_rel32(std::vector<uint8_t> &out);
size_t je_rel32(std::vector<uint8_t> &out);
size_t jne_rel32(std::vector<uint8_t> &out);
// Unsigned "below" (CF=1) -- used only by the vstack overflow guard's
// pointer comparison (interp_codegen.cpp), where signedness matters:
// vsp/vstack_limit are addresses, not signed quantities.
size_t jb_rel32(std::vector<uint8_t> &out);
void patch_rel32(std::vector<uint8_t> &out, size_t operand_pos, size_t target_pos);

void call_reg(std::vector<uint8_t> &out, int reg);
void ret(std::vector<uint8_t> &out);

// Deliberately-illegal opcode (raises SIGILL/EXCEPTION_ILLEGAL_INSTRUCTION
// immediately, at this exact point) -- the vstack overflow guard's fail-
// closed response (see interp_codegen.cpp and vm_thunk.S's header).
void ud2(std::vector<uint8_t> &out);

// Emits `call rel32=0` -- the target is the very next instruction, so this
// falls straight through rather than actually branching anywhere. It's the
// classic position-independent-code idiom: a `pop reg` immediately
// afterward captures the live, always-correct runtime address of that pop
// instruction itself, with no baked absolute VA and no PE relocation entry
// required (the same reasoning that makes a plain `call rel32` to a fixed
// in-image target ASLR-safe). Returns the buffer offset of the instruction
// immediately following (i.e. the offset that ends up in the popped
// register, relative to wherever this buffer is ultimately placed).
size_t call_rel32_self(std::vector<uint8_t> &out);

// Scalar SSE/SSE2, just enough to hand-generate VOP_ADDSD/.../VOP_CVTTSS2SI
// (see interp_codegen.cpp): every xmm register is passed as its plain 0-15
// encoding (XMM0=0..XMM15=15), same convention as the GPR functions above.
// No memory-operand arithmetic forms -- interp_codegen.cpp always round-
// trips a vstack slot through a fixed scratch xmm register instead (see its
// case 0x52-0x5D), so only reg<->mem moves and reg<->reg arithmetic/convert
// are needed here.

// xmm = *(u64*)(base+disp), zero-extending the upper 64 bits of xmm (matches
// native MOVQ xmm1, xmm2/m64 semantics).
void movq_xmm_mem64(std::vector<uint8_t> &out, int xmm, int base, int32_t disp);
// *(u64*)(base+disp) = low64(xmm) (native MOVQ xmm2/m64, xmm1).
void movq_mem64_xmm(std::vector<uint8_t> &out, int base, int32_t disp, int xmm);
// *(u32*)(base+disp) = low32(xmm) (native MOVD r/m32, xmm).
void movd_mem32_xmm(std::vector<uint8_t> &out, int base, int32_t disp, int xmm);

enum class SseOp { Add, Sub, Mul, Div };

// dst_xmm = dst_xmm OP src_xmm, scalar double precision (F2 0F .. /r).
void sse_arith_sd_reg_reg(std::vector<uint8_t> &out, SseOp op, int dst_xmm, int src_xmm);
// Same, scalar single precision (F3 0F .. /r).
void sse_arith_ss_reg_reg(std::vector<uint8_t> &out, SseOp op, int dst_xmm, int src_xmm);

// dst_xmm = (double)(int64_t)src_gpr / (float)(int64_t)src_gpr -- REX.W
// forced, always the 64-bit-integer-source form.
void cvtsi2sd_reg_reg(std::vector<uint8_t> &out, int dst_xmm, int src_gpr);
void cvtsi2ss_reg_reg(std::vector<uint8_t> &out, int dst_xmm, int src_gpr);
// dst_gpr = (int64_t)(double)src_xmm / (int64_t)(float)src_xmm, truncating --
// REX.W forced, always the 64-bit-integer-destination form.
void cvttsd2si_reg_reg(std::vector<uint8_t> &out, int dst_gpr, int src_xmm);
void cvttss2si_reg_reg(std::vector<uint8_t> &out, int dst_gpr, int src_xmm);

} // namespace x64
} // namespace karity
