#include "x64_asm.h"

namespace karity {
namespace x64 {

namespace {

void emit_u32le(std::vector<uint8_t> &out, uint32_t v)
{
    for (int i = 0; i < 4; i++) out.push_back(static_cast<uint8_t>(v >> (8 * i)));
}

void emit_u64le(std::vector<uint8_t> &out, uint64_t v)
{
    for (int i = 0; i < 8; i++) out.push_back(static_cast<uint8_t>(v >> (8 * i)));
}

uint8_t rex(bool w, bool r, bool x, bool b)
{
    return static_cast<uint8_t>(0x40 | (w ? 8 : 0) | (r ? 4 : 0) | (x ? 2 : 0) | (b ? 1 : 0));
}

uint8_t modrm(int mod, int reg, int rm) { return static_cast<uint8_t>((mod << 6) | ((reg & 7) << 3) | (rm & 7)); }

// Encodes the ModRM(+SIB)(+disp) for `[base + disp]` with `reg_field` in
// ModRM.reg (the other operand -- a register, or an opcode-extension digit
// for group-1/group-2 instructions). Defensively handles RSP/R12 (needs a
// SIB byte) and RBP/R13 (can't use mod=00) even though interp_codegen.h's
// register assignment never actually exercises either case.
void emit_mem_operand(std::vector<uint8_t> &out, int reg_field, int base, int32_t disp)
{
    const int base_low = base & 7;
    const bool need_sib = base_low == 4;   // RSP/R12
    const bool force_disp8 = base_low == 5 && disp == 0; // RBP/R13, can't use mod=00

    int mod;
    if (disp == 0 && !force_disp8) mod = 0;
    else if (disp >= -128 && disp <= 127) mod = 1;
    else mod = 2;

    out.push_back(modrm(mod, reg_field, need_sib ? 4 : base_low));
    if (need_sib) out.push_back(0x24); // scale=0, index=none, base=RSP/R12

    if (mod == 1) out.push_back(static_cast<uint8_t>(disp));
    else if (mod == 2) emit_u32le(out, static_cast<uint32_t>(disp));
}

int alu_opcode_reg_form(AluOp op) { return 0x01 + static_cast<int>(op) * 8; }

// Shared helper for every two-byte-opcode (0F ..) SSE instruction below,
// register-register form (mod=3). `mandatory_prefix` is always one of
// 0x66/0xF2/0xF3 here -- every SSE opcode this file encodes needs one, so
// unlike the plain GPR helpers above there's no "no prefix" case to skip.
// `reg_field`/`rm_field` follow the same reg=dst-or-src-per-opcode
// convention as the plain GPR helpers above: callers pick the order to
// match what each specific opcode's Intel encoding actually wants.
void emit_sse_2byte_reg_reg(std::vector<uint8_t> &out, uint8_t mandatory_prefix, bool rexw,
                             int reg_field, int rm_field, uint8_t opcode2)
{
    out.push_back(mandatory_prefix);
    if (rexw || reg_field >= 8 || rm_field >= 8) out.push_back(rex(rexw, reg_field >= 8, false, rm_field >= 8));
    out.push_back(0x0F);
    out.push_back(opcode2);
    out.push_back(modrm(3, reg_field, rm_field));
}

// Same, but the non-register operand is `[base+disp]` instead of a second
// register (reuses emit_mem_operand, exactly like the plain GPR mem
// functions above).
void emit_sse_2byte_reg_mem(std::vector<uint8_t> &out, uint8_t mandatory_prefix, bool rexw,
                             int reg_field, int base, int32_t disp, uint8_t opcode2)
{
    out.push_back(mandatory_prefix);
    if (rexw || reg_field >= 8 || base >= 8) out.push_back(rex(rexw, reg_field >= 8, false, base >= 8));
    out.push_back(0x0F);
    out.push_back(opcode2);
    emit_mem_operand(out, reg_field, base, disp);
}

uint8_t sse_arith_opcode2(SseOp op)
{
    switch (op) {
    case SseOp::Add: return 0x58;
    case SseOp::Sub: return 0x5C;
    case SseOp::Mul: return 0x59;
    case SseOp::Div: return 0x5E;
    }
    return 0x58;
}

} // namespace

void push_reg(std::vector<uint8_t> &out, int reg)
{
    if (reg >= 8) out.push_back(rex(false, false, false, true));
    out.push_back(static_cast<uint8_t>(0x50 + (reg & 7)));
}

void pop_reg(std::vector<uint8_t> &out, int reg)
{
    if (reg >= 8) out.push_back(rex(false, false, false, true));
    out.push_back(static_cast<uint8_t>(0x58 + (reg & 7)));
}

void mov_reg_imm64(std::vector<uint8_t> &out, int reg, uint64_t imm)
{
    out.push_back(rex(true, false, false, reg >= 8));
    out.push_back(static_cast<uint8_t>(0xB8 + (reg & 7)));
    emit_u64le(out, imm);
}

void mov_reg_imm32(std::vector<uint8_t> &out, int reg, uint32_t imm)
{
    if (reg >= 8) out.push_back(rex(false, false, false, true));
    out.push_back(static_cast<uint8_t>(0xB8 + (reg & 7)));
    emit_u32le(out, imm);
}

void mov_reg_reg(std::vector<uint8_t> &out, int dst, int src)
{
    out.push_back(rex(true, src >= 8, false, dst >= 8));
    out.push_back(0x89);
    out.push_back(modrm(3, src, dst));
}

void mov_reg_mem64(std::vector<uint8_t> &out, int dst, int base, int32_t disp)
{
    out.push_back(rex(true, dst >= 8, false, base >= 8));
    out.push_back(0x8B);
    emit_mem_operand(out, dst, base, disp);
}

void mov_reg_mem32(std::vector<uint8_t> &out, int dst, int base, int32_t disp)
{
    if (dst >= 8 || base >= 8) out.push_back(rex(false, dst >= 8, false, base >= 8));
    out.push_back(0x8B);
    emit_mem_operand(out, dst, base, disp);
}

void movzx_reg_mem16(std::vector<uint8_t> &out, int dst, int base, int32_t disp)
{
    out.push_back(rex(true, dst >= 8, false, base >= 8));
    out.push_back(0x0F);
    out.push_back(0xB7);
    emit_mem_operand(out, dst, base, disp);
}

void movzx_reg_mem8(std::vector<uint8_t> &out, int dst, int base, int32_t disp)
{
    out.push_back(rex(true, dst >= 8, false, base >= 8));
    out.push_back(0x0F);
    out.push_back(0xB6);
    emit_mem_operand(out, dst, base, disp);
}

void mov_mem64_reg(std::vector<uint8_t> &out, int base, int32_t disp, int src)
{
    out.push_back(rex(true, src >= 8, false, base >= 8));
    out.push_back(0x89);
    emit_mem_operand(out, src, base, disp);
}

void mov_mem32_reg(std::vector<uint8_t> &out, int base, int32_t disp, int src)
{
    if (src >= 8 || base >= 8) out.push_back(rex(false, src >= 8, false, base >= 8));
    out.push_back(0x89);
    emit_mem_operand(out, src, base, disp);
}

void mov_mem16_reg(std::vector<uint8_t> &out, int base, int32_t disp, int src)
{
    out.push_back(0x66); // operand-size override
    if (src >= 8 || base >= 8) out.push_back(rex(false, src >= 8, false, base >= 8));
    out.push_back(0x89);
    emit_mem_operand(out, src, base, disp);
}

void mov_mem8_reg(std::vector<uint8_t> &out, int base, int32_t disp, int src)
{
    // A REX prefix is mandatory here even when no bit is set: without one,
    // register encodings 4-7 in an 8-bit operand mean AH/CH/DH/BH, not the
    // low byte of RSP/RBP/RSI/RDI. Any REX byte (even 0x40) switches to the
    // SIL/DIL/BPL/SPL interpretation.
    out.push_back(rex(false, src >= 8, false, base >= 8));
    out.push_back(0x88);
    emit_mem_operand(out, src, base, disp);
}

void alu_reg_reg(std::vector<uint8_t> &out, AluOp op, int dst, int src)
{
    out.push_back(rex(true, src >= 8, false, dst >= 8));
    out.push_back(static_cast<uint8_t>(alu_opcode_reg_form(op)));
    out.push_back(modrm(3, src, dst));
}

void alu_reg_imm32(std::vector<uint8_t> &out, AluOp op, int reg, uint32_t imm)
{
    out.push_back(rex(true, false, false, reg >= 8));
    out.push_back(0x81);
    out.push_back(modrm(3, static_cast<int>(op), reg));
    emit_u32le(out, imm);
}

void alu_mem64_reg(std::vector<uint8_t> &out, AluOp op, int base, int32_t disp, int src)
{
    out.push_back(rex(true, src >= 8, false, base >= 8));
    out.push_back(static_cast<uint8_t>(alu_opcode_reg_form(op)));
    emit_mem_operand(out, src, base, disp);
}

void not_reg(std::vector<uint8_t> &out, int reg)
{
    out.push_back(rex(true, false, false, reg >= 8));
    out.push_back(0xF7);
    out.push_back(modrm(3, 2, reg));
}

void neg_reg(std::vector<uint8_t> &out, int reg)
{
    out.push_back(rex(true, false, false, reg >= 8));
    out.push_back(0xF7);
    out.push_back(modrm(3, 3, reg));
}

void inc_reg(std::vector<uint8_t> &out, int reg)
{
    out.push_back(rex(true, false, false, reg >= 8));
    out.push_back(0xFF);
    out.push_back(modrm(3, 0, reg));
}

void dec_reg(std::vector<uint8_t> &out, int reg)
{
    out.push_back(rex(true, false, false, reg >= 8));
    out.push_back(0xFF);
    out.push_back(modrm(3, 1, reg));
}

void shl_reg_imm8(std::vector<uint8_t> &out, int reg, uint8_t imm)
{
    out.push_back(rex(true, false, false, reg >= 8));
    out.push_back(0xC1);
    out.push_back(modrm(3, 4, reg));
    out.push_back(imm);
}

void shr_reg_imm8(std::vector<uint8_t> &out, int reg, uint8_t imm)
{
    out.push_back(rex(true, false, false, reg >= 8));
    out.push_back(0xC1);
    out.push_back(modrm(3, 5, reg));
    out.push_back(imm);
}

// Group-2 shift/rotate by CL: REX.W + 0xD3 /digit (digit selects the
// operation: 0=ROL, 1=ROR, 4=SHL, 5=SHR, 7=SAR -- 2/3/6 are RCL/RCR/SAL-
// alias, unused here).
void shl_reg_cl(std::vector<uint8_t> &out, int reg)
{
    out.push_back(rex(true, false, false, reg >= 8));
    out.push_back(0xD3);
    out.push_back(modrm(3, 4, reg));
}

void shr_reg_cl(std::vector<uint8_t> &out, int reg)
{
    out.push_back(rex(true, false, false, reg >= 8));
    out.push_back(0xD3);
    out.push_back(modrm(3, 5, reg));
}

void sar_reg_cl(std::vector<uint8_t> &out, int reg)
{
    out.push_back(rex(true, false, false, reg >= 8));
    out.push_back(0xD3);
    out.push_back(modrm(3, 7, reg));
}

void rol_reg_cl(std::vector<uint8_t> &out, int reg)
{
    out.push_back(rex(true, false, false, reg >= 8));
    out.push_back(0xD3);
    out.push_back(modrm(3, 0, reg));
}

void ror_reg_cl(std::vector<uint8_t> &out, int reg)
{
    out.push_back(rex(true, false, false, reg >= 8));
    out.push_back(0xD3);
    out.push_back(modrm(3, 1, reg));
}

void mul_reg(std::vector<uint8_t> &out, int reg)
{
    out.push_back(rex(true, false, false, reg >= 8));
    out.push_back(0xF7);
    out.push_back(modrm(3, 4, reg));
}

void imul_reg(std::vector<uint8_t> &out, int reg)
{
    out.push_back(rex(true, false, false, reg >= 8));
    out.push_back(0xF7);
    out.push_back(modrm(3, 5, reg));
}

void div_reg(std::vector<uint8_t> &out, int reg)
{
    out.push_back(rex(true, false, false, reg >= 8));
    out.push_back(0xF7);
    out.push_back(modrm(3, 6, reg));
}

void idiv_reg(std::vector<uint8_t> &out, int reg)
{
    out.push_back(rex(true, false, false, reg >= 8));
    out.push_back(0xF7);
    out.push_back(modrm(3, 7, reg));
}

void imul_reg_reg(std::vector<uint8_t> &out, int dst, int src)
{
    out.push_back(rex(true, dst >= 8, false, src >= 8));
    out.push_back(0x0F);
    out.push_back(0xAF);
    out.push_back(modrm(3, dst, src));
}

void test_reg_reg(std::vector<uint8_t> &out, int a, int b)
{
    out.push_back(rex(true, b >= 8, false, a >= 8));
    out.push_back(0x85);
    out.push_back(modrm(3, b, a));
}

void test_mem64_reg(std::vector<uint8_t> &out, int base, int32_t disp, int src)
{
    out.push_back(rex(true, src >= 8, false, base >= 8));
    out.push_back(0x85);
    emit_mem_operand(out, src, base, disp);
}

void cmp_reg_imm32(std::vector<uint8_t> &out, int reg, uint32_t imm)
{
    alu_reg_imm32(out, AluOp::Cmp, reg, imm);
}

void pushfq(std::vector<uint8_t> &out)
{
    out.push_back(0x9C);
}

void popfq(std::vector<uint8_t> &out)
{
    out.push_back(0x9D);
}

size_t jmp_rel32(std::vector<uint8_t> &out)
{
    out.push_back(0xE9);
    size_t pos = out.size();
    emit_u32le(out, 0);
    return pos;
}

size_t je_rel32(std::vector<uint8_t> &out)
{
    out.push_back(0x0F);
    out.push_back(0x84);
    size_t pos = out.size();
    emit_u32le(out, 0);
    return pos;
}

size_t jne_rel32(std::vector<uint8_t> &out)
{
    out.push_back(0x0F);
    out.push_back(0x85);
    size_t pos = out.size();
    emit_u32le(out, 0);
    return pos;
}

size_t jb_rel32(std::vector<uint8_t> &out)
{
    out.push_back(0x0F);
    out.push_back(0x82);
    size_t pos = out.size();
    emit_u32le(out, 0);
    return pos;
}

size_t call_rel32_self(std::vector<uint8_t> &out)
{
    out.push_back(0xE8);
    emit_u32le(out, 0);
    return out.size();
}

void patch_rel32(std::vector<uint8_t> &out, size_t operand_pos, size_t target_pos)
{
    int32_t rel = static_cast<int32_t>(static_cast<int64_t>(target_pos) - static_cast<int64_t>(operand_pos + 4));
    uint32_t urel = static_cast<uint32_t>(rel);
    for (int i = 0; i < 4; i++) out[operand_pos + i] = static_cast<uint8_t>(urel >> (8 * i));
}

void call_reg(std::vector<uint8_t> &out, int reg)
{
    if (reg >= 8) out.push_back(rex(false, false, false, true));
    out.push_back(0xFF);
    out.push_back(modrm(3, 2, reg));
}

void ret(std::vector<uint8_t> &out)
{
    out.push_back(0xC3);
}

void ud2(std::vector<uint8_t> &out)
{
    out.push_back(0x0F);
    out.push_back(0x0B);
}

void movq_xmm_mem64(std::vector<uint8_t> &out, int xmm, int base, int32_t disp)
{
    emit_sse_2byte_reg_mem(out, 0xF3, false, xmm, base, disp, 0x7E); // MOVQ xmm1, xmm2/m64
}

void movq_mem64_xmm(std::vector<uint8_t> &out, int base, int32_t disp, int xmm)
{
    emit_sse_2byte_reg_mem(out, 0x66, false, xmm, base, disp, 0xD6); // MOVQ xmm2/m64, xmm1
}

void movd_mem32_xmm(std::vector<uint8_t> &out, int base, int32_t disp, int xmm)
{
    emit_sse_2byte_reg_mem(out, 0x66, false, xmm, base, disp, 0x7E); // MOVD r/m32, xmm (no REX.W)
}

void sse_arith_sd_reg_reg(std::vector<uint8_t> &out, SseOp op, int dst_xmm, int src_xmm)
{
    emit_sse_2byte_reg_reg(out, 0xF2, false, dst_xmm, src_xmm, sse_arith_opcode2(op));
}

void sse_arith_ss_reg_reg(std::vector<uint8_t> &out, SseOp op, int dst_xmm, int src_xmm)
{
    emit_sse_2byte_reg_reg(out, 0xF3, false, dst_xmm, src_xmm, sse_arith_opcode2(op));
}

void cvtsi2sd_reg_reg(std::vector<uint8_t> &out, int dst_xmm, int src_gpr)
{
    emit_sse_2byte_reg_reg(out, 0xF2, true, dst_xmm, src_gpr, 0x2A);
}

void cvtsi2ss_reg_reg(std::vector<uint8_t> &out, int dst_xmm, int src_gpr)
{
    emit_sse_2byte_reg_reg(out, 0xF3, true, dst_xmm, src_gpr, 0x2A);
}

void cvttsd2si_reg_reg(std::vector<uint8_t> &out, int dst_gpr, int src_xmm)
{
    emit_sse_2byte_reg_reg(out, 0xF2, true, dst_gpr, src_xmm, 0x2C);
}

void cvttss2si_reg_reg(std::vector<uint8_t> &out, int dst_gpr, int src_xmm)
{
    emit_sse_2byte_reg_reg(out, 0xF3, true, dst_gpr, src_xmm, 0x2C);
}

} // namespace x64
} // namespace karity
