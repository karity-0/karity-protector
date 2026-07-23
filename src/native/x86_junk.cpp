#include "x86_junk.h"

namespace karity {

namespace {

// Scratch register pool for junk: RAX, RCX, RDX, RBX, RSI, RDI (encoding
// 0,1,2,3,6,7). RSP/RBP are deliberately excluded -- no amount of
// push/pop bracketing around stack-pointer arithmetic is worth the risk.
constexpr int kRegPool[] = {0, 1, 2, 3, 6, 7};
constexpr int kRegPoolSize = 6;

void emit_u32le(std::vector<uint8_t> &out, uint32_t v)
{
    for (int i = 0; i < 4; i++) out.push_back(static_cast<uint8_t>(v >> (8 * i)));
}

uint8_t modrm11(int digit, int reg) { return static_cast<uint8_t>(0xC0 | (digit << 3) | reg); }

void push_reg(std::vector<uint8_t> &out, int reg) { out.push_back(static_cast<uint8_t>(0x50 + reg)); }
void pop_reg(std::vector<uint8_t> &out, int reg) { out.push_back(static_cast<uint8_t>(0x58 + reg)); }

void mov_reg_imm32(std::vector<uint8_t> &out, int reg, uint32_t imm)
{
    out.push_back(static_cast<uint8_t>(0xB8 + reg));
    emit_u32le(out, imm);
}

// ADD/OR/AND/SUB/XOR reg32, imm32 (group-1 opcode 0x81, /digit selects op)
void arith_reg_imm32(std::vector<uint8_t> &out, int digit, int reg, uint32_t imm)
{
    out.push_back(0x81);
    out.push_back(modrm11(digit, reg));
    emit_u32le(out, imm);
}

void not_reg(std::vector<uint8_t> &out, int reg) { out.push_back(0xF7); out.push_back(modrm11(2, reg)); }
void neg_reg(std::vector<uint8_t> &out, int reg) { out.push_back(0xF7); out.push_back(modrm11(3, reg)); }
void inc_reg(std::vector<uint8_t> &out, int reg) { out.push_back(0xFF); out.push_back(modrm11(0, reg)); }
void dec_reg(std::vector<uint8_t> &out, int reg) { out.push_back(0xFF); out.push_back(modrm11(1, reg)); }

// ROL/SHL/SHR reg32, imm8 (group-2 opcode 0xC1, /digit selects op)
void shift_reg_imm8(std::vector<uint8_t> &out, int digit, int reg, uint8_t imm8)
{
    out.push_back(0xC1);
    out.push_back(modrm11(digit, reg));
    out.push_back(imm8);
}

void test_reg_self(std::vector<uint8_t> &out, int reg)
{
    out.push_back(0x85);
    out.push_back(modrm11(reg, reg));
}

// One register's worth of junk arithmetic: push it, scribble on it with a
// random chain of ops, pop it back. Whatever ends up in the register when
// popped is discarded by construction -- the point is the *instructions*,
// not their result.
void emit_junk_on_one_register(std::vector<uint8_t> &out, std::mt19937_64 &rng)
{
    std::uniform_int_distribution<int> reg_dist(0, kRegPoolSize - 1);
    std::uniform_int_distribution<uint32_t> imm_dist(0, UINT32_MAX);
    std::uniform_int_distribution<int> rounds_dist(2, 6);
    std::uniform_int_distribution<int> op_dist(0, 10);
    std::uniform_int_distribution<int> shift_dist(1, 31);

    int reg = kRegPool[reg_dist(rng)];
    push_reg(out, reg);
    mov_reg_imm32(out, reg, imm_dist(rng));

    int rounds = rounds_dist(rng);
    for (int i = 0; i < rounds; i++) {
        switch (op_dist(rng)) {
        case 0: arith_reg_imm32(out, 0, reg, imm_dist(rng)); break; // add
        case 1: arith_reg_imm32(out, 4, reg, imm_dist(rng)); break; // and
        case 2: arith_reg_imm32(out, 5, reg, imm_dist(rng)); break; // sub
        case 3: arith_reg_imm32(out, 6, reg, imm_dist(rng)); break; // xor
        case 4: arith_reg_imm32(out, 1, reg, imm_dist(rng)); break; // or
        case 5: not_reg(out, reg); break;
        case 6: neg_reg(out, reg); break;
        case 7: inc_reg(out, reg); break;
        case 8: dec_reg(out, reg); break;
        case 9: shift_reg_imm8(out, 4, reg, static_cast<uint8_t>(shift_dist(rng))); break; // shl
        default: shift_reg_imm8(out, 5, reg, static_cast<uint8_t>(shift_dist(rng))); break; // shr
        }
    }

    pop_reg(out, reg);
}

} // namespace

void emit_native_junk(std::vector<uint8_t> &out, std::mt19937_64 &rng)
{
    std::uniform_int_distribution<int> reg_count_dist(1, 3);
    out.push_back(0x9C); // pushfq
    int n = reg_count_dist(rng);
    for (int i = 0; i < n; i++) emit_junk_on_one_register(out, rng);
    out.push_back(0x9D); // popfq
}

void emit_native_opaque_predicate(std::vector<uint8_t> &out, std::mt19937_64 &rng, int max_nest_depth)
{
    std::uniform_int_distribution<int> reg_dist(0, kRegPoolSize - 1);
    std::uniform_int_distribution<int> variant_dist(0, 1);
    std::uniform_int_distribution<int> dead_rounds_dist(1, 3);
    std::uniform_int_distribution<int> nest_dist(0, 1);

    int reg = kRegPool[reg_dist(rng)];

    out.push_back(0x9C); // pushfq
    push_reg(out, reg);

    // (carrier | 1) & 1, or (carrier & 1) | 1 -- both always evaluate to 1
    // regardless of the live value push_reg just saved a copy of.
    if (variant_dist(rng) == 0) {
        arith_reg_imm32(out, 1, reg, 1); // or reg, 1
        arith_reg_imm32(out, 4, reg, 1); // and reg, 1
    } else {
        arith_reg_imm32(out, 4, reg, 1); // and reg, 1
        arith_reg_imm32(out, 1, reg, 1); // or reg, 1
    }
    test_reg_self(out, reg);
    out.push_back(0x0F); out.push_back(0x85); // jnz rel32 (always taken)
    size_t rel_pos = out.size();
    emit_u32le(out, 0); // placeholder

    // dead branch: never reached, but may itself contain another opaque
    // predicate (bounded depth, so this can't recurse forever) so a
    // reverse engineer tracing "just in case" finds another one waiting.
    int dead_rounds = dead_rounds_dist(rng);
    for (int i = 0; i < dead_rounds; i++) emit_junk_on_one_register(out, rng);
    if (max_nest_depth > 0 && nest_dist(rng) == 0) {
        emit_native_opaque_predicate(out, rng, max_nest_depth - 1);
    }

    int32_t rel = static_cast<int32_t>(out.size() - (rel_pos + 4));
    uint32_t urel = static_cast<uint32_t>(rel);
    for (int i = 0; i < 4; i++) out[rel_pos + i] = static_cast<uint8_t>(urel >> (8 * i));

    pop_reg(out, reg);
    out.push_back(0x9D); // popfq
}

void emit_junk_call(std::vector<uint8_t> &out, std::mt19937_64 &rng)
{
    // jmp over the subroutine we're about to place inline -- it must never
    // be reached by falling through, only by the `call` emitted below.
    out.push_back(0xE9); // jmp rel32
    size_t skip_pos = out.size();
    emit_u32le(out, 0);

    size_t sub_start = out.size();
    out.push_back(0x9C); // pushfq
    std::uniform_int_distribution<int> reg_count_dist(1, 2);
    int n = reg_count_dist(rng);
    for (int i = 0; i < n; i++) emit_junk_on_one_register(out, rng);
    out.push_back(0x9D); // popfq
    out.push_back(0xC3); // ret

    int32_t skip_rel = static_cast<int32_t>(out.size() - (skip_pos + 4));
    uint32_t uskip_rel = static_cast<uint32_t>(skip_rel);
    for (int i = 0; i < 4; i++) out[skip_pos + i] = static_cast<uint8_t>(uskip_rel >> (8 * i));

    out.push_back(0xE8); // call rel32
    size_t call_pos = out.size();
    emit_u32le(out, 0);
    int32_t call_rel = static_cast<int32_t>(static_cast<int64_t>(sub_start) - static_cast<int64_t>(call_pos + 4));
    uint32_t ucall_rel = static_cast<uint32_t>(call_rel);
    for (int i = 0; i < 4; i++) out[call_pos + i] = static_cast<uint8_t>(ucall_rel >> (8 * i));
}

} // namespace karity
