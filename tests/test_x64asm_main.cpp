#include <cstdio>
#include <cstring>
#include <vector>
#include <windows.h>
#include "x64_asm.h"

using namespace karity;
using namespace karity::x64;

extern "C" void x64_run_with_regs(void *code, uint64_t regs_in[16], uint64_t regs_out[16]);

static int g_fail = 0;
#define CHECK(cond, msg) do { if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fail++; } } while (0)

static void *make_exec(const std::vector<uint8_t> &code_no_ret)
{
    std::vector<uint8_t> full = code_no_ret;
    full.push_back(0xC3);
    void *mem = VirtualAlloc(nullptr, full.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(mem, full.data(), full.size());
    return mem;
}

static void run(const std::vector<uint8_t> &code, const uint64_t in[16], uint64_t out[16])
{
    void *mem = make_exec(code);
    uint64_t in_copy[16];
    memcpy(in_copy, in, sizeof(in_copy));
    x64_run_with_regs(mem, in_copy, out);
    VirtualFree(mem, 0, MEM_RELEASE);
}

static const int kAllRegsNoRsp[] = {0, 1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

static void test_mov_reg_imm64()
{
    for (int reg : kAllRegsNoRsp) {
        std::vector<uint8_t> code;
        mov_reg_imm64(code, reg, 0x1122334455667788ULL + static_cast<uint64_t>(reg));
        uint64_t in[16] = {0}, out[16] = {0};
        run(code, in, out);
        CHECK(out[reg] == 0x1122334455667788ULL + static_cast<uint64_t>(reg), "mov_reg_imm64 round trip");
    }
}

static void test_mov_reg_reg()
{
    int pairs[][2] = {{0, 8}, {8, 0}, {9, 10}, {15, 1}, {3, 15}, {11, 11}, {7, 12}};
    for (auto &p : pairs) {
        int dst = p[0], src = p[1];
        std::vector<uint8_t> code;
        mov_reg_reg(code, dst, src);
        uint64_t in[16] = {0}, out[16] = {0};
        in[src] = 0xCAFEBABE12345678ULL;
        run(code, in, out);
        CHECK(out[dst] == 0xCAFEBABE12345678ULL, "mov_reg_reg");
    }
}

static void test_memory_roundtrip()
{
    // exercise every candidate base register, including R12/R13 (defensive
    // SIB/disp8 handling), even though interp_codegen.h avoids using them
    // as memory bases in the actual generated interpreter.
    for (int base : {8, 9, 10, 11, 12, 13, 14, 15}) {
        alignas(8) uint8_t buf[64] = {0};
        uint64_t magic64 = 0x0102030405060708ULL;
        memcpy(buf + 8, &magic64, 8);

        {
            std::vector<uint8_t> code;
            mov_reg_mem64(code, 11 == base ? 3 : 11, base, 8); // avoid dst==base collision
            uint64_t in[16] = {0}, out[16] = {0};
            in[base] = reinterpret_cast<uint64_t>(buf);
            run(code, in, out);
            int dst = (base == 11) ? 3 : 11;
            char msg[64];
            snprintf(msg, sizeof(msg), "mov_reg_mem64 base=r%d", base);
            CHECK(out[dst] == magic64, msg);
        }
        {
            std::vector<uint8_t> code;
            int dst = (base == 11) ? 3 : 11;
            mov_reg_mem32(code, dst, base, 8);
            uint64_t in[16] = {0}, out[16] = {0};
            in[base] = reinterpret_cast<uint64_t>(buf);
            run(code, in, out);
            CHECK(out[dst] == 0x05060708u, "mov_reg_mem32 zero-extends");
        }
        {
            std::vector<uint8_t> code;
            int dst = (base == 11) ? 3 : 11;
            movzx_reg_mem16(code, dst, base, 8);
            uint64_t in[16] = {0}, out[16] = {0};
            in[base] = reinterpret_cast<uint64_t>(buf);
            run(code, in, out);
            CHECK(out[dst] == 0x0708u, "movzx_reg_mem16");
        }
        {
            std::vector<uint8_t> code;
            int dst = (base == 11) ? 3 : 11;
            movzx_reg_mem8(code, dst, base, 8);
            uint64_t in[16] = {0}, out[16] = {0};
            in[base] = reinterpret_cast<uint64_t>(buf);
            run(code, in, out);
            CHECK(out[dst] == 0x08u, "movzx_reg_mem8");
        }

        // stores
        {
            std::vector<uint8_t> code;
            int src = (base == 3) ? 11 : 3;
            mov_mem64_reg(code, base, 16, src);
            uint64_t in[16] = {0}, out[16] = {0};
            in[base] = reinterpret_cast<uint64_t>(buf);
            in[src] = 0xAABBCCDDEEFF0011ULL;
            run(code, in, out);
            uint64_t got;
            memcpy(&got, buf + 16, 8);
            CHECK(got == 0xAABBCCDDEEFF0011ULL, "mov_mem64_reg store");
        }
        {
            std::vector<uint8_t> code;
            int src = (base == 3) ? 11 : 3;
            memset(buf + 24, 0xFF, 8);
            mov_mem32_reg(code, base, 24, src);
            uint64_t in[16] = {0}, out[16] = {0};
            in[base] = reinterpret_cast<uint64_t>(buf);
            in[src] = 0x1234567890ABCDEFULL;
            run(code, in, out);
            uint32_t got32; memcpy(&got32, buf + 24, 4);
            uint32_t untouched; memcpy(&untouched, buf + 28, 4);
            CHECK(got32 == 0x90ABCDEFu, "mov_mem32_reg truncates to low 32 bits");
            CHECK(untouched == 0xFFFFFFFFu, "mov_mem32_reg doesn't touch adjacent bytes");
        }
        {
            std::vector<uint8_t> code;
            int src = (base == 3) ? 11 : 3;
            memset(buf + 32, 0xFF, 8);
            mov_mem16_reg(code, base, 32, src);
            uint64_t in[16] = {0}, out[16] = {0};
            in[base] = reinterpret_cast<uint64_t>(buf);
            in[src] = 0xBEEF;
            run(code, in, out);
            uint16_t got16; memcpy(&got16, buf + 32, 2);
            uint16_t untouched; memcpy(&untouched, buf + 34, 2);
            CHECK(got16 == 0xBEEF, "mov_mem16_reg");
            CHECK(untouched == 0xFFFF, "mov_mem16_reg doesn't touch adjacent bytes");
        }
        {
            std::vector<uint8_t> code;
            int src = (base == 3) ? 11 : 3;
            memset(buf + 40, 0xFF, 8);
            mov_mem8_reg(code, base, 40, src);
            uint64_t in[16] = {0}, out[16] = {0};
            in[base] = reinterpret_cast<uint64_t>(buf);
            in[src] = 0x42;
            run(code, in, out);
            CHECK(buf[40] == 0x42, "mov_mem8_reg");
            CHECK(buf[41] == 0xFF, "mov_mem8_reg doesn't touch adjacent bytes");
        }
    }
}

static void test_alu()
{
    struct { AluOp op; uint64_t a, b, expect; const char *name; } cases[] = {
        {AluOp::Add, 10, 32, 42, "add"},
        {AluOp::Sub, 50, 8, 42, "sub"},
        {AluOp::Xor, 0xFF, 0x0F, 0xF0, "xor"},
        {AluOp::And, 0xFF, 0x0F, 0x0F, "and"},
        {AluOp::Or,  0xF0, 0x0F, 0xFF, "or"},
    };
    for (auto &c : cases) {
        // reg,reg
        {
            std::vector<uint8_t> code;
            alu_reg_reg(code, c.op, 11, 3); // r11 = r11 OP rbx
            uint64_t in[16] = {0}, out[16] = {0};
            in[11] = c.a; in[3] = c.b;
            run(code, in, out);
            CHECK(out[11] == c.expect, c.name);
        }
        // reg,imm32
        {
            std::vector<uint8_t> code;
            alu_reg_imm32(code, c.op, 11, static_cast<uint32_t>(c.b));
            uint64_t in[16] = {0}, out[16] = {0};
            in[11] = c.a;
            run(code, in, out);
            CHECK(out[11] == c.expect, c.name);
        }
        // mem,reg
        {
            alignas(8) uint64_t mem_val = c.a;
            std::vector<uint8_t> code;
            alu_mem64_reg(code, c.op, 10, 0, 3); // [r10] OP= rbx
            uint64_t in[16] = {0}, out[16] = {0};
            in[10] = reinterpret_cast<uint64_t>(&mem_val);
            in[3] = c.b;
            run(code, in, out);
            CHECK(mem_val == c.expect, c.name);
        }
    }
}

static void test_not_neg()
{
    {
        std::vector<uint8_t> code;
        not_reg(code, 11);
        uint64_t in[16] = {0}, out[16] = {0};
        in[11] = 0;
        run(code, in, out);
        CHECK(out[11] == ~0ULL, "not_reg");
    }
    {
        std::vector<uint8_t> code;
        neg_reg(code, 11);
        uint64_t in[16] = {0}, out[16] = {0};
        in[11] = 5;
        run(code, in, out);
        CHECK(out[11] == static_cast<uint64_t>(-5), "neg_reg");
    }
    {
        std::vector<uint8_t> code;
        shl_reg_imm8(code, 11, 3);
        uint64_t in[16] = {0}, out[16] = {0};
        in[11] = 5; // vreg index 5 -> byte offset 40, matching interp_codegen's use
        run(code, in, out);
        CHECK(out[11] == 40, "shl_reg_imm8");
    }
}

static void test_branch()
{
    // if (r11 == 0) r15 = 111 else r15 = 222, via test+jne
    for (uint64_t v : {0ULL, 1ULL, 0xFFFFFFFFFFFFFFFFULL}) {
        std::vector<uint8_t> code;
        test_reg_reg(code, 11, 11);
        size_t j = jne_rel32(code);
        mov_reg_imm64(code, 15, 111);
        size_t skip = jmp_rel32(code);
        patch_rel32(code, j, code.size());
        mov_reg_imm64(code, 15, 222);
        patch_rel32(code, skip, code.size());

        uint64_t in[16] = {0}, out[16] = {0};
        in[11] = v;
        run(code, in, out);
        uint64_t expect = (v == 0) ? 111 : 222;
        CHECK(out[15] == expect, "branch on test+jne");
    }
}

static void test_call_reg()
{
    std::vector<uint8_t> target_code;
    mov_reg_imm64(target_code, 11, 0xDEADC0DEULL);
    void *target = make_exec(target_code);

    std::vector<uint8_t> code;
    mov_reg_imm64(code, 14, reinterpret_cast<uint64_t>(target));
    call_reg(code, 14);

    uint64_t in[16] = {0}, out[16] = {0};
    run(code, in, out);
    VirtualFree(target, 0, MEM_RELEASE);
    CHECK(out[11] == 0xDEADC0DEULL, "call_reg invokes target and returns");
}

int main()
{
    test_mov_reg_imm64();
    test_mov_reg_reg();
    test_memory_roundtrip();
    test_alu();
    test_not_neg();
    test_branch();
    test_call_reg();

    if (g_fail == 0) { printf("ALL PASS\n"); return 0; }
    printf("%d FAILURES\n", g_fail);
    return 1;
}
