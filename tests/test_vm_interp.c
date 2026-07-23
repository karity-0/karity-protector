/* Hosted correctness tests for the interpreter core (runtime/vm_interp.c),
 * compiled normally (not freestanding) so we get libc asserts/printf here. */
#include <stdio.h>
#include <string.h>
#include "karity/bytecode_crypt.h"
#include "vm_interp.h"

static int g_failures = 0;

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__); \
            g_failures++; \
        } \
    } while (0)

/* Copies `code` into a scratch buffer, encrypts it with a fixed test seed
 * (see include/karity/bytecode_crypt.h -- "opcode rolling decryption", both
 * interpreters now unconditionally decrypt every fetch), and runs that copy
 * through karity_vm_run with a scratch vstack, returning the resulting
 * karity_vmctx by value for inspection. code_len must cover every byte the
 * program actually reads (trailing slack past that is fine, never read). */
static karity_vmctx run_program(const uint8_t *code, size_t code_len, uint64_t vreg_in[KARITY_VREG_COUNT])
{
    static uint8_t vstack[4096];
    static uint8_t encrypted[256];
    static const uint64_t kTestSeed = 0x1234567890ABCDEFULL;
    karity_vmctx ctx;
    int i;

    memcpy(encrypted, code, code_len);
    karity_bytecode_xor_crypt(encrypted, code_len, 0, kTestSeed);

    memset(&ctx, 0, sizeof(ctx));
    for (i = 0; i < KARITY_VREG_COUNT; i++) {
        ctx.vreg[i] = vreg_in ? vreg_in[i] : 0;
    }
    ctx.vip = (uint64_t)(uintptr_t)encrypted;
    ctx.vsp = (uint64_t)(uintptr_t)(vstack + sizeof(vstack));
    ctx.bytecode_base = ctx.vip;
    ctx.bytecode_key_seed = kTestSeed;

    karity_vm_run(&ctx);
    return ctx;
}

static void test_push_imm_pop_vreg(void)
{
    const uint8_t code[] = {
        VOP_PUSH_IMM, 0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE,
        VOP_POP_VREG, 3,
        VOP_VMEXIT,
    };
    karity_vmctx ctx = run_program(code, sizeof(code), NULL);
    CHECK(ctx.vreg[3] == 0xDEADBEEFDEADBEEFULL, "push_imm/pop_vreg round trip");
}

static void test_arith(void)
{
    const uint8_t code[] = {
        VOP_PUSH_VREG, 0,
        VOP_PUSH_VREG, 1,
        VOP_ADD,
        VOP_POP_VREG, 2,
        VOP_VMEXIT,
    };
    uint64_t regs[KARITY_VREG_COUNT] = {0};
    regs[0] = 10;
    regs[1] = 32;
    karity_vmctx ctx = run_program(code, sizeof(code), regs);
    CHECK(ctx.vreg[2] == 42, "add");
}

static void test_sub_xor_and_or(void)
{
    const uint8_t code[] = {
        VOP_PUSH_IMM, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        VOP_PUSH_IMM, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        VOP_OR,
        VOP_PUSH_IMM, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        VOP_AND,
        VOP_PUSH_IMM, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        VOP_XOR,
        VOP_PUSH_IMM, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        VOP_SUB,
        VOP_POP_VREG, 0,
        VOP_VMEXIT,
    };
    karity_vmctx ctx = run_program(code, sizeof(code), NULL);
    /* (0x0F | 0xF0) & 0xFF = 0xFF; 0xFF ^ 0x0F = 0xF0; 0xF0 - 1 = 0xEF */
    CHECK(ctx.vreg[0] == 0xEF, "sub/xor/and/or chain");
}

static void test_load_store(void)
{
    static uint64_t mem = 0;
    uint8_t code[64];
    size_t n = 0;
    uint64_t addr = (uint64_t)(uintptr_t)&mem;
    int i;

    code[n++] = VOP_PUSH_IMM;
    for (i = 0; i < 8; i++) code[n++] = (uint8_t)(addr >> (8 * i));
    code[n++] = VOP_PUSH_IMM;
    { uint64_t v = 0x1234; for (i = 0; i < 8; i++) code[n++] = (uint8_t)(v >> (8 * i)); }
    code[n++] = VOP_STORE64;
    code[n++] = VOP_PUSH_IMM;
    for (i = 0; i < 8; i++) code[n++] = (uint8_t)(addr >> (8 * i));
    code[n++] = VOP_LOAD64;
    code[n++] = VOP_POP_VREG;
    code[n++] = 5;
    code[n++] = VOP_VMEXIT;

    karity_vmctx ctx = run_program(code, n, NULL);
    CHECK(mem == 0x1234, "store64 wrote through");
    CHECK(ctx.vreg[5] == 0x1234, "load64 read back");
}

static void test_nop_and_vmexit(void)
{
    const uint8_t code[] = { VOP_NOP, VOP_NOP, VOP_VMEXIT };
    karity_vmctx ctx = run_program(code, sizeof(code), NULL);
    /* ctx.vip now points into run_program's internal encrypted copy, not
     * `code` itself -- compare the offset from bytecode_base (== that
     * copy's start address) instead of an absolute address. */
    CHECK(ctx.vip - ctx.bytecode_base == 3, "vip advances past NOPs and VMEXIT");
}

int main(void)
{
    test_push_imm_pop_vreg();
    test_arith();
    test_sub_xor_and_or();
    test_load_store();
    test_nop_and_vmexit();

    if (g_failures == 0) {
        printf("all interpreter tests passed\n");
        return 0;
    }
    fprintf(stderr, "%d test(s) failed\n", g_failures);
    return 1;
}
