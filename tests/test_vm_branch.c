#include <stdio.h>
#include <string.h>
#include "karity/bytecode_crypt.h"
#include "vm_interp.h"

static int g_fail = 0;
#define CHECK(cond, msg) do { if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fail++; } } while (0)

/* Encrypts `code` in place (fixed test seed -- both interpreters now
 * unconditionally decrypt every fetch, see include/karity/bytecode_crypt.h
 * and look/todo.md section C) before running it. `code_len` must cover
 * every byte the program actually reads. */
static void run(uint8_t *code, size_t code_len, karity_vmctx *ctx)
{
    static uint8_t vstack[256];
    static const uint64_t kTestSeed = 0xC0FFEE1234567890ULL;

    karity_bytecode_xor_crypt(code, code_len, 0, kTestSeed);
    ctx->vip = (uint64_t)(uintptr_t)code;
    ctx->vsp = (uint64_t)(uintptr_t)(vstack + sizeof(vstack));
    ctx->bytecode_base = ctx->vip;
    ctx->bytecode_key_seed = kTestSeed;
    karity_vm_run(ctx);
}

static void put_i64(uint8_t *buf, size_t *n, int64_t v)
{
    int i;
    for (i = 0; i < 8; i++) buf[(*n)++] = (uint8_t)((uint64_t)v >> (8 * i));
}

static void test_jmp_skips_junk(void)
{
    uint8_t code[64];
    size_t n = 0;

    code[n++] = VOP_JMP;
    size_t rel_pos = n;
    put_i64(code, &n, 0); /* placeholder, patched below */

    size_t junk_start = n;
    code[n++] = VOP_PUSH_IMM; put_i64(code, &n, 0xDEAD);
    code[n++] = VOP_POP_VREG; code[n++] = 5; /* if this executes, vreg[5] becomes 0xDEAD (bug) */

    size_t after_junk = n;
    int64_t rel = (int64_t)(after_junk - rel_pos - 8);
    { int i; for (i = 0; i < 8; i++) code[rel_pos + i] = (uint8_t)((uint64_t)rel >> (8 * i)); }
    (void)junk_start;

    code[n++] = VOP_PUSH_IMM; put_i64(code, &n, 111);
    code[n++] = VOP_POP_VREG; code[n++] = 5;
    code[n++] = VOP_VMEXIT;

    karity_vmctx ctx; memset(&ctx, 0, sizeof(ctx));
    run(code, n, &ctx);
    CHECK(ctx.vreg[5] == 111, "VOP_JMP skipped the junk block entirely");
}

static void test_jcc_taken_and_not_taken(void)
{
    /* cond != 0 -> taken */
    {
        uint8_t code[64];
        size_t n = 0;
        code[n++] = VOP_PUSH_IMM; put_i64(code, &n, 1); /* cond = 1 */
        code[n++] = VOP_JCC_NZ;
        size_t rel_pos = n;
        put_i64(code, &n, 0);
        code[n++] = VOP_PUSH_IMM; put_i64(code, &n, 0xBAD);
        code[n++] = VOP_POP_VREG; code[n++] = 6;
        size_t after = n;
        int64_t rel = (int64_t)(after - rel_pos - 8);
        { int i; for (i = 0; i < 8; i++) code[rel_pos + i] = (uint8_t)((uint64_t)rel >> (8 * i)); }
        code[n++] = VOP_PUSH_IMM; put_i64(code, &n, 222);
        code[n++] = VOP_POP_VREG; code[n++] = 6;
        code[n++] = VOP_VMEXIT;

        karity_vmctx ctx; memset(&ctx, 0, sizeof(ctx));
        run(code, n, &ctx);
        CHECK(ctx.vreg[6] == 222, "VOP_JCC_NZ with nonzero cond takes the branch");
    }
    /* cond == 0 -> not taken (falls through into what would be "junk" here) */
    {
        uint8_t code[64];
        size_t n = 0;
        code[n++] = VOP_PUSH_IMM; put_i64(code, &n, 0); /* cond = 0 */
        code[n++] = VOP_JCC_NZ;
        size_t rel_pos = n;
        put_i64(code, &n, 0);
        code[n++] = VOP_PUSH_IMM; put_i64(code, &n, 333);
        code[n++] = VOP_POP_VREG; code[n++] = 7;
        size_t after = n;
        int64_t rel = (int64_t)(after - rel_pos - 8);
        { int i; for (i = 0; i < 8; i++) code[rel_pos + i] = (uint8_t)((uint64_t)rel >> (8 * i)); }
        code[n++] = VOP_VMEXIT;

        karity_vmctx ctx; memset(&ctx, 0, sizeof(ctx));
        run(code, n, &ctx);
        CHECK(ctx.vreg[7] == 333, "VOP_JCC_NZ with zero cond falls through");
    }
}

static void test_drop(void)
{
    uint8_t code[32];
    size_t n = 0;
    code[n++] = VOP_PUSH_IMM; put_i64(code, &n, 999);
    code[n++] = VOP_PUSH_IMM; put_i64(code, &n, 5);
    code[n++] = VOP_DROP; /* discard the 5, leaving 999 on top */
    code[n++] = VOP_POP_VREG; code[n++] = 3;
    code[n++] = VOP_VMEXIT;

    karity_vmctx ctx; memset(&ctx, 0, sizeof(ctx));
    run(code, n, &ctx);
    CHECK(ctx.vreg[3] == 999, "VOP_DROP discards top-of-stack, exposing the value below");
}

static void test_opaque_predicate_pattern(void)
{
    /* (carrier | 1) & 1 is always 1 regardless of carrier's value */
    uint64_t carriers[] = {0, 1, 2, 0xFFFFFFFFFFFFFFFFULL, 0x8000000000000000ULL, 42};
    size_t i;
    for (i = 0; i < sizeof(carriers)/sizeof(carriers[0]); i++) {
        uint8_t code[64];
        size_t n = 0;
        code[n++] = VOP_PUSH_VREG; code[n++] = 0; /* carrier in vreg[0] */
        code[n++] = VOP_PUSH_IMM; put_i64(code, &n, 1);
        code[n++] = VOP_OR;
        code[n++] = VOP_PUSH_IMM; put_i64(code, &n, 1);
        code[n++] = VOP_AND;
        code[n++] = VOP_JCC_NZ;
        size_t rel_pos = n;
        put_i64(code, &n, 0);
        code[n++] = VOP_PUSH_IMM; put_i64(code, &n, 0xDEAD); /* dead junk branch */
        code[n++] = VOP_POP_VREG; code[n++] = 9;
        size_t after = n;
        int64_t rel = (int64_t)(after - rel_pos - 8);
        { int j; for (j = 0; j < 8; j++) code[rel_pos + j] = (uint8_t)((uint64_t)rel >> (8 * j)); }
        code[n++] = VOP_PUSH_IMM; put_i64(code, &n, 555);
        code[n++] = VOP_POP_VREG; code[n++] = 9;
        code[n++] = VOP_VMEXIT;

        karity_vmctx ctx; memset(&ctx, 0, sizeof(ctx));
        ctx.vreg[0] = carriers[i];
        run(code, n, &ctx);
        CHECK(ctx.vreg[9] == 555, "opaque predicate always takes the real path regardless of carrier value");
    }
}

int main(void)
{
    test_jmp_skips_junk();
    test_jcc_taken_and_not_taken();
    test_drop();
    test_opaque_predicate_pattern();
    if (g_fail == 0) { printf("all branch/drop tests passed\n"); return 0; }
    fprintf(stderr, "%d failure(s)\n", g_fail);
    return 1;
}
