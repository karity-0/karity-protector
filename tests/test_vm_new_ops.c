#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <setjmp.h>
#include <windows.h>
#include "karity/bytecode_crypt.h"
#include "vm_interp.h"

static int g_fail = 0;
#define CHECK(cond, msg) do { if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fail++; } } while (0)

/* Catches the vstack overflow guard's deliberate ud2 trap (see
 * runtime/vm_thunk.S's header and runtime/vm_interp.c's
 * karity_check_vstack_overflow) without taking the whole test process down
 * with it -- same VEH mechanism runtime/nanomite_veh.c uses to catch real
 * CPU faults from injected code, just aimed at this process's own hosted
 * karity_vm_run call instead. longjmp from inside a VEH callback is safe
 * here: it runs on the same thread/stack as the fault, so unwinding back to
 * the setjmp point below just abandons the VEH dispatcher's own frames
 * along with whatever karity_vm_run was doing, exactly like any other
 * longjmp out of a deeply nested call. */
static jmp_buf g_vstack_trap_jmp;
static volatile int g_vstack_trap_armed;

static LONG WINAPI vstack_trap_veh(EXCEPTION_POINTERS *info)
{
    if (g_vstack_trap_armed && info->ExceptionRecord->ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION) {
        g_vstack_trap_armed = 0;
        longjmp(g_vstack_trap_jmp, 1);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

/* Runs ctx through karity_vm_run, returning 1 if the overflow guard's ud2
 * fired (caught via the VEH above) instead of running to a normal
 * VOP_VMEXIT, 0 otherwise. */
static int run_expect_maybe_trap(karity_vmctx *ctx)
{
    int hit;
    g_vstack_trap_armed = 1;
    if (setjmp(g_vstack_trap_jmp) == 0) {
        karity_vm_run(ctx);
        hit = 0;
    } else {
        hit = 1;
    }
    g_vstack_trap_armed = 0;
    return hit;
}

/* A genuine Win64-ABI native function to call through VOP_CALL. */
static uint64_t test_add(uint64_t a, uint64_t b) { return a + b; }

static const uint64_t kTestSeed = 0x5EED1234ABCD9876ULL; // fixed test seed, see
                                                          // include/karity/bytecode_crypt.h

/* Encrypts `code` in place (both interpreters now unconditionally decrypt
 * every fetch -- "opcode rolling decryption", look/todo.md section C) and
 * runs it. code_len must cover every byte the program actually reads. */
static void run(uint8_t *code, size_t code_len, karity_vmctx *ctx)
{
    static uint8_t vstack[256];
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

static void test_push_rel(void)
{
    static uint64_t scratch_target = 0xAABBCCDD;
    uint8_t code[32];
    size_t n = 0;
    int64_t delta = (int64_t)(uintptr_t)&scratch_target - 1000; /* anchor = 1000 */
    int i;

    code[n++] = VOP_PUSH_REL;
    for (i = 0; i < 8; i++) code[n++] = (uint8_t)((uint64_t)delta >> (8 * i));
    code[n++] = VOP_POP_VREG;
    code[n++] = 9;
    code[n++] = VOP_VMEXIT;

    karity_vmctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.anchor = 1000;
    run(code, n, &ctx);
    CHECK(ctx.vreg[9] == (uint64_t)(uintptr_t)&scratch_target, "push_rel resolves anchor+delta");
}

static void test_sized_mem(void)
{
    static uint8_t mem[8] = {0};
    uint8_t code[64];
    size_t n = 0;
    uint64_t addr = (uint64_t)(uintptr_t)mem;
    int i;

    /* store32 0x11223344 at mem, then load8/load16/load32 back */
    code[n++] = VOP_PUSH_IMM;
    for (i = 0; i < 8; i++) code[n++] = (uint8_t)(addr >> (8 * i));
    code[n++] = VOP_PUSH_IMM;
    { uint64_t v = 0x11223344; for (i = 0; i < 8; i++) code[n++] = (uint8_t)(v >> (8 * i)); }
    code[n++] = VOP_STORE32;

    code[n++] = VOP_PUSH_IMM;
    for (i = 0; i < 8; i++) code[n++] = (uint8_t)(addr >> (8 * i));
    code[n++] = VOP_LOAD8;
    code[n++] = VOP_POP_VREG; code[n++] = 1;

    code[n++] = VOP_PUSH_IMM;
    for (i = 0; i < 8; i++) code[n++] = (uint8_t)(addr >> (8 * i));
    code[n++] = VOP_LOAD16;
    code[n++] = VOP_POP_VREG; code[n++] = 2;

    code[n++] = VOP_PUSH_IMM;
    for (i = 0; i < 8; i++) code[n++] = (uint8_t)(addr >> (8 * i));
    code[n++] = VOP_LOAD32;
    code[n++] = VOP_POP_VREG; code[n++] = 3;

    code[n++] = VOP_VMEXIT;

    karity_vmctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    run(code, n, &ctx);
    CHECK(mem[0] == 0x44 && mem[1] == 0x33 && mem[2] == 0x22 && mem[3] == 0x11, "store32 wrote little-endian bytes");
    CHECK(ctx.vreg[1] == 0x44, "load8 reads single byte");
    CHECK(ctx.vreg[2] == 0x3344, "load16 reads two bytes");
    CHECK(ctx.vreg[3] == 0x11223344, "load32 reads four bytes");
}

static void test_call(void)
{
    uint8_t code[16];
    size_t n = 0;
    int i;

    code[n++] = VOP_CALL;
    for (i = 0; i < 8; i++) code[n++] = 0; /* delta = 0, anchor = target directly */
    code[n++] = VOP_VMEXIT;

    static uint8_t native_stack[8192];
    uint64_t rsp_top = ((uint64_t)(uintptr_t)(native_stack + sizeof(native_stack))) & ~(uint64_t)0xF;

    karity_vmctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.anchor = (uint64_t)(uintptr_t)&test_add;
    ctx.vreg[1] = 10; /* RCX = a */
    ctx.vreg[2] = 32; /* RDX = b */
    ctx.vreg[4] = rsp_top; /* RSP */
    run(code, n, &ctx);
    CHECK(ctx.vreg[0] == 42, "VOP_CALL result lands in vreg[RAX]");
}

static void test_call_ind(void)
{
    uint8_t code[16];
    size_t n = 0;
    int i;
    uint64_t target = (uint64_t)(uintptr_t)&test_add;

    /* push the runtime target (as if it came from a vreg or a dereferenced
     * [mem] operand), then VOP_CALL_IND pops it -- no delta/anchor involved */
    code[n++] = VOP_PUSH_IMM;
    for (i = 0; i < 8; i++) code[n++] = (uint8_t)(target >> (8 * i));
    code[n++] = VOP_CALL_IND;
    code[n++] = VOP_VMEXIT;

    static uint8_t native_stack[8192];
    uint64_t rsp_top = ((uint64_t)(uintptr_t)(native_stack + sizeof(native_stack))) & ~(uint64_t)0xF;

    karity_vmctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.vreg[1] = 11; /* RCX = a */
    ctx.vreg[2] = 31; /* RDX = b */
    ctx.vreg[4] = rsp_top; /* RSP */
    run(code, n, &ctx);
    CHECK(ctx.vreg[0] == 42, "VOP_CALL_IND result lands in vreg[RAX]");
}

/* Runs `a OP b` (b then a pushed, per the VM's pop-b-pop-a convention) and
 * returns the resulting vflags word. */
static uint64_t flags_after(uint8_t vop, uint64_t a, uint64_t b)
{
    uint8_t code[32];
    size_t n = 0;
    int i;

    code[n++] = VOP_PUSH_IMM; for (i = 0; i < 8; i++) code[n++] = (uint8_t)(a >> (8 * i));
    code[n++] = VOP_PUSH_IMM; for (i = 0; i < 8; i++) code[n++] = (uint8_t)(b >> (8 * i));
    code[n++] = vop;
    code[n++] = VOP_VMEXIT;

    karity_vmctx ctx; memset(&ctx, 0, sizeof(ctx));
    run(code, n, &ctx);
    return ctx.vflags;
}

static void test_cmp_test_flags(void)
{
    uint64_t f;

    f = flags_after(VOP_CMP, 5, 5);
    CHECK((f & KARITY_FLAG_ZF) != 0, "cmp 5,5 sets ZF");
    CHECK((f & KARITY_FLAG_CF) == 0, "cmp 5,5 clears CF");

    f = flags_after(VOP_CMP, 3, 5);
    CHECK((f & KARITY_FLAG_ZF) == 0, "cmp 3,5 clears ZF");
    CHECK((f & KARITY_FLAG_CF) != 0, "cmp 3,5 sets CF (unsigned borrow)");
    CHECK((f & KARITY_FLAG_SF) != 0, "cmp 3,5 sets SF (result negative)");

    f = flags_after(VOP_CMP, 5, 3);
    CHECK((f & KARITY_FLAG_CF) == 0, "cmp 5,3 clears CF");
    CHECK((f & KARITY_FLAG_SF) == 0, "cmp 5,3 clears SF");

    /* signed overflow: INT64_MIN - 1 overflows (result should look positive) */
    f = flags_after(VOP_CMP, 0x8000000000000000ULL, 1);
    CHECK((f & KARITY_FLAG_OF) != 0, "cmp INT64_MIN,1 sets OF");

    f = flags_after(VOP_TEST, 0, 0xFF);
    CHECK((f & KARITY_FLAG_ZF) != 0, "test 0,0xFF sets ZF");
    CHECK((f & (KARITY_FLAG_CF | KARITY_FLAG_OF)) == 0, "test always clears CF/OF");

    f = flags_after(VOP_TEST, 0xFF, 0xFF);
    CHECK((f & KARITY_FLAG_ZF) == 0, "test 0xFF,0xFF clears ZF");

    /* CMP/TEST push nothing back: vstack must be exactly where it started */
    {
        uint8_t code[32]; size_t n = 0; int i;
        code[n++] = VOP_PUSH_IMM; for (i = 0; i < 8; i++) code[n++] = 0;
        code[n++] = VOP_PUSH_IMM; for (i = 0; i < 8; i++) code[n++] = 0;
        code[n++] = VOP_CMP;
        code[n++] = VOP_PUSH_IMM; for (i = 0; i < 8; i++) code[n++] = (uint8_t)(77 >> (8*i));
        code[n++] = VOP_POP_VREG; code[n++] = 2;
        code[n++] = VOP_VMEXIT;
        karity_vmctx ctx; memset(&ctx, 0, sizeof(ctx));
        run(code, n, &ctx);
        CHECK(ctx.vreg[2] == 77, "CMP consumes both operands and pushes nothing");
    }
}

static void test_neg_not(void)
{
    uint8_t code[32];
    size_t n;
    karity_vmctx ctx;

    /* NEG: -5 -> two's complement, CF=1 (operand != 0), SF=1 */
    n = 0;
    code[n++] = VOP_PUSH_IMM; put_i64(code, &n, 5);
    code[n++] = VOP_NEG;
    code[n++] = VOP_POP_VREG; code[n++] = 1;
    code[n++] = VOP_VMEXIT;
    memset(&ctx, 0, sizeof(ctx));
    run(code, n, &ctx);
    CHECK(ctx.vreg[1] == (uint64_t)(-5LL), "NEG 5 computes two's complement");
    CHECK((ctx.vflags & KARITY_FLAG_CF) != 0, "NEG nonzero operand sets CF");
    CHECK((ctx.vflags & KARITY_FLAG_SF) != 0, "NEG 5 sets SF (result negative)");

    /* NEG 0: CF=0 (the one exception), ZF=1 */
    n = 0;
    code[n++] = VOP_PUSH_IMM; put_i64(code, &n, 0);
    code[n++] = VOP_NEG;
    code[n++] = VOP_POP_VREG; code[n++] = 1;
    code[n++] = VOP_VMEXIT;
    memset(&ctx, 0, sizeof(ctx));
    run(code, n, &ctx);
    CHECK(ctx.vreg[1] == 0, "NEG 0 is 0");
    CHECK((ctx.vflags & KARITY_FLAG_CF) == 0, "NEG 0 clears CF");
    CHECK((ctx.vflags & KARITY_FLAG_ZF) != 0, "NEG 0 sets ZF");

    /* NEG INT64_MIN: overflow, result unchanged, OF=1 */
    n = 0;
    code[n++] = VOP_PUSH_IMM; put_i64(code, &n, (int64_t)0x8000000000000000ULL);
    code[n++] = VOP_NEG;
    code[n++] = VOP_POP_VREG; code[n++] = 1;
    code[n++] = VOP_VMEXIT;
    memset(&ctx, 0, sizeof(ctx));
    run(code, n, &ctx);
    CHECK(ctx.vreg[1] == 0x8000000000000000ULL, "NEG INT64_MIN wraps to itself");
    CHECK((ctx.vflags & KARITY_FLAG_OF) != 0, "NEG INT64_MIN sets OF");

    /* NOT: bitwise complement, and must NOT touch vflags */
    n = 0;
    code[n++] = VOP_PUSH_IMM; put_i64(code, &n, 3); /* set some flags first */
    code[n++] = VOP_PUSH_IMM; put_i64(code, &n, 3);
    code[n++] = VOP_CMP; /* ZF=1 */
    code[n++] = VOP_PUSH_IMM; put_i64(code, &n, 0x0F0F0F0F0F0F0F0FLL);
    code[n++] = VOP_NOT;
    code[n++] = VOP_POP_VREG; code[n++] = 1;
    code[n++] = VOP_VMEXIT;
    memset(&ctx, 0, sizeof(ctx));
    run(code, n, &ctx);
    CHECK(ctx.vreg[1] == 0xF0F0F0F0F0F0F0F0ULL, "NOT complements every bit");
    CHECK((ctx.vflags & KARITY_FLAG_ZF) != 0, "NOT leaves prior vflags (ZF from the earlier CMP) untouched");
}

static void test_movzx_movsx(void)
{
    uint8_t code[128];
    size_t n;
    karity_vmctx ctx;

    /* MOVZX: dst-width-independent (see isa.h) -- always zero-extends the
     * low src_size bytes to the full 64 bits, regardless of what a native
     * 32-bit-dest vs 64-bit-dest movzx encoding would have looked like. */
    n = 0;
    code[n++] = VOP_PUSH_IMM; put_i64(code, &n, 0xFFFFFFFFFFFFFF80ULL);
    code[n++] = VOP_MOVZX; code[n++] = 1; /* src_size = 1 byte */
    code[n++] = VOP_POP_VREG; code[n++] = 5;
    code[n++] = VOP_PUSH_IMM; put_i64(code, &n, 0xFFFFFFFFFFFF8000ULL);
    code[n++] = VOP_MOVZX; code[n++] = 2; /* src_size = 2 bytes */
    code[n++] = VOP_POP_VREG; code[n++] = 6;
    code[n++] = VOP_VMEXIT;

    memset(&ctx, 0, sizeof(ctx));
    ctx.vflags = 0xDEADBEEF; /* sentinel: MOVZX must never touch vflags */
    run(code, n, &ctx);
    CHECK(ctx.vreg[5] == 0x80, "movzx byte zero-extends (...FF80 -> 0x80)");
    CHECK(ctx.vreg[6] == 0x8000, "movzx word zero-extends (...FF8000 -> 0x8000)");
    CHECK(ctx.vflags == 0xDEADBEEF, "movzx never touches vflags");

    /* MOVSX: dst_size DOES matter, unlike MOVZX -- a 32-bit destination
     * sign-extends into 32 bits and then implicitly zeroes the upper 32
     * (matching native x86), which is a different 64-bit value than a
     * direct 64-bit sign extension whenever the source is negative. */
    n = 0;
    code[n++] = VOP_PUSH_IMM; put_i64(code, &n, 0x80); /* byte 0x80 = -128 */
    code[n++] = VOP_MOVSX; code[n++] = 1; code[n++] = 8; /* src=1B, dst=64-bit */
    code[n++] = VOP_POP_VREG; code[n++] = 7;

    code[n++] = VOP_PUSH_IMM; put_i64(code, &n, 0x80);
    code[n++] = VOP_MOVSX; code[n++] = 1; code[n++] = 4; /* src=1B, dst=32-bit */
    code[n++] = VOP_POP_VREG; code[n++] = 8;

    /* movsxd (src=4B, always dst=64-bit): negative dword */
    code[n++] = VOP_PUSH_IMM; put_i64(code, &n, 0xFFFFFFFF80000001ULL);
    code[n++] = VOP_MOVSX; code[n++] = 4; code[n++] = 8;
    code[n++] = VOP_POP_VREG; code[n++] = 9;

    /* positive source stays positive regardless of dst_size */
    code[n++] = VOP_PUSH_IMM; put_i64(code, &n, 0x7F);
    code[n++] = VOP_MOVSX; code[n++] = 1; code[n++] = 8;
    code[n++] = VOP_POP_VREG; code[n++] = 10;

    code[n++] = VOP_VMEXIT;

    memset(&ctx, 0, sizeof(ctx));
    ctx.vflags = 0xCAFEBABE; /* sentinel: MOVSX must never touch vflags */
    run(code, n, &ctx);
    CHECK(ctx.vreg[7] == 0xFFFFFFFFFFFFFF80ULL, "movsx byte->64 sign-extends fully");
    CHECK(ctx.vreg[8] == 0x00000000FFFFFF80ULL,
          "movsx byte->32 sign-extends then zero-uppers (not a plain 64-bit sign extend)");
    CHECK(ctx.vreg[9] == 0xFFFFFFFF80000001ULL, "movsxd dword->64 sign-extends");
    CHECK(ctx.vreg[10] == 0x7F, "movsx of a positive value stays positive");
    CHECK(ctx.vflags == 0xCAFEBABE, "movsx never touches vflags");
}

static void test_inc_dec(void)
{
    uint8_t code[48];
    size_t n;
    karity_vmctx ctx;

    /* INC INT64_MAX: wraps to INT64_MIN, OF=1 SF=1 ZF=0 */
    n = 0;
    code[n++] = VOP_PUSH_IMM; put_i64(code, &n, (int64_t)0x7FFFFFFFFFFFFFFFLL);
    code[n++] = VOP_INC;
    code[n++] = VOP_POP_VREG; code[n++] = 1;
    code[n++] = VOP_VMEXIT;
    memset(&ctx, 0, sizeof(ctx));
    run(code, n, &ctx);
    CHECK(ctx.vreg[1] == 0x8000000000000000ULL, "INC INT64_MAX wraps to INT64_MIN");
    CHECK((ctx.vflags & KARITY_FLAG_OF) != 0, "INC INT64_MAX sets OF");
    CHECK((ctx.vflags & KARITY_FLAG_SF) != 0, "INC INT64_MAX sets SF");
    CHECK((ctx.vflags & KARITY_FLAG_ZF) == 0, "INC INT64_MAX clears ZF");

    /* INC -1: wraps to 0, ZF=1, no OF */
    n = 0;
    code[n++] = VOP_PUSH_IMM; put_i64(code, &n, -1);
    code[n++] = VOP_INC;
    code[n++] = VOP_POP_VREG; code[n++] = 1;
    code[n++] = VOP_VMEXIT;
    memset(&ctx, 0, sizeof(ctx));
    run(code, n, &ctx);
    CHECK(ctx.vreg[1] == 0, "INC -1 wraps to 0");
    CHECK((ctx.vflags & KARITY_FLAG_ZF) != 0, "INC -1 sets ZF");
    CHECK((ctx.vflags & KARITY_FLAG_OF) == 0, "INC -1 does not set OF");

    /* DEC INT64_MIN: wraps to INT64_MAX, OF=1 */
    n = 0;
    code[n++] = VOP_PUSH_IMM; put_i64(code, &n, (int64_t)0x8000000000000000ULL);
    code[n++] = VOP_DEC;
    code[n++] = VOP_POP_VREG; code[n++] = 1;
    code[n++] = VOP_VMEXIT;
    memset(&ctx, 0, sizeof(ctx));
    run(code, n, &ctx);
    CHECK(ctx.vreg[1] == 0x7FFFFFFFFFFFFFFFULL, "DEC INT64_MIN wraps to INT64_MAX");
    CHECK((ctx.vflags & KARITY_FLAG_OF) != 0, "DEC INT64_MIN sets OF");

    /* Unlike ADD/SUB/NEG, INC/DEC must leave CF exactly as it was. */
    n = 0;
    code[n++] = VOP_PUSH_IMM; put_i64(code, &n, 0); /* cmp 0,1 -> CF=1 (unsigned 0<1) */
    code[n++] = VOP_PUSH_IMM; put_i64(code, &n, 1);
    code[n++] = VOP_CMP;
    code[n++] = VOP_PUSH_IMM; put_i64(code, &n, 10);
    code[n++] = VOP_INC;
    code[n++] = VOP_POP_VREG; code[n++] = 1;
    code[n++] = VOP_VMEXIT;
    memset(&ctx, 0, sizeof(ctx));
    run(code, n, &ctx);
    CHECK(ctx.vreg[1] == 11, "INC 10 -> 11");
    CHECK((ctx.vflags & KARITY_FLAG_CF) != 0, "INC preserves a CF=1 set by an earlier CMP");

    n = 0;
    code[n++] = VOP_PUSH_IMM; put_i64(code, &n, 5); /* cmp 5,3 -> CF=0 (unsigned 5>=3) */
    code[n++] = VOP_PUSH_IMM; put_i64(code, &n, 3);
    code[n++] = VOP_CMP;
    code[n++] = VOP_PUSH_IMM; put_i64(code, &n, 10);
    code[n++] = VOP_DEC;
    code[n++] = VOP_POP_VREG; code[n++] = 1;
    code[n++] = VOP_VMEXIT;
    memset(&ctx, 0, sizeof(ctx));
    run(code, n, &ctx);
    CHECK(ctx.vreg[1] == 9, "DEC 10 -> 9");
    CHECK((ctx.vflags & KARITY_FLAG_CF) == 0, "DEC preserves a CF=0 set by an earlier CMP");
}

/* Runs `push value; push count; <shift_vop>; pop vreg[1]` and returns the
 * resulting ctx (vreg[1] = result, vflags = whatever the shift set). */
static karity_vmctx shift_result(uint8_t shift_vop, uint64_t value, uint64_t count)
{
    uint8_t code[64];
    size_t n = 0;
    karity_vmctx ctx;

    code[n++] = VOP_PUSH_IMM; put_i64(code, &n, (int64_t)value);
    code[n++] = VOP_PUSH_IMM; put_i64(code, &n, (int64_t)count);
    code[n++] = shift_vop;
    code[n++] = VOP_POP_VREG; code[n++] = 1;
    code[n++] = VOP_VMEXIT;
    memset(&ctx, 0, sizeof(ctx));
    run(code, n, &ctx);
    return ctx;
}

static void test_shift_rotate(void)
{
    karity_vmctx ctx;

    /* SHL: 0x8000000000000001 << 1 -> 0x2, CF=1 (bit63 shifted out), OF=1
     * (MSB(result)=0 XOR CF=1) */
    ctx = shift_result(VOP_SHL, 0x8000000000000001ULL, 1);
    CHECK(ctx.vreg[1] == 2, "SHL 0x8000000000000001,1 == 2");
    CHECK((ctx.vflags & KARITY_FLAG_CF) != 0, "SHL sets CF from the bit shifted out");
    CHECK((ctx.vflags & KARITY_FLAG_OF) != 0, "SHL count=1 sets OF when the sign bit changes");

    /* SHR: 3 >> 1 -> 1, CF=1 (bit0 shifted out), OF=0 (original MSB was 0) */
    ctx = shift_result(VOP_SHR, 3, 1);
    CHECK(ctx.vreg[1] == 1, "SHR 3,1 == 1");
    CHECK((ctx.vflags & KARITY_FLAG_CF) != 0, "SHR sets CF from the bit shifted out");
    CHECK((ctx.vflags & KARITY_FLAG_OF) == 0, "SHR count=1 OF reflects original MSB (0 here)");

    /* SAR: -2 >> 1 (arithmetic) -> -1, sign-extends; CF=0 (bit0 of -2 is 0) */
    ctx = shift_result(VOP_SAR, (uint64_t)(int64_t)-2, 1);
    CHECK(ctx.vreg[1] == (uint64_t)(int64_t)-1, "SAR -2,1 == -1 (sign-extending)");
    CHECK((ctx.vflags & KARITY_FLAG_CF) == 0, "SAR -2,1 clears CF (bit0 of -2 is 0)");

    /* ROL: top bit wraps around to bottom */
    ctx = shift_result(VOP_ROL, 0x8000000000000000ULL, 1);
    CHECK(ctx.vreg[1] == 1, "ROL 0x8000000000000000,1 == 1 (top bit wraps to bottom)");
    CHECK((ctx.vflags & KARITY_FLAG_CF) != 0, "ROL CF = LSB of result");
    CHECK((ctx.vflags & KARITY_FLAG_OF) != 0, "ROL count=1 OF = MSB(result) XOR CF");

    /* ROR: bottom bit wraps around to top */
    ctx = shift_result(VOP_ROR, 1, 1);
    CHECK(ctx.vreg[1] == 0x8000000000000000ULL, "ROR 1,1 == 0x8000000000000000 (bottom bit wraps to top)");
    CHECK((ctx.vflags & KARITY_FLAG_CF) != 0, "ROR CF = MSB of result");

    /* count is masked to 0-63: 65 behaves like 1 */
    ctx = shift_result(VOP_SHL, 1, 65);
    CHECK(ctx.vreg[1] == 2, "SHL count=65 masks to 1 (1<<1==2)");

    /* count==0: value AND every flag bit stay exactly as they were before */
    {
        uint8_t code[64];
        size_t n = 0;
        code[n++] = VOP_PUSH_IMM; put_i64(code, &n, 3); /* cmp 3,3 -> ZF=1, sets a known flag state */
        code[n++] = VOP_PUSH_IMM; put_i64(code, &n, 3);
        code[n++] = VOP_CMP;
        code[n++] = VOP_PUSH_IMM; put_i64(code, &n, 0x1234);
        code[n++] = VOP_PUSH_IMM; put_i64(code, &n, 0); /* count = 0 */
        code[n++] = VOP_SHL;
        code[n++] = VOP_POP_VREG; code[n++] = 1;
        code[n++] = VOP_VMEXIT;
        memset(&ctx, 0, sizeof(ctx));
        run(code, n, &ctx);
        CHECK(ctx.vreg[1] == 0x1234, "shift by count=0 leaves the value unchanged");
        CHECK((ctx.vflags & KARITY_FLAG_ZF) != 0, "shift by count=0 leaves vflags (ZF from the earlier CMP) untouched");
    }

    /* ROL/ROR must not touch SF/ZF/PF even when count != 0 */
    {
        uint8_t code[64];
        size_t n = 0;
        code[n++] = VOP_PUSH_IMM; put_i64(code, &n, 3); /* cmp 3,3 -> ZF=1 */
        code[n++] = VOP_PUSH_IMM; put_i64(code, &n, 3);
        code[n++] = VOP_CMP;
        code[n++] = VOP_PUSH_IMM; put_i64(code, &n, 1);
        code[n++] = VOP_PUSH_IMM; put_i64(code, &n, 1); /* rol 1,1 == 2 */
        code[n++] = VOP_ROL;
        code[n++] = VOP_POP_VREG; code[n++] = 1;
        code[n++] = VOP_VMEXIT;
        memset(&ctx, 0, sizeof(ctx));
        run(code, n, &ctx);
        CHECK(ctx.vreg[1] == 2, "rol 1,1 == 2");
        CHECK((ctx.vflags & KARITY_FLAG_ZF) != 0, "rol leaves ZF from an earlier cmp untouched");
    }
}

/* Runs `push b; <vop>` with ctx.vreg[0](RAX)=rax_in and ctx.vreg[2](RDX)=
 * rdx_in preset beforehand (MUL/IMUL1/DIV/IDIV's implicit operand(s), which
 * -- unlike every other ALU op -- aren't pushed onto the vstack at all). */
static karity_vmctx mulx_result(uint8_t vop, uint64_t rax_in, uint64_t rdx_in, uint64_t b)
{
    uint8_t code[32];
    size_t n = 0;
    karity_vmctx ctx;

    code[n++] = VOP_PUSH_IMM; put_i64(code, &n, (int64_t)b);
    code[n++] = vop;
    code[n++] = VOP_VMEXIT;
    memset(&ctx, 0, sizeof(ctx));
    ctx.vreg[0] = rax_in;
    ctx.vreg[2] = rdx_in;
    run(code, n, &ctx);
    return ctx;
}

static void test_mul_imul_div(void)
{
    karity_vmctx ctx;

    /* MUL: 6*7=42, fits in 64 bits -> CF=OF=0, high64 (RDX) == 0 */
    ctx = mulx_result(VOP_MUL, 6, 0, 7);
    CHECK(ctx.vreg[0] == 42, "mul 6*7 == 42 (RAX)");
    CHECK(ctx.vreg[2] == 0, "mul 6*7 high64 == 0 (RDX)");
    CHECK((ctx.vflags & (KARITY_FLAG_CF | KARITY_FLAG_OF)) == 0, "mul 6*7 clears CF/OF (no overflow)");

    /* MUL: UINT64_MAX*2 overflows into RDX -> CF=OF=1 */
    ctx = mulx_result(VOP_MUL, UINT64_MAX, 0, 2);
    CHECK(ctx.vreg[0] == 0xFFFFFFFFFFFFFFFEULL, "mul UINT64_MAX*2 low64");
    CHECK(ctx.vreg[2] == 1, "mul UINT64_MAX*2 high64 == 1");
    CHECK((ctx.vflags & (KARITY_FLAG_CF | KARITY_FLAG_OF)) != 0, "mul overflow sets CF/OF");

    /* IMUL1: -6*7 = -42, fits in signed 64 bits -> CF=OF=0, RDX sign-extends */
    ctx = mulx_result(VOP_IMUL1, (uint64_t)(int64_t)-6, 0, 7);
    CHECK(ctx.vreg[0] == (uint64_t)(int64_t)-42, "imul1 -6*7 == -42 (RAX)");
    CHECK(ctx.vreg[2] == UINT64_MAX, "imul1 -6*7 sign-extends into RDX");
    CHECK((ctx.vflags & (KARITY_FLAG_CF | KARITY_FLAG_OF)) == 0, "imul1 -6*7 clears CF/OF (no overflow)");

    /* IMUL1: INT64_MIN*-1 -- the classic signed-overflow case -> CF=OF=1 */
    ctx = mulx_result(VOP_IMUL1, 0x8000000000000000ULL, 0, (uint64_t)(int64_t)-1);
    CHECK((ctx.vflags & (KARITY_FLAG_CF | KARITY_FLAG_OF)) != 0, "imul1 INT64_MIN*-1 overflows, sets CF/OF");

    /* IMUL2: pop b, pop a, push a*b -- never touches vreg[RAX]/vreg[RDX] */
    {
        uint8_t code[32]; size_t n = 0;
        code[n++] = VOP_PUSH_IMM; put_i64(code, &n, 6);
        code[n++] = VOP_PUSH_IMM; put_i64(code, &n, 7);
        code[n++] = VOP_IMUL2;
        code[n++] = VOP_POP_VREG; code[n++] = 5;
        code[n++] = VOP_VMEXIT;
        memset(&ctx, 0, sizeof(ctx));
        run(code, n, &ctx);
        CHECK(ctx.vreg[5] == 42, "imul2 6*7 == 42");
        CHECK((ctx.vflags & (KARITY_FLAG_CF | KARITY_FLAG_OF)) == 0, "imul2 6*7 clears CF/OF");
    }
    /* IMUL2: INT64_MAX*2 doesn't fit in a signed 64-bit result -> CF=OF=1 */
    {
        uint8_t code[32]; size_t n = 0;
        code[n++] = VOP_PUSH_IMM; put_i64(code, &n, (int64_t)0x7FFFFFFFFFFFFFFFLL);
        code[n++] = VOP_PUSH_IMM; put_i64(code, &n, 2);
        code[n++] = VOP_IMUL2;
        code[n++] = VOP_POP_VREG; code[n++] = 5;
        code[n++] = VOP_VMEXIT;
        memset(&ctx, 0, sizeof(ctx));
        run(code, n, &ctx);
        CHECK((ctx.vflags & (KARITY_FLAG_CF | KARITY_FLAG_OF)) != 0, "imul2 INT64_MAX*2 overflows, sets CF/OF");
    }

    /* DIV: 42/5 -> quotient 8, remainder 2 (RDX preset to 0: unsigned dividend) */
    ctx = mulx_result(VOP_DIV, 42, 0, 5);
    CHECK(ctx.vreg[0] == 8, "div 42/5 quotient == 8");
    CHECK(ctx.vreg[2] == 2, "div 42/5 remainder == 2");

    /* IDIV: -42/5 -> quotient -8, remainder -2 (truncating toward zero;
     * RDX preset to -1, the sign-extension a real `cqo` would produce) */
    ctx = mulx_result(VOP_IDIV, (uint64_t)(int64_t)-42, UINT64_MAX, 5);
    CHECK(ctx.vreg[0] == (uint64_t)(int64_t)-8, "idiv -42/5 quotient == -8");
    CHECK(ctx.vreg[2] == (uint64_t)(int64_t)-2, "idiv -42/5 remainder == -2");
}

static void test_arith_sets_flags(void)
{
    uint64_t f = flags_after(VOP_SUB, 5, 5);
    CHECK((f & KARITY_FLAG_ZF) != 0, "5-5 sets ZF via VOP_SUB too");

    f = flags_after(VOP_ADD, 0x7FFFFFFFFFFFFFFFULL, 1);
    CHECK((f & KARITY_FLAG_OF) != 0, "INT64_MAX+1 sets OF via VOP_ADD");
    CHECK((f & KARITY_FLAG_SF) != 0, "INT64_MAX+1 looks negative (wraps)");

    f = flags_after(VOP_AND, 0xF0, 0x0F);
    CHECK((f & KARITY_FLAG_ZF) != 0, "0xF0 & 0x0F sets ZF via VOP_AND");
    CHECK((f & (KARITY_FLAG_CF | KARITY_FLAG_OF)) == 0, "logic ops clear CF/OF");
}

/* Runs `<flags_vop> flags_a,flags_b; VOP_JCC cc,rel` and reports whether the
 * branch was taken: not-taken path writes 0 then jumps past the taken path
 * (otherwise it would just fall through into it and the result would always
 * read as "taken", regardless of cc). */
static int jcc_taken(uint8_t cc, uint64_t flags_a, uint64_t flags_b, uint8_t flags_vop)
{
    uint8_t code[80];
    size_t n = 0;
    size_t jcc_rel_pos, jmp_rel_pos, taken_pos, end_pos;
    int64_t rel;

    code[n++] = VOP_PUSH_IMM; put_i64(code, &n, (int64_t)flags_a);
    code[n++] = VOP_PUSH_IMM; put_i64(code, &n, (int64_t)flags_b);
    code[n++] = flags_vop; /* CMP or TEST: sets vflags, pushes nothing */

    code[n++] = VOP_JCC; code[n++] = cc;
    jcc_rel_pos = n;
    put_i64(code, &n, 0); /* placeholder, patched once "taken_pos" is known */

    /* not-taken path */
    code[n++] = VOP_PUSH_IMM; put_i64(code, &n, 0);
    code[n++] = VOP_POP_VREG; code[n++] = 8;
    code[n++] = VOP_JMP;
    jmp_rel_pos = n;
    put_i64(code, &n, 0); /* placeholder, patched once "end_pos" is known */

    /* taken path (VOP_JCC lands here) */
    taken_pos = n;
    rel = (int64_t)(taken_pos - jcc_rel_pos - 8);
    { int i; for (i = 0; i < 8; i++) code[jcc_rel_pos + i] = (uint8_t)((uint64_t)rel >> (8 * i)); }
    code[n++] = VOP_PUSH_IMM; put_i64(code, &n, 1);
    code[n++] = VOP_POP_VREG; code[n++] = 8;

    /* end (VOP_JMP lands here) */
    end_pos = n;
    rel = (int64_t)(end_pos - jmp_rel_pos - 8);
    { int i; for (i = 0; i < 8; i++) code[jmp_rel_pos + i] = (uint8_t)((uint64_t)rel >> (8 * i)); }
    code[n++] = VOP_VMEXIT;

    karity_vmctx ctx; memset(&ctx, 0, sizeof(ctx));
    run(code, n, &ctx);
    return (int)ctx.vreg[8];
}

static void test_jcc_conditions(void)
{
    /* cmp 3,5 (a<b): ZF=0, SF=1, CF=1, OF=0 -> B/BE/L/LE/S taken; their
     * negations (AE/A/GE/G/NS) not taken. E/NE/O/NO/P/NP depend on equality/
     * overflow/parity specifically, checked via dedicated cases below. */
    CHECK(jcc_taken(KARITY_CC_B,  3, 5, VOP_CMP) == 1, "3<5: B taken");
    CHECK(jcc_taken(KARITY_CC_AE, 3, 5, VOP_CMP) == 0, "3<5: AE not taken");
    CHECK(jcc_taken(KARITY_CC_BE, 3, 5, VOP_CMP) == 1, "3<5: BE taken");
    CHECK(jcc_taken(KARITY_CC_A,  3, 5, VOP_CMP) == 0, "3<5: A not taken");
    CHECK(jcc_taken(KARITY_CC_L,  3, 5, VOP_CMP) == 1, "3<5: L taken");
    CHECK(jcc_taken(KARITY_CC_GE, 3, 5, VOP_CMP) == 0, "3<5: GE not taken");
    CHECK(jcc_taken(KARITY_CC_LE, 3, 5, VOP_CMP) == 1, "3<5: LE taken");
    CHECK(jcc_taken(KARITY_CC_G,  3, 5, VOP_CMP) == 0, "3<5: G not taken");
    CHECK(jcc_taken(KARITY_CC_S,  3, 5, VOP_CMP) == 1, "3<5: S taken");
    CHECK(jcc_taken(KARITY_CC_NS, 3, 5, VOP_CMP) == 0, "3<5: NS not taken");
    CHECK(jcc_taken(KARITY_CC_NE, 3, 5, VOP_CMP) == 1, "3<5: NE taken");
    CHECK(jcc_taken(KARITY_CC_E,  3, 5, VOP_CMP) == 0, "3<5: E not taken");

    /* cmp 5,5: ZF=1, everything else 0 */
    CHECK(jcc_taken(KARITY_CC_E,  5, 5, VOP_CMP) == 1, "5==5: E taken");
    CHECK(jcc_taken(KARITY_CC_NE, 5, 5, VOP_CMP) == 0, "5==5: NE not taken");
    CHECK(jcc_taken(KARITY_CC_GE, 5, 5, VOP_CMP) == 1, "5==5: GE taken (SF==OF)");
    CHECK(jcc_taken(KARITY_CC_LE, 5, 5, VOP_CMP) == 1, "5==5: LE taken (ZF)");
    CHECK(jcc_taken(KARITY_CC_G,  5, 5, VOP_CMP) == 0, "5==5: G not taken");
    CHECK(jcc_taken(KARITY_CC_AE, 5, 5, VOP_CMP) == 1, "5==5: AE taken (CF=0)");
    CHECK(jcc_taken(KARITY_CC_BE, 5, 5, VOP_CMP) == 1, "5==5: BE taken (ZF)");

    /* cmp INT64_MIN,1 -> OF=1 */
    CHECK(jcc_taken(KARITY_CC_O,  0x8000000000000000ULL, 1, VOP_CMP) == 1, "overflow: O taken");
    CHECK(jcc_taken(KARITY_CC_NO, 0x8000000000000000ULL, 1, VOP_CMP) == 0, "overflow: NO not taken");

    /* test 0,0xFF -> ZF=1 (parity of result 0 is even -> PF=1) */
    CHECK(jcc_taken(KARITY_CC_P,  0, 0xFF, VOP_TEST) == 1, "test 0,0xFF: P taken (even parity)");
    CHECK(jcc_taken(KARITY_CC_NP, 0, 0xFF, VOP_TEST) == 0, "test 0,0xFF: NP not taken");
    /* test 0xFF,0xFF -> result 0xFF, popcount(low byte)=8 -> even -> PF=1 too;
     * use a result with odd popcount to exercise NP */
    CHECK(jcc_taken(KARITY_CC_NP, 0x01, 0xFF, VOP_TEST) == 1, "test 0x01,0xFF: NP taken (odd parity)");
}

static uint64_t d2bits(double d) { uint64_t u; memcpy(&u, &d, 8); return u; }
static double bits2d(uint64_t u) { double d; memcpy(&d, &u, 8); return d; }
static uint64_t f2bits(float f) { uint32_t u; memcpy(&u, &f, 4); return (uint64_t)u; }
static float bits2f(uint64_t u) { uint32_t v = (uint32_t)u; float f; memcpy(&f, &v, 4); return f; }

static void test_sse(void)
{
    uint8_t code[64];
    size_t n;
    karity_vmctx ctx;

    /* ADDSD/SUBSD/MULSD/DIVSD: raw 8-byte double bit patterns on the vstack */
    n = 0;
    code[n++] = VOP_PUSH_IMM; put_i64(code, &n, (int64_t)d2bits(1.5));
    code[n++] = VOP_PUSH_IMM; put_i64(code, &n, (int64_t)d2bits(2.5));
    code[n++] = VOP_ADDSD;
    code[n++] = VOP_POP_VREG; code[n++] = 1;
    code[n++] = VOP_VMEXIT;
    memset(&ctx, 0, sizeof(ctx));
    run(code, n, &ctx);
    CHECK(bits2d(ctx.vreg[1]) == 4.0, "addsd 1.5+2.5 == 4.0");

    n = 0;
    code[n++] = VOP_PUSH_IMM; put_i64(code, &n, (int64_t)d2bits(5.0));
    code[n++] = VOP_PUSH_IMM; put_i64(code, &n, (int64_t)d2bits(2.0));
    code[n++] = VOP_SUBSD;
    code[n++] = VOP_POP_VREG; code[n++] = 1;
    code[n++] = VOP_VMEXIT;
    memset(&ctx, 0, sizeof(ctx));
    run(code, n, &ctx);
    CHECK(bits2d(ctx.vreg[1]) == 3.0, "subsd 5.0-2.0 == 3.0");

    n = 0;
    code[n++] = VOP_PUSH_IMM; put_i64(code, &n, (int64_t)d2bits(6.0));
    code[n++] = VOP_PUSH_IMM; put_i64(code, &n, (int64_t)d2bits(7.0));
    code[n++] = VOP_MULSD;
    code[n++] = VOP_POP_VREG; code[n++] = 1;
    code[n++] = VOP_VMEXIT;
    memset(&ctx, 0, sizeof(ctx));
    run(code, n, &ctx);
    CHECK(bits2d(ctx.vreg[1]) == 42.0, "mulsd 6.0*7.0 == 42.0");

    n = 0;
    code[n++] = VOP_PUSH_IMM; put_i64(code, &n, (int64_t)d2bits(84.0));
    code[n++] = VOP_PUSH_IMM; put_i64(code, &n, (int64_t)d2bits(2.0));
    code[n++] = VOP_DIVSD;
    code[n++] = VOP_POP_VREG; code[n++] = 1;
    code[n++] = VOP_VMEXIT;
    memset(&ctx, 0, sizeof(ctx));
    run(code, n, &ctx);
    CHECK(bits2d(ctx.vreg[1]) == 42.0, "divsd 84.0/2.0 == 42.0");

    /* ADDSS/SUBSS/MULSS/DIVSS: same shape, low 4 bytes of the slot; upper
     * 4 bytes must always come back zeroed (see isa.h). */
    n = 0;
    code[n++] = VOP_PUSH_IMM; put_i64(code, &n, (int64_t)f2bits(1.5f));
    code[n++] = VOP_PUSH_IMM; put_i64(code, &n, (int64_t)f2bits(2.5f));
    code[n++] = VOP_ADDSS;
    code[n++] = VOP_POP_VREG; code[n++] = 2;
    code[n++] = VOP_VMEXIT;
    memset(&ctx, 0, sizeof(ctx));
    run(code, n, &ctx);
    CHECK(bits2f(ctx.vreg[2]) == 4.0f, "addss 1.5f+2.5f == 4.0f");
    CHECK((ctx.vreg[2] >> 32) == 0, "addss zero-extends the upper 32 bits of the slot");

    n = 0;
    code[n++] = VOP_PUSH_IMM; put_i64(code, &n, (int64_t)f2bits(6.0f));
    code[n++] = VOP_PUSH_IMM; put_i64(code, &n, (int64_t)f2bits(7.0f));
    code[n++] = VOP_MULSS;
    code[n++] = VOP_POP_VREG; code[n++] = 2;
    code[n++] = VOP_VMEXIT;
    memset(&ctx, 0, sizeof(ctx));
    run(code, n, &ctx);
    CHECK(bits2f(ctx.vreg[2]) == 42.0f, "mulss 6.0f*7.0f == 42.0f");

    /* CVTSI2SD / CVTTSD2SI round trip */
    n = 0;
    code[n++] = VOP_PUSH_IMM; put_i64(code, &n, 42);
    code[n++] = VOP_CVTSI2SD;
    code[n++] = VOP_CVTTSD2SI;
    code[n++] = VOP_POP_VREG; code[n++] = 3;
    code[n++] = VOP_VMEXIT;
    memset(&ctx, 0, sizeof(ctx));
    run(code, n, &ctx);
    CHECK(ctx.vreg[3] == 42, "cvtsi2sd -> cvttsd2si round trip preserves 42");

    n = 0;
    code[n++] = VOP_PUSH_IMM; put_i64(code, &n, -7);
    code[n++] = VOP_CVTSI2SD;
    code[n++] = VOP_POP_VREG; code[n++] = 4; /* stash the bits to check the actual value */
    code[n++] = VOP_VMEXIT;
    memset(&ctx, 0, sizeof(ctx));
    run(code, n, &ctx);
    CHECK(bits2d(ctx.vreg[4]) == -7.0, "cvtsi2sd -7 == -7.0");

    /* CVTSI2SS / CVTTSS2SI round trip */
    n = 0;
    code[n++] = VOP_PUSH_IMM; put_i64(code, &n, 11);
    code[n++] = VOP_CVTSI2SS;
    code[n++] = VOP_CVTTSS2SI;
    code[n++] = VOP_POP_VREG; code[n++] = 5;
    code[n++] = VOP_VMEXIT;
    memset(&ctx, 0, sizeof(ctx));
    run(code, n, &ctx);
    CHECK(ctx.vreg[5] == 11, "cvtsi2ss -> cvttss2si round trip preserves 11");

    /* PUSH_XREG/POP_XREG: execution-local scratch slots round-trip raw bits */
    n = 0;
    code[n++] = VOP_PUSH_IMM; put_i64(code, &n, (int64_t)d2bits(3.25));
    code[n++] = VOP_POP_XREG; code[n++] = 2;
    code[n++] = VOP_PUSH_XREG; code[n++] = 2;
    code[n++] = VOP_POP_VREG; code[n++] = 6;
    code[n++] = VOP_VMEXIT;
    memset(&ctx, 0, sizeof(ctx));
    run(code, n, &ctx);
    CHECK(bits2d(ctx.vreg[6]) == 3.25, "push_xreg/pop_xreg round trip preserves bits");

    /* All of the above must be flag-transparent, matching native SSE
     * arithmetic/converts (which never touch integer RFLAGS at all). */
    n = 0;
    code[n++] = VOP_PUSH_IMM; put_i64(code, &n, 3);
    code[n++] = VOP_PUSH_IMM; put_i64(code, &n, 3);
    code[n++] = VOP_CMP; /* ZF=1 */
    code[n++] = VOP_PUSH_IMM; put_i64(code, &n, (int64_t)d2bits(1.0));
    code[n++] = VOP_PUSH_IMM; put_i64(code, &n, (int64_t)d2bits(2.0));
    code[n++] = VOP_ADDSD;
    code[n++] = VOP_POP_VREG; code[n++] = 7;
    code[n++] = VOP_VMEXIT;
    memset(&ctx, 0, sizeof(ctx));
    run(code, n, &ctx);
    CHECK((ctx.vflags & KARITY_FLAG_ZF) != 0, "addsd leaves vflags from a prior cmp untouched");
}

static void test_vmexit_rel(void)
{
    uint8_t code[32];
    size_t n = 0;
    int64_t delta = 0x1234;

    /* vreg[4] must NOT be touched: VOP_VMEXIT_REL exits before it, same as
     * plain VOP_VMEXIT would. */
    code[n++] = VOP_PUSH_IMM; put_i64(code, &n, 999);
    code[n++] = VOP_POP_VREG; code[n++] = 4;
    code[n++] = VOP_VMEXIT_REL;
    put_i64(code, &n, delta);
    code[n++] = VOP_PUSH_IMM; put_i64(code, &n, 0xBAD);
    code[n++] = VOP_POP_VREG; code[n++] = 4;
    code[n++] = VOP_VMEXIT;

    karity_vmctx ctx; memset(&ctx, 0, sizeof(ctx));
    ctx.anchor = 5000;
    run(code, n, &ctx);
    CHECK(ctx.vreg[4] == 999, "VOP_VMEXIT_REL exits before the dead code after it");
    CHECK(ctx.exit_target == ctx.anchor + (uint64_t)delta, "VOP_VMEXIT_REL sets ctx->exit_target = anchor + delta");
}

/* vstack overflow guard (see runtime/vm_thunk.S's header, isa.h's
 * vstack_limit comment, and karity_check_vstack_overflow above): a private
 * 8-slot (64-byte) vstack sandwiched between two canary regions, so a guard
 * that failed to stop an out-of-bounds write would corrupt one of them --
 * this test would then fail the canary checks below, not just the "did it
 * trap" check. */
static void test_vstack_overflow_guard(void)
{
    struct {
        uint8_t low_canary[16];
        uint8_t vstack[64];
        uint8_t high_canary[16];
    } buf;
    uint8_t code[256];
    size_t n;
    int i, ok;
    karity_vmctx ctx;

    memset(buf.low_canary, 0xCC, sizeof(buf.low_canary));
    memset(buf.high_canary, 0xCC, sizeof(buf.high_canary));

    /* Case 1: filling the 8-slot buffer exactly (8 pushes, no pops) must
     * NOT trap -- the guard must not be off-by-one and reject legitimate
     * use of the buffer's full capacity. */
    n = 0;
    for (i = 0; i < 8; i++) {
        code[n++] = VOP_PUSH_IMM;
        put_i64(code, &n, 100 + i);
    }
    code[n++] = VOP_VMEXIT;
    memset(&ctx, 0, sizeof(ctx));
    karity_bytecode_xor_crypt(code, n, 0, kTestSeed);
    ctx.vip = (uint64_t)(uintptr_t)code;
    ctx.vsp = (uint64_t)(uintptr_t)(buf.vstack + sizeof(buf.vstack));
    ctx.vstack_limit = (uint64_t)(uintptr_t)buf.vstack;
    ctx.bytecode_base = ctx.vip;
    ctx.bytecode_key_seed = kTestSeed;
    CHECK(!run_expect_maybe_trap(&ctx), "vstack guard: filling the buffer exactly to capacity does not trap");
    CHECK(ctx.vsp == (uint64_t)(uintptr_t)buf.vstack,
          "vstack guard: vsp lands exactly at vstack_limit after 8 pushes into an 8-slot buffer");

    /* Case 2: a 9th push -- one slot past capacity -- must trap, and must do
     * so *before* writing anywhere outside [vstack, vstack+64), verified via
     * the untouched canaries below. */
    n = 0;
    for (i = 0; i < 9; i++) {
        code[n++] = VOP_PUSH_IMM;
        put_i64(code, &n, 200 + i);
    }
    code[n++] = VOP_VMEXIT;
    memset(&ctx, 0, sizeof(ctx));
    karity_bytecode_xor_crypt(code, n, 0, kTestSeed);
    ctx.vip = (uint64_t)(uintptr_t)code;
    ctx.vsp = (uint64_t)(uintptr_t)(buf.vstack + sizeof(buf.vstack));
    ctx.vstack_limit = (uint64_t)(uintptr_t)buf.vstack;
    ctx.bytecode_base = ctx.vip;
    ctx.bytecode_key_seed = kTestSeed;
    CHECK(run_expect_maybe_trap(&ctx), "vstack guard: a 9th push into an 8-slot buffer traps");

    ok = 1;
    for (i = 0; i < 16; i++) if (buf.low_canary[i] != 0xCC) ok = 0;
    CHECK(ok, "vstack guard: overflow trap fires before corrupting memory below the buffer");

    ok = 1;
    for (i = 0; i < 16; i++) if (buf.high_canary[i] != 0xCC) ok = 0;
    CHECK(ok, "vstack guard: overflow trap fires before corrupting memory above the buffer");

    /* A zero-initialized ctx.vstack_limit (every other test in this file,
     * via `run`'s memset(&ctx, 0, ...)) must keep the pre-guard behavior:
     * the check never fires. Reuses the 9-push program from case 2 against
     * the file-scoped `run` helper's own (much larger, 256-byte) static
     * vstack, which has ample room for 9 slots regardless. */
    n = 0;
    for (i = 0; i < 9; i++) {
        code[n++] = VOP_PUSH_IMM;
        put_i64(code, &n, 300 + i);
    }
    code[n++] = VOP_VMEXIT;
    memset(&ctx, 0, sizeof(ctx));
    run(code, n, &ctx);
    CHECK(ctx.vstack_limit == 0, "vstack guard: default-zero ctx.vstack_limit is left alone by unrelated code paths");
}

int main(void)
{
    AddVectoredExceptionHandler(1, vstack_trap_veh);

    test_push_rel();
    test_sized_mem();
    test_call();
    test_call_ind();
    test_cmp_test_flags();
    test_neg_not();
    test_movzx_movsx();
    test_inc_dec();
    test_shift_rotate();
    test_mul_imul_div();
    test_sse();
    test_arith_sets_flags();
    test_jcc_conditions();
    test_vmexit_rel();
    test_vstack_overflow_guard();
    if (g_fail == 0) { printf("all new-op tests passed\n"); return 0; }
    fprintf(stderr, "%d failure(s)\n", g_fail);
    return 1;
}
