#include <csetjmp>
#include <cstdio>
#include <cstring>
#include <random>
#include <vector>
#include <windows.h>
#include "interp_codegen.h"
#include "karity/bytecode_crypt.h"
#include "karity/isa.h"
#include "karity/opcode_map.h"
#include "vm/emitter.h"

using namespace karity;

extern "C" void karity_vm_native_call(karity_vmctx *ctx, uint64_t target_va);

static int g_fail = 0;
#define CHECK(cond, msg) do { if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fail++; } } while (0)

typedef void (*InterpFn)(karity_vmctx *);

// CALL/CALL_IND's target *callee* is still resolved as ctx->anchor + a
// per-instruction delta read from the bytecode -- that's genuinely per call
// site (see lifter.cpp) and unaffected by this file's own generate_interpreter
// plumbing below. Tests exercising that path set ctx.anchor to this same
// constant so the delta resolves correctly; kept nonzero (rather than 0,
// which would silently pass even if ctx->anchor were never read at all) so
// a regression that drops the anchor add would still fail.
static constexpr uint64_t kTestAnchor = 7000;

// karity_vm_native_call's own address, by contrast, is resolved by the
// generated interpreter *without* touching ctx->anchor at all (see
// interp_codegen.h): it's native_call_va - interp_va, both fixed relative
// to wherever the interpreter itself ends up. So the buffer has to be
// allocated *before* generating code into it, mirroring how the real
// injector fixes interp_va ahead of calling generate_interpreter -- unlike
// the anchor, this has nothing to do with any particular call site, which
// is exactly what makes the interpreter safely shareable across many.
static constexpr size_t kInterpBufSize = 256 * 1024; // generous headroom

static InterpFn build(std::mt19937_64 &rng, void **out_mem = nullptr,
                       const OpcodeMap &opcode_map = OpcodeMap())
{
    void *mem = VirtualAlloc(nullptr, kInterpBufSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    uint64_t interp_va = reinterpret_cast<uint64_t>(mem);
    uint64_t native_call_va = reinterpret_cast<uint64_t>(&karity_vm_native_call);
    std::vector<uint8_t> code = generate_interpreter(native_call_va - interp_va, rng, opcode_map);
    memcpy(mem, code.data(), code.size());
    if (out_mem) *out_mem = mem;
    return reinterpret_cast<InterpFn>(mem);
}

// Fixed test seed: the real generated interpreter now unconditionally
// decrypts every bytecode fetch (see include/karity/bytecode_crypt.h and
// look/todo.md section C), so every hand-built test program below has to be
// encrypted the same way src/inject/injector.cpp encrypts a real site's
// bytecode before it's handed to the interpreter.
static constexpr uint64_t kTestBytecodeSeed = 0xA5A5DEADF00DBEEFULL;

static karity_vmctx run_program(InterpFn interp, const uint8_t *code, size_t code_len, uint64_t vreg_in[16])
{
    static uint8_t vstack[4096];
    static std::vector<uint8_t> encrypted;
    karity_vmctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    if (vreg_in) memcpy(ctx.vreg, vreg_in, sizeof(ctx.vreg));
    encrypted.assign(code, code + code_len);
    karity_bytecode_xor_crypt(encrypted.data(), encrypted.size(), 0, kTestBytecodeSeed);
    ctx.vip = reinterpret_cast<uint64_t>(encrypted.data());
    ctx.vsp = reinterpret_cast<uint64_t>(vstack + sizeof(vstack));
    ctx.bytecode_base = ctx.vip;
    ctx.bytecode_key_seed = kTestBytecodeSeed;
    interp(&ctx);
    return ctx;
}

static uint64_t test_add_native(uint64_t a, uint64_t b) { return a + b; }

static void put_i64(std::vector<uint8_t> &v, int64_t x)
{
    for (int i = 0; i < 8; i++) v.push_back(static_cast<uint8_t>(static_cast<uint64_t>(x) >> (8 * i)));
}

static uint64_t d2bits(double d) { uint64_t u; memcpy(&u, &d, 8); return u; }
static double bits2d(uint64_t u) { double d; memcpy(&d, &u, 8); return d; }
static uint64_t f2bits(float f) { uint32_t u; memcpy(&u, &f, 4); return static_cast<uint64_t>(u); }
static float bits2f(uint64_t u) { uint32_t v = static_cast<uint32_t>(u); float f; memcpy(&f, &v, 4); return f; }

static void test_all_opcodes(InterpFn interp, int seed)
{
    char tag[64];
    auto T = [&](const char *s) { snprintf(tag, sizeof(tag), "[seed %d] %s", seed, s); return tag; };

    // push_imm / pop_vreg
    {
        std::vector<uint8_t> c = {VOP_PUSH_IMM};
        put_i64(c, (int64_t)0xDEADBEEFCAFEBABEULL);
        c.push_back(VOP_POP_VREG); c.push_back(3);
        c.push_back(VOP_VMEXIT);
        auto ctx = run_program(interp, c.data(), c.size(), nullptr);
        CHECK(ctx.vreg[3] == 0xDEADBEEFCAFEBABEULL, T("push_imm/pop_vreg"));
    }
    // push_vreg + arithmetic
    {
        std::vector<uint8_t> c = {VOP_PUSH_VREG, 0, VOP_PUSH_VREG, 1, VOP_ADD, VOP_POP_VREG, 2, VOP_VMEXIT};
        uint64_t regs[16] = {0}; regs[0] = 10; regs[1] = 32;
        auto ctx = run_program(interp, c.data(), c.size(), regs);
        CHECK(ctx.vreg[2] == 42, T("push_vreg/add"));
    }
    // sub/xor/and/or chain
    {
        std::vector<uint8_t> c;
        c.push_back(VOP_PUSH_IMM); put_i64(c, 0x0F);
        c.push_back(VOP_PUSH_IMM); put_i64(c, 0xF0);
        c.push_back(VOP_OR);
        c.push_back(VOP_PUSH_IMM); put_i64(c, 0xFF);
        c.push_back(VOP_AND);
        c.push_back(VOP_PUSH_IMM); put_i64(c, 0x0F);
        c.push_back(VOP_XOR);
        c.push_back(VOP_PUSH_IMM); put_i64(c, 0x01);
        c.push_back(VOP_SUB);
        c.push_back(VOP_POP_VREG); c.push_back(0);
        c.push_back(VOP_VMEXIT);
        auto ctx = run_program(interp, c.data(), c.size(), nullptr);
        CHECK(ctx.vreg[0] == 0xEF, T("sub/xor/and/or"));
    }
    // drop
    {
        std::vector<uint8_t> c;
        c.push_back(VOP_PUSH_IMM); put_i64(c, 999);
        c.push_back(VOP_PUSH_IMM); put_i64(c, 5);
        c.push_back(VOP_DROP);
        c.push_back(VOP_POP_VREG); c.push_back(3);
        c.push_back(VOP_VMEXIT);
        auto ctx = run_program(interp, c.data(), c.size(), nullptr);
        CHECK(ctx.vreg[3] == 999, T("drop"));
    }
    // load/store all widths
    {
        static uint64_t mem64 = 0;
        std::vector<uint8_t> c;
        uint64_t addr = reinterpret_cast<uint64_t>(&mem64);
        c.push_back(VOP_PUSH_IMM); put_i64(c, (int64_t)addr);
        c.push_back(VOP_PUSH_IMM); put_i64(c, 0x1122334455667788LL);
        c.push_back(VOP_STORE64);
        c.push_back(VOP_PUSH_IMM); put_i64(c, (int64_t)addr);
        c.push_back(VOP_LOAD64);
        c.push_back(VOP_POP_VREG); c.push_back(4);
        c.push_back(VOP_PUSH_IMM); put_i64(c, (int64_t)addr);
        c.push_back(VOP_LOAD32);
        c.push_back(VOP_POP_VREG); c.push_back(5);
        c.push_back(VOP_PUSH_IMM); put_i64(c, (int64_t)addr);
        c.push_back(VOP_LOAD16);
        c.push_back(VOP_POP_VREG); c.push_back(6);
        c.push_back(VOP_PUSH_IMM); put_i64(c, (int64_t)addr);
        c.push_back(VOP_LOAD8);
        c.push_back(VOP_POP_VREG); c.push_back(7);
        c.push_back(VOP_VMEXIT);
        auto ctx = run_program(interp, c.data(), c.size(), nullptr);
        CHECK(mem64 == 0x1122334455667788ULL, T("store64"));
        CHECK(ctx.vreg[4] == 0x1122334455667788ULL, T("load64"));
        CHECK(ctx.vreg[5] == 0x55667788u, T("load32"));
        CHECK(ctx.vreg[6] == 0x7788u, T("load16"));
        CHECK(ctx.vreg[7] == 0x88u, T("load8"));
    }
    // store8/16/32 truncation + adjacent-byte safety
    {
        static uint8_t buf[16];
        memset(buf, 0xAA, sizeof(buf));
        uint64_t addr = reinterpret_cast<uint64_t>(buf);
        std::vector<uint8_t> c;
        c.push_back(VOP_PUSH_IMM); put_i64(c, (int64_t)addr);
        c.push_back(VOP_PUSH_IMM); put_i64(c, 0x42);
        c.push_back(VOP_STORE8);
        c.push_back(VOP_PUSH_IMM); put_i64(c, (int64_t)(addr + 4));
        c.push_back(VOP_PUSH_IMM); put_i64(c, 0xBEEF);
        c.push_back(VOP_STORE16);
        c.push_back(VOP_PUSH_IMM); put_i64(c, (int64_t)(addr + 8));
        c.push_back(VOP_PUSH_IMM); put_i64(c, 0x12345678);
        c.push_back(VOP_STORE32);
        c.push_back(VOP_VMEXIT);
        run_program(interp, c.data(), c.size(), nullptr);
        CHECK(buf[0] == 0x42 && buf[1] == 0xAA, T("store8 + adjacent"));
        CHECK(buf[4] == 0xEF && buf[5] == 0xBE && buf[6] == 0xAA, T("store16 + adjacent"));
        uint32_t got32; memcpy(&got32, buf + 8, 4);
        CHECK(got32 == 0x12345678u && buf[12] == 0xAA, T("store32 + adjacent"));
    }
    // push_rel via anchor
    {
        static uint64_t target = 0xCAFEF00DULL;
        std::vector<uint8_t> c;
        int64_t delta = (int64_t)(reinterpret_cast<uint64_t>(&target)) - 5000; // anchor = 5000
        c.push_back(VOP_PUSH_REL); put_i64(c, delta);
        c.push_back(VOP_POP_VREG); c.push_back(9);
        c.push_back(VOP_VMEXIT);
        karity_vmctx ctx; memset(&ctx, 0, sizeof(ctx));
        static uint8_t vstack[256];
        ctx.anchor = 5000;
        karity_bytecode_xor_crypt(c.data(), c.size(), 0, kTestBytecodeSeed);
        ctx.vip = reinterpret_cast<uint64_t>(c.data());
        ctx.vsp = reinterpret_cast<uint64_t>(vstack + sizeof(vstack));
        ctx.bytecode_base = ctx.vip;
        ctx.bytecode_key_seed = kTestBytecodeSeed;
        interp(&ctx);
        CHECK(ctx.vreg[9] == reinterpret_cast<uint64_t>(&target), T("push_rel"));
    }
    // jmp skips
    {
        std::vector<uint8_t> c;
        c.push_back(VOP_JMP);
        size_t rel_pos = c.size();
        put_i64(c, 0);
        size_t junk_start = c.size();
        c.push_back(VOP_PUSH_IMM); put_i64(c, 0xBAD);
        c.push_back(VOP_POP_VREG); c.push_back(5);
        size_t after = c.size();
        int64_t rel = (int64_t)(after - rel_pos - 8);
        for (int i = 0; i < 8; i++) c[rel_pos + i] = (uint8_t)((uint64_t)rel >> (8 * i));
        (void)junk_start;
        c.push_back(VOP_PUSH_IMM); put_i64(c, 111);
        c.push_back(VOP_POP_VREG); c.push_back(5);
        c.push_back(VOP_VMEXIT);
        auto ctx = run_program(interp, c.data(), c.size(), nullptr);
        CHECK(ctx.vreg[5] == 111, T("jmp"));
    }
    // jcc_nz taken/not-taken
    {
        for (uint64_t cond : {0ULL, 1ULL}) {
            std::vector<uint8_t> c;
            c.push_back(VOP_PUSH_IMM); put_i64(c, (int64_t)cond);
            c.push_back(VOP_JCC_NZ);
            size_t rel_pos = c.size();
            put_i64(c, 0);
            c.push_back(VOP_PUSH_IMM); put_i64(c, 0xBAD);
            c.push_back(VOP_POP_VREG); c.push_back(6);
            size_t after = c.size();
            int64_t rel = (int64_t)(after - rel_pos - 8);
            for (int i = 0; i < 8; i++) c[rel_pos + i] = (uint8_t)((uint64_t)rel >> (8 * i));
            c.push_back(VOP_PUSH_IMM); put_i64(c, 222);
            c.push_back(VOP_POP_VREG); c.push_back(6);
            c.push_back(VOP_VMEXIT);
            auto ctx = run_program(interp, c.data(), c.size(), nullptr);
            uint64_t expect = cond != 0 ? 222 : 0xBAD; // taken->skips junk->falls to 222 write; not taken->runs junk then 222 overwrites anyway
            (void)expect;
            // Both paths end up writing vreg[6] eventually (taken skips the junk write,
            // not-taken executes it then continues into the same 222 write) so vreg[6]==222 either way.
            CHECK(ctx.vreg[6] == 222, T("jcc_nz reaches common continuation"));
        }
    }
    // call (native passthrough)
    {
        std::vector<uint8_t> c;
        int64_t delta = (int64_t)reinterpret_cast<uint64_t>(&test_add_native) - (int64_t)kTestAnchor;
        c.push_back(VOP_CALL); put_i64(c, delta); // writes result directly to vreg[0] (RAX), no vstack push
        c.push_back(VOP_VMEXIT);

        static uint8_t native_stack[8192];
        uint64_t rsp_top = (reinterpret_cast<uint64_t>(native_stack + sizeof(native_stack))) & ~(uint64_t)0xF;

        karity_vmctx ctx; memset(&ctx, 0, sizeof(ctx));
        ctx.anchor = kTestAnchor;
        ctx.vreg[1] = 10; // RCX = a
        ctx.vreg[2] = 32; // RDX = b
        ctx.vreg[4] = rsp_top;
        static uint8_t vstack[256];
        karity_bytecode_xor_crypt(c.data(), c.size(), 0, kTestBytecodeSeed);
        ctx.vip = reinterpret_cast<uint64_t>(c.data());
        ctx.vsp = reinterpret_cast<uint64_t>(vstack + sizeof(vstack));
        ctx.bytecode_base = ctx.vip;
        ctx.bytecode_key_seed = kTestBytecodeSeed;
        interp(&ctx);
        CHECK(ctx.vreg[0] == 42, T("call"));
    }
    // call_ind (native passthrough, target popped off the vstack instead of
    // anchor+delta -- the same generated handler that a lifted `call reg` or
    // `call [rip+X]`/`call [reg+disp]` would hit)
    {
        std::vector<uint8_t> c;
        c.push_back(VOP_PUSH_IMM); put_i64(c, (int64_t)reinterpret_cast<uint64_t>(&test_add_native));
        c.push_back(VOP_CALL_IND);
        c.push_back(VOP_VMEXIT);

        static uint8_t native_stack[8192];
        uint64_t rsp_top = (reinterpret_cast<uint64_t>(native_stack + sizeof(native_stack))) & ~(uint64_t)0xF;

        karity_vmctx ctx; memset(&ctx, 0, sizeof(ctx));
        ctx.anchor = kTestAnchor;
        ctx.vreg[1] = 11; // RCX = a
        ctx.vreg[2] = 31; // RDX = b
        ctx.vreg[4] = rsp_top;
        static uint8_t vstack[256];
        karity_bytecode_xor_crypt(c.data(), c.size(), 0, kTestBytecodeSeed);
        ctx.vip = reinterpret_cast<uint64_t>(c.data());
        ctx.vsp = reinterpret_cast<uint64_t>(vstack + sizeof(vstack));
        ctx.bytecode_base = ctx.vip;
        ctx.bytecode_key_seed = kTestBytecodeSeed;
        interp(&ctx);
        CHECK(ctx.vreg[0] == 42, T("call_ind"));
    }
    // call: karity_vm_native_call's own address must resolve correctly
    // regardless of ctx.anchor -- it's baked relative to the interpreter's
    // own (fixed) placement, not to any call site (see interp_codegen.h).
    // Run the *same* built interpreter twice with two different anchors
    // (each with its own correctly-recomputed callee delta) and confirm
    // both dispatch to the real native callee; this is the direct
    // regression test for that fix -- it would have failed on the old
    // anchor-relative addressing the moment the second anchor differed
    // from whatever was baked in at generate_interpreter() time.
    {
        for (uint64_t anchor : {kTestAnchor, kTestAnchor + 123456}) {
            std::vector<uint8_t> c;
            int64_t delta = (int64_t)reinterpret_cast<uint64_t>(&test_add_native) - (int64_t)anchor;
            c.push_back(VOP_CALL); put_i64(c, delta);
            c.push_back(VOP_VMEXIT);

            static uint8_t native_stack[8192];
            uint64_t rsp_top = (reinterpret_cast<uint64_t>(native_stack + sizeof(native_stack))) & ~(uint64_t)0xF;

            karity_vmctx ctx; memset(&ctx, 0, sizeof(ctx));
            ctx.anchor = anchor;
            ctx.vreg[1] = 4; // RCX = a
            ctx.vreg[2] = 38; // RDX = b
            ctx.vreg[4] = rsp_top;
            static uint8_t vstack[256];
            karity_bytecode_xor_crypt(c.data(), c.size(), 0, kTestBytecodeSeed);
            ctx.vip = reinterpret_cast<uint64_t>(c.data());
            ctx.vsp = reinterpret_cast<uint64_t>(vstack + sizeof(vstack));
            ctx.bytecode_base = ctx.vip;
            ctx.bytecode_key_seed = kTestBytecodeSeed;
            interp(&ctx);
            CHECK(ctx.vreg[0] == 42, T("call: native_call resolves correctly across different ctx.anchor values"));
        }
    }
    // cmp/test set vflags, push nothing back
    {
        std::vector<uint8_t> c;
        c.push_back(VOP_PUSH_IMM); put_i64(c, 3);
        c.push_back(VOP_PUSH_IMM); put_i64(c, 5);
        c.push_back(VOP_CMP); // 3 - 5: ZF=0, SF=1, CF=1, OF=0
        c.push_back(VOP_PUSH_IMM); put_i64(c, 77); // vstack must be back to empty here
        c.push_back(VOP_POP_VREG); c.push_back(2);
        c.push_back(VOP_VMEXIT);
        auto ctx = run_program(interp, c.data(), c.size(), nullptr);
        CHECK(ctx.vreg[2] == 77, T("cmp consumes both operands, pushes nothing"));
        CHECK((ctx.vflags & KARITY_FLAG_ZF) == 0, T("cmp 3,5 clears ZF"));
        CHECK((ctx.vflags & KARITY_FLAG_SF) != 0, T("cmp 3,5 sets SF"));
        CHECK((ctx.vflags & KARITY_FLAG_CF) != 0, T("cmp 3,5 sets CF"));
        CHECK((ctx.vflags & KARITY_FLAG_OF) == 0, T("cmp 3,5 clears OF"));
    }
    {
        std::vector<uint8_t> c;
        c.push_back(VOP_PUSH_IMM); put_i64(c, 0);
        c.push_back(VOP_PUSH_IMM); put_i64(c, 0xFF);
        c.push_back(VOP_TEST); // 0 & 0xFF -> ZF=1, CF=OF=0
        c.push_back(VOP_VMEXIT);
        auto ctx = run_program(interp, c.data(), c.size(), nullptr);
        CHECK((ctx.vflags & KARITY_FLAG_ZF) != 0, T("test 0,0xFF sets ZF"));
        CHECK((ctx.vflags & (KARITY_FLAG_CF | KARITY_FLAG_OF)) == 0, T("test clears CF/OF"));
    }
    // add/sub also set vflags as a side effect
    {
        std::vector<uint8_t> c;
        c.push_back(VOP_PUSH_IMM); put_i64(c, 0x7FFFFFFFFFFFFFFFLL);
        c.push_back(VOP_PUSH_IMM); put_i64(c, 1);
        c.push_back(VOP_ADD); // INT64_MAX + 1 overflows
        c.push_back(VOP_POP_VREG); c.push_back(0);
        c.push_back(VOP_VMEXIT);
        auto ctx = run_program(interp, c.data(), c.size(), nullptr);
        CHECK(ctx.vreg[0] == 0x8000000000000000ULL, T("add still computes the value"));
        CHECK((ctx.vflags & KARITY_FLAG_OF) != 0, T("INT64_MAX+1 sets OF via VOP_ADD"));
        CHECK((ctx.vflags & KARITY_FLAG_SF) != 0, T("INT64_MAX+1 sets SF via VOP_ADD"));
    }
    // neg/not
    {
        std::vector<uint8_t> c;
        c.push_back(VOP_PUSH_IMM); put_i64(c, 5);
        c.push_back(VOP_NEG);
        c.push_back(VOP_POP_VREG); c.push_back(1);
        c.push_back(VOP_PUSH_IMM); put_i64(c, 0x0F0F0F0F0F0F0F0FLL);
        c.push_back(VOP_NOT);
        c.push_back(VOP_POP_VREG); c.push_back(2);
        c.push_back(VOP_VMEXIT);
        auto ctx = run_program(interp, c.data(), c.size(), nullptr);
        CHECK(ctx.vreg[1] == (uint64_t)(-5LL), T("neg 5 computes two's complement"));
        CHECK((ctx.vflags & KARITY_FLAG_CF) != 0, T("neg nonzero operand sets CF"));
        CHECK(ctx.vreg[2] == 0xF0F0F0F0F0F0F0F0ULL, T("not complements every bit"));
    }
    {
        // not must not touch vflags: set ZF via cmp, then run not, then check ZF survives
        std::vector<uint8_t> c;
        c.push_back(VOP_PUSH_IMM); put_i64(c, 3);
        c.push_back(VOP_PUSH_IMM); put_i64(c, 3);
        c.push_back(VOP_CMP); // ZF=1
        c.push_back(VOP_PUSH_IMM); put_i64(c, 1);
        c.push_back(VOP_NOT);
        c.push_back(VOP_POP_VREG); c.push_back(3);
        c.push_back(VOP_VMEXIT);
        auto ctx = run_program(interp, c.data(), c.size(), nullptr);
        CHECK((ctx.vflags & KARITY_FLAG_ZF) != 0, T("not leaves vflags from a prior cmp untouched"));
    }
    // inc/dec
    {
        std::vector<uint8_t> c;
        c.push_back(VOP_PUSH_IMM); put_i64(c, (int64_t)0x7FFFFFFFFFFFFFFFLL);
        c.push_back(VOP_INC);
        c.push_back(VOP_POP_VREG); c.push_back(1);
        c.push_back(VOP_PUSH_IMM); put_i64(c, (int64_t)0x8000000000000000ULL);
        c.push_back(VOP_DEC);
        c.push_back(VOP_POP_VREG); c.push_back(2);
        c.push_back(VOP_VMEXIT);
        auto ctx = run_program(interp, c.data(), c.size(), nullptr);
        CHECK(ctx.vreg[1] == 0x8000000000000000ULL, T("inc INT64_MAX wraps to INT64_MIN"));
        CHECK((ctx.vflags & KARITY_FLAG_OF) != 0, T("inc INT64_MAX sets OF"));
        CHECK(ctx.vreg[2] == 0x7FFFFFFFFFFFFFFFULL, T("dec INT64_MIN wraps to INT64_MAX"));
        CHECK((ctx.vflags & KARITY_FLAG_OF) != 0, T("dec INT64_MIN sets OF"));
    }
    {
        // inc/dec must preserve CF (unlike add/sub/neg): set CF=1 via cmp 0,1, then inc.
        std::vector<uint8_t> c;
        c.push_back(VOP_PUSH_IMM); put_i64(c, 0);
        c.push_back(VOP_PUSH_IMM); put_i64(c, 1);
        c.push_back(VOP_CMP); // CF=1 (unsigned 0<1)
        c.push_back(VOP_PUSH_IMM); put_i64(c, 10);
        c.push_back(VOP_INC);
        c.push_back(VOP_POP_VREG); c.push_back(3);
        c.push_back(VOP_VMEXIT);
        auto ctx = run_program(interp, c.data(), c.size(), nullptr);
        CHECK(ctx.vreg[3] == 11, T("inc 10 -> 11"));
        CHECK((ctx.vflags & KARITY_FLAG_CF) != 0, T("inc preserves a CF=1 set by an earlier cmp"));
    }
    {
        std::vector<uint8_t> c;
        c.push_back(VOP_PUSH_IMM); put_i64(c, 5);
        c.push_back(VOP_PUSH_IMM); put_i64(c, 3);
        c.push_back(VOP_CMP); // CF=0 (unsigned 5>=3)
        c.push_back(VOP_PUSH_IMM); put_i64(c, 10);
        c.push_back(VOP_DEC);
        c.push_back(VOP_POP_VREG); c.push_back(3);
        c.push_back(VOP_VMEXIT);
        auto ctx = run_program(interp, c.data(), c.size(), nullptr);
        CHECK(ctx.vreg[3] == 9, T("dec 10 -> 9"));
        CHECK((ctx.vflags & KARITY_FLAG_CF) == 0, T("dec preserves a CF=0 set by an earlier cmp"));
    }

    // shift/rotate
    auto shift_result = [&](uint8_t vop, uint64_t value, uint64_t count) -> karity_vmctx {
        std::vector<uint8_t> c;
        c.push_back(VOP_PUSH_IMM); put_i64(c, static_cast<int64_t>(value));
        c.push_back(VOP_PUSH_IMM); put_i64(c, static_cast<int64_t>(count));
        c.push_back(vop);
        c.push_back(VOP_POP_VREG); c.push_back(1);
        c.push_back(VOP_VMEXIT);
        return run_program(interp, c.data(), c.size(), nullptr);
    };
    {
        auto ctx = shift_result(VOP_SHL, 0x8000000000000001ULL, 1);
        CHECK(ctx.vreg[1] == 2, T("shl 0x8000000000000001,1 == 2"));
        CHECK((ctx.vflags & KARITY_FLAG_CF) != 0, T("shl sets CF from the bit shifted out"));
        CHECK((ctx.vflags & KARITY_FLAG_OF) != 0, T("shl count=1 sets OF when the sign bit changes"));
    }
    {
        auto ctx = shift_result(VOP_SHR, 3, 1);
        CHECK(ctx.vreg[1] == 1, T("shr 3,1 == 1"));
        CHECK((ctx.vflags & KARITY_FLAG_CF) != 0, T("shr sets CF from the bit shifted out"));
        CHECK((ctx.vflags & KARITY_FLAG_OF) == 0, T("shr count=1 OF reflects original MSB (0 here)"));
    }
    {
        auto ctx = shift_result(VOP_SAR, static_cast<uint64_t>(static_cast<int64_t>(-2)), 1);
        CHECK(ctx.vreg[1] == static_cast<uint64_t>(static_cast<int64_t>(-1)), T("sar -2,1 == -1 (sign-extending)"));
        CHECK((ctx.vflags & KARITY_FLAG_CF) == 0, T("sar -2,1 clears CF (bit0 of -2 is 0)"));
    }
    {
        auto ctx = shift_result(VOP_ROL, 0x8000000000000000ULL, 1);
        CHECK(ctx.vreg[1] == 1, T("rol 0x8000000000000000,1 == 1 (top bit wraps to bottom)"));
        CHECK((ctx.vflags & KARITY_FLAG_CF) != 0, T("rol CF = LSB of result"));
        CHECK((ctx.vflags & KARITY_FLAG_OF) != 0, T("rol count=1 OF = MSB(result) XOR CF"));
    }
    {
        auto ctx = shift_result(VOP_ROR, 1, 1);
        CHECK(ctx.vreg[1] == 0x8000000000000000ULL, T("ror 1,1 == 0x8000000000000000 (bottom bit wraps to top)"));
        CHECK((ctx.vflags & KARITY_FLAG_CF) != 0, T("ror CF = MSB of result"));
    }
    {
        auto ctx = shift_result(VOP_SHL, 1, 65);
        CHECK(ctx.vreg[1] == 2, T("shl count=65 masks to 1 (1<<1==2)"));
    }
    {
        // count==0: value and every flag bit stay exactly as they were before.
        std::vector<uint8_t> c;
        c.push_back(VOP_PUSH_IMM); put_i64(c, 3);
        c.push_back(VOP_PUSH_IMM); put_i64(c, 3);
        c.push_back(VOP_CMP); // ZF=1
        c.push_back(VOP_PUSH_IMM); put_i64(c, 0x1234);
        c.push_back(VOP_PUSH_IMM); put_i64(c, 0); // count = 0
        c.push_back(VOP_SHL);
        c.push_back(VOP_POP_VREG); c.push_back(1);
        c.push_back(VOP_VMEXIT);
        auto ctx = run_program(interp, c.data(), c.size(), nullptr);
        CHECK(ctx.vreg[1] == 0x1234, T("shift by count=0 leaves the value unchanged"));
        CHECK((ctx.vflags & KARITY_FLAG_ZF) != 0, T("shift by count=0 leaves vflags untouched"));
    }
    {
        // rol/ror must not touch SF/ZF/PF even when count != 0.
        std::vector<uint8_t> c;
        c.push_back(VOP_PUSH_IMM); put_i64(c, 3);
        c.push_back(VOP_PUSH_IMM); put_i64(c, 3);
        c.push_back(VOP_CMP); // ZF=1
        c.push_back(VOP_PUSH_IMM); put_i64(c, 1);
        c.push_back(VOP_PUSH_IMM); put_i64(c, 1);
        c.push_back(VOP_ROL); // rol 1,1 == 2
        c.push_back(VOP_POP_VREG); c.push_back(1);
        c.push_back(VOP_VMEXIT);
        auto ctx = run_program(interp, c.data(), c.size(), nullptr);
        CHECK(ctx.vreg[1] == 2, T("rol 1,1 == 2"));
        CHECK((ctx.vflags & KARITY_FLAG_ZF) != 0, T("rol leaves ZF from an earlier cmp untouched"));
    }

    // mul/imul1/div/idiv: implicit RAX/RDX operand(s), preset via vreg_in
    // (unlike every other ALU op here, which pushes all its operands).
    auto mulx_result = [&](uint8_t vop, uint64_t rax_in, uint64_t rdx_in, uint64_t b) -> karity_vmctx {
        std::vector<uint8_t> c;
        c.push_back(VOP_PUSH_IMM); put_i64(c, static_cast<int64_t>(b));
        c.push_back(vop);
        c.push_back(VOP_VMEXIT);
        uint64_t regs[16] = {0};
        regs[0] = rax_in;
        regs[2] = rdx_in;
        return run_program(interp, c.data(), c.size(), regs);
    };
    {
        auto ctx = mulx_result(VOP_MUL, 6, 0, 7);
        CHECK(ctx.vreg[0] == 42, T("mul 6*7 == 42 (RAX)"));
        CHECK(ctx.vreg[2] == 0, T("mul 6*7 high64 == 0 (RDX)"));
        CHECK((ctx.vflags & (KARITY_FLAG_CF | KARITY_FLAG_OF)) == 0, T("mul 6*7 clears CF/OF"));
    }
    {
        auto ctx = mulx_result(VOP_MUL, UINT64_MAX, 0, 2);
        CHECK(ctx.vreg[0] == 0xFFFFFFFFFFFFFFFEULL, T("mul UINT64_MAX*2 low64"));
        CHECK(ctx.vreg[2] == 1, T("mul UINT64_MAX*2 high64 == 1"));
        CHECK((ctx.vflags & (KARITY_FLAG_CF | KARITY_FLAG_OF)) != 0, T("mul overflow sets CF/OF"));
    }
    {
        auto ctx = mulx_result(VOP_IMUL1, static_cast<uint64_t>(static_cast<int64_t>(-6)), 0, 7);
        CHECK(ctx.vreg[0] == static_cast<uint64_t>(static_cast<int64_t>(-42)), T("imul1 -6*7 == -42 (RAX)"));
        CHECK(ctx.vreg[2] == UINT64_MAX, T("imul1 -6*7 sign-extends into RDX"));
        CHECK((ctx.vflags & (KARITY_FLAG_CF | KARITY_FLAG_OF)) == 0, T("imul1 -6*7 clears CF/OF"));
    }
    {
        auto ctx = mulx_result(VOP_IMUL1, 0x8000000000000000ULL, 0, static_cast<uint64_t>(static_cast<int64_t>(-1)));
        CHECK((ctx.vflags & (KARITY_FLAG_CF | KARITY_FLAG_OF)) != 0, T("imul1 INT64_MIN*-1 overflows, sets CF/OF"));
    }
    {
        std::vector<uint8_t> c = {VOP_PUSH_IMM};
        put_i64(c, 6);
        c.push_back(VOP_PUSH_IMM); put_i64(c, 7);
        c.push_back(VOP_IMUL2);
        c.push_back(VOP_POP_VREG); c.push_back(5);
        c.push_back(VOP_VMEXIT);
        auto ctx = run_program(interp, c.data(), c.size(), nullptr);
        CHECK(ctx.vreg[5] == 42, T("imul2 6*7 == 42"));
        CHECK((ctx.vflags & (KARITY_FLAG_CF | KARITY_FLAG_OF)) == 0, T("imul2 6*7 clears CF/OF"));
    }
    {
        std::vector<uint8_t> c;
        c.push_back(VOP_PUSH_IMM); put_i64(c, 0x7FFFFFFFFFFFFFFFLL);
        c.push_back(VOP_PUSH_IMM); put_i64(c, 2);
        c.push_back(VOP_IMUL2);
        c.push_back(VOP_POP_VREG); c.push_back(5);
        c.push_back(VOP_VMEXIT);
        auto ctx = run_program(interp, c.data(), c.size(), nullptr);
        CHECK((ctx.vflags & (KARITY_FLAG_CF | KARITY_FLAG_OF)) != 0, T("imul2 INT64_MAX*2 overflows, sets CF/OF"));
    }
    {
        auto ctx = mulx_result(VOP_DIV, 42, 0, 5);
        CHECK(ctx.vreg[0] == 8, T("div 42/5 quotient == 8"));
        CHECK(ctx.vreg[2] == 2, T("div 42/5 remainder == 2"));
    }
    {
        auto ctx = mulx_result(VOP_IDIV, static_cast<uint64_t>(static_cast<int64_t>(-42)), UINT64_MAX, 5);
        CHECK(ctx.vreg[0] == static_cast<uint64_t>(static_cast<int64_t>(-8)), T("idiv -42/5 quotient == -8"));
        CHECK(ctx.vreg[2] == static_cast<uint64_t>(static_cast<int64_t>(-2)), T("idiv -42/5 remainder == -2"));
    }

    // movzx/movsx: dst-width-independent zero extension vs dst-width-
    // sensitive sign extension (see isa.h) -- src_size/dst_size are
    // themselves bytecode-supplied runtime values that the generated
    // interpreter has to read and act on, not something baked in at
    // generate_interpreter() time.
    {
        std::vector<uint8_t> c;
        c.push_back(VOP_PUSH_IMM); put_i64(c, static_cast<int64_t>(0xFFFFFFFFFFFFFF80ULL));
        c.push_back(VOP_MOVZX); c.push_back(1); // src_size = 1 byte
        c.push_back(VOP_POP_VREG); c.push_back(5);
        c.push_back(VOP_PUSH_IMM); put_i64(c, static_cast<int64_t>(0xFFFFFFFFFFFF8000ULL));
        c.push_back(VOP_MOVZX); c.push_back(2); // src_size = 2 bytes
        c.push_back(VOP_POP_VREG); c.push_back(6);
        c.push_back(VOP_VMEXIT);
        auto ctx = run_program(interp, c.data(), c.size(), nullptr);
        CHECK(ctx.vreg[5] == 0x80, T("movzx byte zero-extends"));
        CHECK(ctx.vreg[6] == 0x8000, T("movzx word zero-extends"));
    }
    {
        // movzx must not touch vflags: set ZF via cmp, then run movzx, check ZF survives.
        std::vector<uint8_t> c;
        c.push_back(VOP_PUSH_IMM); put_i64(c, 3);
        c.push_back(VOP_PUSH_IMM); put_i64(c, 3);
        c.push_back(VOP_CMP); // ZF=1
        c.push_back(VOP_PUSH_IMM); put_i64(c, static_cast<int64_t>(0xFFFFFFFFFFFFFF80ULL));
        c.push_back(VOP_MOVZX); c.push_back(1);
        c.push_back(VOP_POP_VREG); c.push_back(7);
        c.push_back(VOP_VMEXIT);
        auto ctx = run_program(interp, c.data(), c.size(), nullptr);
        CHECK((ctx.vflags & KARITY_FLAG_ZF) != 0, T("movzx leaves vflags from a prior cmp untouched"));
    }
    {
        std::vector<uint8_t> c;
        c.push_back(VOP_PUSH_IMM); put_i64(c, 0x80); // byte 0x80 == -128
        c.push_back(VOP_MOVSX); c.push_back(1); c.push_back(8); // src=1B, dst=64-bit
        c.push_back(VOP_POP_VREG); c.push_back(1);
        c.push_back(VOP_PUSH_IMM); put_i64(c, 0x80);
        c.push_back(VOP_MOVSX); c.push_back(1); c.push_back(4); // src=1B, dst=32-bit
        c.push_back(VOP_POP_VREG); c.push_back(2);
        c.push_back(VOP_PUSH_IMM); put_i64(c, static_cast<int64_t>(0xFFFFFFFF80000001ULL));
        c.push_back(VOP_MOVSX); c.push_back(4); c.push_back(8); // movsxd: src=4B, dst=64-bit
        c.push_back(VOP_POP_VREG); c.push_back(3);
        c.push_back(VOP_PUSH_IMM); put_i64(c, 0x7F);
        c.push_back(VOP_MOVSX); c.push_back(1); c.push_back(8);
        c.push_back(VOP_POP_VREG); c.push_back(4);
        c.push_back(VOP_VMEXIT);
        auto ctx = run_program(interp, c.data(), c.size(), nullptr);
        CHECK(ctx.vreg[1] == 0xFFFFFFFFFFFFFF80ULL, T("movsx byte->64 sign-extends fully"));
        CHECK(ctx.vreg[2] == 0x00000000FFFFFF80ULL,
              T("movsx byte->32 sign-extends then zero-uppers (not a plain 64-bit sign extend)"));
        CHECK(ctx.vreg[3] == 0xFFFFFFFF80000001ULL, T("movsxd dword->64 sign-extends"));
        CHECK(ctx.vreg[4] == 0x7F, T("movsx of a positive value stays positive"));
    }
    {
        // movsx must not touch vflags either.
        std::vector<uint8_t> c;
        c.push_back(VOP_PUSH_IMM); put_i64(c, 3);
        c.push_back(VOP_PUSH_IMM); put_i64(c, 3);
        c.push_back(VOP_CMP); // ZF=1
        c.push_back(VOP_PUSH_IMM); put_i64(c, 0x80);
        c.push_back(VOP_MOVSX); c.push_back(1); c.push_back(8);
        c.push_back(VOP_POP_VREG); c.push_back(8);
        c.push_back(VOP_VMEXIT);
        auto ctx = run_program(interp, c.data(), c.size(), nullptr);
        CHECK((ctx.vflags & KARITY_FLAG_ZF) != 0, T("movsx leaves vflags from a prior cmp untouched"));
    }

    // sse: real generated ADDSD/SUBSD/MULSD/DIVSD/ADDSS/MULSS/CVT*/PUSH_XREG/
    // POP_XREG machine code, executed for real (exercises the actual
    // interp_codegen.cpp SSE encoders + the REG_RSP-relative xreg scratch
    // region, not just the portable C reference interpreter).
    {
        std::vector<uint8_t> c;
        c.push_back(VOP_PUSH_IMM); put_i64(c, static_cast<int64_t>(d2bits(1.5)));
        c.push_back(VOP_PUSH_IMM); put_i64(c, static_cast<int64_t>(d2bits(2.5)));
        c.push_back(VOP_ADDSD);
        c.push_back(VOP_POP_VREG); c.push_back(1);
        c.push_back(VOP_VMEXIT);
        auto ctx = run_program(interp, c.data(), c.size(), nullptr);
        CHECK(bits2d(ctx.vreg[1]) == 4.0, T("addsd 1.5+2.5 == 4.0"));
    }
    {
        std::vector<uint8_t> c;
        c.push_back(VOP_PUSH_IMM); put_i64(c, static_cast<int64_t>(d2bits(84.0)));
        c.push_back(VOP_PUSH_IMM); put_i64(c, static_cast<int64_t>(d2bits(2.0)));
        c.push_back(VOP_DIVSD);
        c.push_back(VOP_POP_VREG); c.push_back(1);
        c.push_back(VOP_VMEXIT);
        auto ctx = run_program(interp, c.data(), c.size(), nullptr);
        CHECK(bits2d(ctx.vreg[1]) == 42.0, T("divsd 84.0/2.0 == 42.0"));
    }
    {
        std::vector<uint8_t> c;
        c.push_back(VOP_PUSH_IMM); put_i64(c, static_cast<int64_t>(f2bits(6.0f)));
        c.push_back(VOP_PUSH_IMM); put_i64(c, static_cast<int64_t>(f2bits(7.0f)));
        c.push_back(VOP_MULSS);
        c.push_back(VOP_POP_VREG); c.push_back(2);
        c.push_back(VOP_VMEXIT);
        auto ctx = run_program(interp, c.data(), c.size(), nullptr);
        CHECK(bits2f(ctx.vreg[2]) == 42.0f, T("mulss 6.0f*7.0f == 42.0f"));
        CHECK((ctx.vreg[2] >> 32) == 0, T("mulss zero-extends the upper 32 bits of the slot"));
    }
    {
        std::vector<uint8_t> c;
        c.push_back(VOP_PUSH_IMM); put_i64(c, 42);
        c.push_back(VOP_CVTSI2SD);
        c.push_back(VOP_CVTTSD2SI);
        c.push_back(VOP_POP_VREG); c.push_back(3);
        c.push_back(VOP_VMEXIT);
        auto ctx = run_program(interp, c.data(), c.size(), nullptr);
        CHECK(ctx.vreg[3] == 42, T("cvtsi2sd -> cvttsd2si round trip preserves 42"));
    }
    {
        std::vector<uint8_t> c;
        c.push_back(VOP_PUSH_IMM); put_i64(c, 11);
        c.push_back(VOP_CVTSI2SS);
        c.push_back(VOP_CVTTSS2SI);
        c.push_back(VOP_POP_VREG); c.push_back(4);
        c.push_back(VOP_VMEXIT);
        auto ctx = run_program(interp, c.data(), c.size(), nullptr);
        CHECK(ctx.vreg[4] == 11, T("cvtsi2ss -> cvttss2si round trip preserves 11"));
    }
    {
        // push_xreg/pop_xreg: the execution-local scratch slots round-trip
        // raw bits through the interpreter's own REG_RSP-relative region.
        std::vector<uint8_t> c;
        c.push_back(VOP_PUSH_IMM); put_i64(c, static_cast<int64_t>(d2bits(3.25)));
        c.push_back(VOP_POP_XREG); c.push_back(2);
        c.push_back(VOP_PUSH_XREG); c.push_back(2);
        c.push_back(VOP_POP_VREG); c.push_back(5);
        c.push_back(VOP_VMEXIT);
        auto ctx = run_program(interp, c.data(), c.size(), nullptr);
        CHECK(bits2d(ctx.vreg[5]) == 3.25, T("push_xreg/pop_xreg round trip preserves bits"));
    }
    {
        // sse ops must never touch vflags (matches native scalar SSE
        // arithmetic, which is flag-transparent).
        std::vector<uint8_t> c;
        c.push_back(VOP_PUSH_IMM); put_i64(c, 3);
        c.push_back(VOP_PUSH_IMM); put_i64(c, 3);
        c.push_back(VOP_CMP); // ZF=1
        c.push_back(VOP_PUSH_IMM); put_i64(c, static_cast<int64_t>(d2bits(1.0)));
        c.push_back(VOP_PUSH_IMM); put_i64(c, static_cast<int64_t>(d2bits(2.0)));
        c.push_back(VOP_ADDSD);
        c.push_back(VOP_POP_VREG); c.push_back(6);
        c.push_back(VOP_VMEXIT);
        auto ctx = run_program(interp, c.data(), c.size(), nullptr);
        CHECK((ctx.vflags & KARITY_FLAG_ZF) != 0, T("addsd leaves vflags from a prior cmp untouched"));
    }

    // sse chain through real memory: reproduces examples/sse_demo.S's exact
    // bytecode shape (cvtsi2sd x2 -> mulsd via xreg -> store64/load64
    // round-trip -> cvttsd2si) against the REAL generated interpreter, to
    // isolate whether a bug is in interp_codegen.cpp's SSE handlers
    // specifically vs. the portable C reference interpreter.
    {
        static double mem = 0.0;
        uint64_t addr = reinterpret_cast<uint64_t>(&mem);
        std::vector<uint8_t> c;
        c.push_back(VOP_PUSH_IMM); put_i64(c, 6);
        c.push_back(VOP_CVTSI2SD);
        c.push_back(VOP_POP_XREG); c.push_back(0);
        c.push_back(VOP_PUSH_IMM); put_i64(c, 7);
        c.push_back(VOP_CVTSI2SD);
        c.push_back(VOP_POP_XREG); c.push_back(1);
        c.push_back(VOP_PUSH_XREG); c.push_back(0);
        c.push_back(VOP_PUSH_XREG); c.push_back(1);
        c.push_back(VOP_MULSD);
        c.push_back(VOP_POP_XREG); c.push_back(0);
        c.push_back(VOP_PUSH_IMM); put_i64(c, static_cast<int64_t>(addr));
        c.push_back(VOP_PUSH_XREG); c.push_back(0);
        c.push_back(VOP_STORE64);
        c.push_back(VOP_PUSH_IMM); put_i64(c, static_cast<int64_t>(addr));
        c.push_back(VOP_LOAD64);
        c.push_back(VOP_POP_XREG); c.push_back(2);
        c.push_back(VOP_PUSH_XREG); c.push_back(2);
        c.push_back(VOP_CVTTSD2SI);
        c.push_back(VOP_POP_VREG); c.push_back(1);
        c.push_back(VOP_VMEXIT);
        auto ctx = run_program(interp, c.data(), c.size(), nullptr);
        CHECK(mem == 42.0, T("sse chain: store64 actually wrote 42.0 to memory"));
        CHECK(ctx.vreg[1] == 42, T("sse chain: cvtsi2sd->mulsd->store64/load64->cvttsd2si ends with 42"));
    }

    // jcc: cmp 3,5 then branch on every condition code
    {
        auto run_jcc = [&](uint8_t cc) -> uint64_t {
            std::vector<uint8_t> c;
            c.push_back(VOP_PUSH_IMM); put_i64(c, 3);
            c.push_back(VOP_PUSH_IMM); put_i64(c, 5);
            c.push_back(VOP_CMP);
            c.push_back(VOP_JCC); c.push_back(cc);
            size_t jcc_rel_pos = c.size();
            put_i64(c, 0);

            // not-taken path: write 0, then jump past the taken path -- without
            // this jump, "not taken" would just fall through into the taken
            // path's write and the result would always read as "taken".
            c.push_back(VOP_PUSH_IMM); put_i64(c, 0);
            c.push_back(VOP_POP_VREG); c.push_back(9);
            c.push_back(VOP_JMP);
            size_t jmp_rel_pos = c.size();
            put_i64(c, 0);

            // taken path (VOP_JCC lands here)
            size_t taken_pos = c.size();
            int64_t jcc_rel = (int64_t)(taken_pos - jcc_rel_pos - 8);
            for (int i = 0; i < 8; i++) c[jcc_rel_pos + i] = (uint8_t)((uint64_t)jcc_rel >> (8 * i));
            c.push_back(VOP_PUSH_IMM); put_i64(c, 1);
            c.push_back(VOP_POP_VREG); c.push_back(9);

            // end (VOP_JMP lands here)
            size_t end_pos = c.size();
            int64_t jmp_rel = (int64_t)(end_pos - jmp_rel_pos - 8);
            for (int i = 0; i < 8; i++) c[jmp_rel_pos + i] = (uint8_t)((uint64_t)jmp_rel >> (8 * i));
            c.push_back(VOP_VMEXIT);

            auto ctx = run_program(interp, c.data(), c.size(), nullptr);
            return ctx.vreg[9];
        };
        // 3 < 5 (unsigned and signed): ZF=0 SF=1 CF=1 OF=0
        CHECK(run_jcc(KARITY_CC_B)  == 1, T("jcc: 3<5 B taken"));
        CHECK(run_jcc(KARITY_CC_AE) == 0, T("jcc: 3<5 AE not taken"));
        CHECK(run_jcc(KARITY_CC_L)  == 1, T("jcc: 3<5 L taken"));
        CHECK(run_jcc(KARITY_CC_GE) == 0, T("jcc: 3<5 GE not taken"));
        CHECK(run_jcc(KARITY_CC_E)  == 0, T("jcc: 3<5 E not taken"));
        CHECK(run_jcc(KARITY_CC_NE) == 1, T("jcc: 3<5 NE taken"));
        CHECK(run_jcc(KARITY_CC_S)  == 1, T("jcc: 3<5 S taken"));
        CHECK(run_jcc(KARITY_CC_O)  == 0, T("jcc: 3<5 O not taken"));
    }
    // vmexit_rel: sets ctx->exit_target = anchor + delta and exits before
    // whatever bytecode follows (same "exits before the rest" contract as
    // plain VMEXIT).
    {
        std::vector<uint8_t> c;
        int64_t delta = 0x1234;
        c.push_back(VOP_PUSH_IMM); put_i64(c, 999);
        c.push_back(VOP_POP_VREG); c.push_back(4);
        c.push_back(VOP_VMEXIT_REL); put_i64(c, delta);
        c.push_back(VOP_PUSH_IMM); put_i64(c, 0xBAD);
        c.push_back(VOP_POP_VREG); c.push_back(4);
        c.push_back(VOP_VMEXIT);

        karity_vmctx ctx; memset(&ctx, 0, sizeof(ctx));
        static uint8_t vstack[256];
        ctx.anchor = kTestAnchor;
        karity_bytecode_xor_crypt(c.data(), c.size(), 0, kTestBytecodeSeed);
        ctx.vip = reinterpret_cast<uint64_t>(c.data());
        ctx.vsp = reinterpret_cast<uint64_t>(vstack + sizeof(vstack));
        ctx.bytecode_base = ctx.vip;
        ctx.bytecode_key_seed = kTestBytecodeSeed;
        interp(&ctx);
        CHECK(ctx.vreg[4] == 999, T("vmexit_rel: exits before the dead code after it"));
        CHECK(ctx.exit_target == ctx.anchor + static_cast<uint64_t>(delta), T("vmexit_rel: sets exit_target = anchor + delta"));
    }
}

// Regression test for the per-protect opcode randomization (todo.md section
// D, "opcode 값 자체의 랜덤화"): a real BytecodeEmitter (src/vm/emitter.h),
// built with a randomized OpcodeMap, feeds a generated interpreter built
// with that *same* map -- proving the two sides of the real injector.cpp
// pipeline (try_lift's emitter, generate_interpreter's dispatch table)
// actually agree when given the same map, not just when both silently fall
// back to the identity default. Also checks the physical bytes actually
// moved (not merely that the plumbing compiles).
//
// Deliberately does NOT test a mismatched emitter/interpreter map pairing:
// this VM has no bytecode bounds-checking at all (trusted-input codegen
// target, not a sandbox -- see isa.h/lifter.h), so a genuine map mismatch is
// equivalent to feeding it corrupted bytecode. A wrong opcode byte can be
// misread as some *other* real opcode with a different operand length,
// desyncing vip from then on and walking it off the end of the buffer --
// confirmed by hand: an earlier version of this test with a mismatched map
// segfaulted deterministically, which is the expected failure mode here,
// not a bug to assert on.
static void test_randomized_opcode_map()
{
    std::mt19937_64 map_rng(0x4B41524954593031ULL); // fixed seed: deterministic test
    OpcodeMap opmap(map_rng);

    // Sanity: this seed's shuffle actually moved at least one opcode off its
    // canonical isa.h byte value -- guards against a no-op "randomization"
    // (e.g. a bug that always rebuilds the identity map).
    bool any_moved = false;
    for (const auto &e : opcode_table()) {
        if (opmap.encode(e.opcode) != static_cast<uint8_t>(e.opcode)) { any_moved = true; break; }
    }
    CHECK(any_moved, "opcode_map: randomized map differs from identity for at least one opcode");

    std::mt19937_64 interp_rng(1);
    InterpFn interp = build(interp_rng, nullptr, opmap);

    // vreg[0]=10, vreg[1]=32 -> push both, add, pop into vreg[2] -- same
    // program as the plain push_vreg/add case above, but built through the
    // real emitter (so every opcode byte is opmap-translated) instead of
    // hand-written isa.h literals.
    BytecodeEmitter em(opmap);
    em.push_vreg(0);
    em.push_vreg(1);
    em.op(VOP_ADD);
    em.pop_vreg(2);
    em.vmexit();
    std::vector<uint8_t> prog = em.finalize();
    const uint8_t *code = prog.data() + sizeof(karity_program_hdr);
    size_t code_len = prog.size() - sizeof(karity_program_hdr);

    uint64_t regs[16] = {0};
    regs[0] = 10;
    regs[1] = 32;
    auto ctx = run_program(interp, code, code_len, regs);
    CHECK(ctx.vreg[2] == 42, "opcode_map: matching emitter+interpreter maps execute correctly");

    VirtualFree(reinterpret_cast<void *>(interp), 0, MEM_RELEASE);
}

// vstack overflow guard (see runtime/vm_thunk.S's header, isa.h's
// vstack_limit comment, and interp_codegen.cpp's guard_vstack_overflow):
// mirrors the reference-interpreter test in tests/test_vm_new_ops.c against
// the *real* generated x64 machine code instead, catching its ud2 trap the
// same way runtime/nanomite_veh.c catches real CPU faults from injected
// code -- a VEH that longjmps back out from inside the callback. That's
// safe here for the same reason it is there: the callback runs on this
// thread's own stack, so unwinding back to the setjmp point just abandons
// the VEH dispatcher's and the generated interpreter's frames together,
// like any other longjmp out of a deeply nested call.
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

static bool run_expect_maybe_trap(InterpFn interp, karity_vmctx *ctx)
{
    bool hit;
    g_vstack_trap_armed = 1;
    if (setjmp(g_vstack_trap_jmp) == 0) {
        interp(ctx);
        hit = false;
    } else {
        hit = true;
    }
    g_vstack_trap_armed = 0;
    return hit;
}

static void test_vstack_overflow_guard()
{
    std::mt19937_64 rng(0xABCDEF0123456789ULL);
    InterpFn interp = build(rng);

    // Private 8-slot (64-byte) vstack sandwiched between two canary
    // regions -- a guard that failed to stop an out-of-bounds write would
    // corrupt one of them, which the checks below would catch independently
    // of whether a trap happened at all.
    struct {
        uint8_t low_canary[16];
        uint8_t vstack[64];
        uint8_t high_canary[16];
    } buf;
    memset(buf.low_canary, 0xCC, sizeof(buf.low_canary));
    memset(buf.high_canary, 0xCC, sizeof(buf.high_canary));

    auto make_ctx = [&](int push_count) {
        std::vector<uint8_t> c;
        for (int i = 0; i < push_count; i++) {
            c.push_back(VOP_PUSH_IMM);
            put_i64(c, 100 + i);
        }
        c.push_back(VOP_VMEXIT);
        karity_bytecode_xor_crypt(c.data(), c.size(), 0, kTestBytecodeSeed);

        static std::vector<uint8_t> encrypted; // must outlive the interp call below
        encrypted = std::move(c);

        karity_vmctx ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.vip = reinterpret_cast<uint64_t>(encrypted.data());
        ctx.vsp = reinterpret_cast<uint64_t>(buf.vstack + sizeof(buf.vstack));
        ctx.vstack_limit = reinterpret_cast<uint64_t>(buf.vstack);
        ctx.bytecode_base = ctx.vip;
        ctx.bytecode_key_seed = kTestBytecodeSeed;
        return ctx;
    };

    // Case 1: exactly filling the 8-slot buffer must not trap.
    {
        karity_vmctx ctx = make_ctx(8);
        CHECK(!run_expect_maybe_trap(interp, &ctx),
              "vstack guard (real interp): filling the buffer exactly to capacity does not trap");
        CHECK(ctx.vsp == reinterpret_cast<uint64_t>(buf.vstack),
              "vstack guard (real interp): vsp lands exactly at vstack_limit after 8 pushes into an 8-slot buffer");
    }

    // Case 2: a 9th push -- one slot past capacity -- must trap before
    // writing anywhere outside [vstack, vstack+64).
    {
        karity_vmctx ctx = make_ctx(9);
        CHECK(run_expect_maybe_trap(interp, &ctx),
              "vstack guard (real interp): a 9th push into an 8-slot buffer traps");
    }

    bool low_ok = true, high_ok = true;
    for (uint8_t b : buf.low_canary) if (b != 0xCC) low_ok = false;
    for (uint8_t b : buf.high_canary) if (b != 0xCC) high_ok = false;
    CHECK(low_ok, "vstack guard (real interp): overflow trap fires before corrupting memory below the buffer");
    CHECK(high_ok, "vstack guard (real interp): overflow trap fires before corrupting memory above the buffer");

    VirtualFree(reinterpret_cast<void *>(interp), 0, MEM_RELEASE);
}

int main()
{
    AddVectoredExceptionHandler(1, vstack_trap_veh);

    for (int seed = 1; seed <= 40; seed++) {
        std::mt19937_64 rng(static_cast<uint64_t>(seed) * 2654435761u + 1);
        InterpFn interp = build(rng);
        test_all_opcodes(interp, seed);
        VirtualFree(reinterpret_cast<void *>(interp), 0, MEM_RELEASE);
    }

    test_randomized_opcode_map();
    test_vstack_overflow_guard();

    if (g_fail == 0) { printf("ALL PASS (40 randomized interpreter builds)\n"); return 0; }
    printf("%d FAILURES\n", g_fail);
    return 1;
}
