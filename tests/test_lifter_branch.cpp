// Exercises src/vm/lifter.cpp's CFG walker directly (no PE injection
// involved): hand-assembled machine code containing a real backward Jcc
// loop, fed through try_lift(), then the resulting bytecode is actually run
// through the reference interpreter (runtime/vm_interp.c) and checked
// against the loop's real arithmetic result -- catches bugs in edge
// resolution / block splitting / patch-position bookkeeping that a purely
// opcode-level test (test_vm_branch.c) can't reach, since those only ever
// hand-write already-correct bytecode.
#include <cstdio>
#include <cstring>
#include <vector>

#include "karity/bytecode_crypt.h"
#include "vm/lifter.h"
#include "vm_interp.h"

using namespace karity;

static int g_fail = 0;
#define CHECK(cond, msg) do { if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fail++; } } while (0)

// mov rax,0 / mov rcx,6 / loop_start: add rax,7 / sub rcx,1 / cmp rcx,0 /
// jne loop_start / mov rcx,rax
//
// A backward-looping countdown: accumulates 7 into rax six times (42), then
// falls through into `mov rcx,rax` once the counter hits zero. Verifies the
// loop actually re-enters itself via VOP_JCC (not an infinite loop, not a
// premature exit) and that the fallthrough edge out of the loop is wired to
// the right block.
static const uint8_t kLoopCode[] = {
    0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00, // mov rax, 0
    0x48, 0xC7, 0xC1, 0x06, 0x00, 0x00, 0x00, // mov rcx, 6
    0x48, 0x83, 0xC0, 0x07,                   // loop_start: add rax, 7
    0x48, 0x83, 0xE9, 0x01,                   // sub rcx, 1
    0x48, 0x83, 0xF9, 0x00,                   // cmp rcx, 0
    0x75, 0xF2,                               // jne loop_start (rel8 = -14)
    0x48, 0x89, 0xC1,                         // mov rcx, rax
};

// Fixed test seed for encrypting try_lift()'s plaintext bytecode output
// before running it -- try_lift/BytecodeEmitter never encrypt anything
// themselves (that's a pure post-process in src/inject/injector.cpp), so
// this mirrors that step by hand; both interpreters now unconditionally
// decrypt every fetch (see include/karity/bytecode_crypt.h and
// look/todo.md section C).
static constexpr uint64_t kTestSeed = 0x9F00D5EEDBADC0DEULL;

static void run_bytecode(const std::vector<uint8_t> &bytecode, uint64_t anchor, karity_vmctx &ctx)
{
    static uint8_t vstack[4096];
    std::vector<uint8_t> encrypted = bytecode;
    karity_bytecode_xor_crypt(encrypted.data() + sizeof(karity_program_hdr),
                               encrypted.size() - sizeof(karity_program_hdr), 0, kTestSeed);
    memset(&ctx, 0, sizeof(ctx));
    ctx.anchor = anchor;
    // encrypted.data() already points past karity_program_hdr's fixed fields
    // at whatever entry_off finalize() used (0, since try_lift never sets
    // one) -- vip must start at the first opcode, i.e. right after the header.
    ctx.vip = reinterpret_cast<uint64_t>(encrypted.data() + sizeof(karity_program_hdr));
    ctx.vsp = reinterpret_cast<uint64_t>(vstack + sizeof(vstack));
    ctx.bytecode_base = ctx.vip;
    ctx.bytecode_key_seed = kTestSeed;
    karity_vm_run(&ctx);
}

static void test_backward_loop(void)
{
    constexpr uint64_t kCodeVa = 0x140001000ULL;
    constexpr uint64_t kAnchorVa = 0x140002000ULL; // deliberately different from code_va
    constexpr size_t kMinBytes = 5;

    auto lifted = try_lift(kLoopCode, sizeof(kLoopCode), kMinBytes, kCodeVa, kAnchorVa);
    CHECK(lifted.has_value(), "try_lift accepts the loop");
    if (!lifted) return;

    CHECK(lifted->consumed_bytes == 7, "mandatory prefix is exactly the first mov (7 bytes)");
    CHECK(lifted->max_probe_offset == sizeof(kLoopCode),
          "max_probe_offset reaches the end of the buffer (whole loop + tail lifted)");

    karity_vmctx ctx;
    run_bytecode(lifted->bytecode, kAnchorVa, ctx);

    CHECK(ctx.vreg[0] == 42, "loop accumulates 6*7=42 into rax"); // RAX is vreg[0]
    CHECK(ctx.vreg[1] == 42, "mov rcx,rax after the loop copies the result"); // RCX is vreg[1]

    // The block after the loop ends the buffer (no more bytes to lift), so
    // it must resolve to a VOP_VMEXIT_REL whose target is exactly
    // code_va + sizeof(kLoopCode) -- i.e. anchor + (exit_target - anchor).
    uint64_t expected_exit = kCodeVa + sizeof(kLoopCode);
    CHECK(ctx.exit_target == expected_exit, "natural end-of-buffer exit targets the right native address");
}

// Same loop, but with min_bytes pushed past the first two movs so the
// mandatory prefix itself ends mid-way through what would otherwise be
// explored territory -- makes sure discovery correctly starts exactly where
// the prefix stopped, not at offset 0.
static void test_backward_loop_longer_prefix(void)
{
    constexpr uint64_t kCodeVa = 0x140001000ULL;
    constexpr uint64_t kAnchorVa = 0x140001000ULL;
    constexpr size_t kMinBytes = 10; // forces prefix to also consume "mov rcx,6"

    auto lifted = try_lift(kLoopCode, sizeof(kLoopCode), kMinBytes, kCodeVa, kAnchorVa);
    CHECK(lifted.has_value(), "try_lift accepts the loop with a longer mandatory prefix");
    if (!lifted) return;

    CHECK(lifted->consumed_bytes == 14, "prefix now covers both movs (14 bytes)");

    karity_vmctx ctx;
    run_bytecode(lifted->bytecode, kAnchorVa, ctx);

    CHECK(ctx.vreg[0] == 42, "loop still accumulates 42 into rax with a longer prefix");
    CHECK(ctx.vreg[1] == 42, "mov rcx,rax still runs after the loop");
}

// mov rax,0 / mov rcx,1 / cmp rcx,0 / je else_branch / mov rax,100 / jmp end
// / else_branch: mov rax,200 / end: mov rcx,rax
//
// A forward if/else: je's taken edge and the fallthrough path's own jmp
// converge on the same shared block ("end"), discovered from two different
// directions (a forced-boundary merge, not a loop-back). rcx=1 so the
// branch is NOT taken, meaning rax should end up 100 (not 200) and the
// jmp must correctly skip the else_branch block.
static const uint8_t kIfElseCode[] = {
    0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00,       // mov rax, 0
    0x48, 0xC7, 0xC1, 0x01, 0x00, 0x00, 0x00,       // mov rcx, 1
    0x48, 0x83, 0xF9, 0x00,                         // cmp rcx, 0
    0x74, 0x09,                                     // je else_branch (rel8=+9)
    0x48, 0xC7, 0xC0, 0x64, 0x00, 0x00, 0x00,       // mov rax, 100
    0xEB, 0x07,                                     // jmp end (rel8=+7)
    0x48, 0xC7, 0xC0, 0xC8, 0x00, 0x00, 0x00,       // else_branch: mov rax, 200
    0x48, 0x89, 0xC1,                               // end: mov rcx, rax
};

static void test_forward_if_else(void)
{
    constexpr uint64_t kCodeVa = 0x140001000ULL;
    constexpr uint64_t kAnchorVa = 0x140001000ULL;
    constexpr size_t kMinBytes = 5;

    auto lifted = try_lift(kIfElseCode, sizeof(kIfElseCode), kMinBytes, kCodeVa, kAnchorVa);
    CHECK(lifted.has_value(), "try_lift accepts the if/else");
    if (!lifted) return;

    karity_vmctx ctx;
    run_bytecode(lifted->bytecode, kAnchorVa, ctx);

    CHECK(ctx.vreg[0] == 100, "not-taken path: rax=100, else_branch's rax=200 correctly skipped");
    CHECK(ctx.vreg[1] == 100, "both the fallthrough's jmp and je's taken edge converge on the same shared block");
}

// mov rax,0 / push 0x12345678 / pop rcx / inc rcx / push qword ptr [rbx] /
// pop qword ptr [rbx+8]
//
// Exercises the lifter's newer PUSH-imm32, PUSH/POP-[mem], and INC
// mnemonic support all in one straight-line (branch-free) sequence, still
// routed through the same CFG machinery as everything else (no branches
// found -> one block, natural end-of-buffer exit) rather than a dedicated
// no-branch code path.
static const uint8_t kPushPopIncCode[] = {
    0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00, // mov rax, 0
    0x68, 0x78, 0x56, 0x34, 0x12,             // push 0x12345678
    0x59,                                     // pop rcx
    0x48, 0xFF, 0xC1,                         // inc rcx
    0xFF, 0x33,                               // push qword ptr [rbx]
    0x8F, 0x43, 0x08,                         // pop qword ptr [rbx+8]
};

static void test_push_pop_imm_mem_and_inc(void)
{
    constexpr uint64_t kCodeVa = 0x140001000ULL;
    constexpr uint64_t kAnchorVa = 0x140001000ULL;
    constexpr size_t kMinBytes = 5;

    auto lifted = try_lift(kPushPopIncCode, sizeof(kPushPopIncCode), kMinBytes, kCodeVa, kAnchorVa);
    CHECK(lifted.has_value(), "try_lift accepts push imm32 / push,pop [mem] / inc");
    if (!lifted) return;

    static uint64_t buf[2] = {0xDEADBEEFCAFEBABEULL, 0};
    static uint8_t vstack[4096];
    // PUSH/POP go through vreg[RSP] as a stand-in for the real native stack
    // (see lift_one's PUSH/POP cases) -- in the real protector this is
    // seeded from the actual RSP by runtime/vm_thunk.S at VM entry; here,
    // bypassing that thunk entirely, it has to be pointed at valid,
    // writable memory by hand or PUSH's own store faults.
    static uint8_t native_stack[4096];
    std::vector<uint8_t> encrypted = lifted->bytecode;
    karity_bytecode_xor_crypt(encrypted.data() + sizeof(karity_program_hdr),
                               encrypted.size() - sizeof(karity_program_hdr), 0, kTestSeed);
    karity_vmctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.anchor = kAnchorVa;
    ctx.vreg[3] = reinterpret_cast<uint64_t>(buf);                             // vreg[3] == RBX
    ctx.vreg[4] = reinterpret_cast<uint64_t>(native_stack + sizeof(native_stack)); // vreg[4] == RSP
    ctx.vip = reinterpret_cast<uint64_t>(encrypted.data() + sizeof(karity_program_hdr));
    ctx.vsp = reinterpret_cast<uint64_t>(vstack + sizeof(vstack));
    ctx.bytecode_base = ctx.vip;
    ctx.bytecode_key_seed = kTestSeed;
    karity_vm_run(&ctx);

    CHECK(ctx.vreg[1] == 0x12345679ULL, "push imm32 + pop rcx + inc rcx == 0x12345678 + 1"); // RCX is vreg[1]
    CHECK(buf[1] == 0xDEADBEEFCAFEBABEULL, "push [rbx] then pop [rbx+8] round-trips through the native stack");
}

// mov rax,6 / mov rcx,7 / imul rax,rcx / mov rcx,5 / mov rdx,0 / div rcx /
// mov rbx,6 / mul rbx / mov rcx,rax / imul rcx / mov rcx,24 / idiv rcx /
// mov rbx,rax
//
// Chains all five new MUL/IMUL/DIV/IDIV opcodes (look/todo.md A-4) through
// try_lift() end to end, each result feeding the next: two-operand IMUL2
// (6*7=42), one-operand DIV (42/5 -> quotient 8), one-operand MUL
// (8*6=48), one-operand IMUL1 (48*48=2304), one-operand IDIV (2304/24=96).
// Straight-line (no branches), same as kPushPopIncCode above -- still
// routed through the CFG machinery (no branch found -> one block, natural
// end-of-buffer exit) rather than a dedicated no-branch path.
static const uint8_t kMulDivCode[] = {
    0x48, 0xC7, 0xC0, 0x06, 0x00, 0x00, 0x00, // mov rax, 6
    0x48, 0xC7, 0xC1, 0x07, 0x00, 0x00, 0x00, // mov rcx, 7
    0x48, 0x0F, 0xAF, 0xC1,                   // imul rax, rcx      (rax=42)
    0x48, 0xC7, 0xC1, 0x05, 0x00, 0x00, 0x00, // mov rcx, 5
    0x48, 0xC7, 0xC2, 0x00, 0x00, 0x00, 0x00, // mov rdx, 0
    0x48, 0xF7, 0xF1,                         // div rcx            (rax=8, rdx=2)
    0x48, 0xC7, 0xC3, 0x06, 0x00, 0x00, 0x00, // mov rbx, 6
    0x48, 0xF7, 0xE3,                         // mul rbx            (rax=48, rdx=0)
    0x48, 0x89, 0xC1,                         // mov rcx, rax       (rcx=48)
    0x48, 0xF7, 0xE9,                         // imul rcx           (rax=2304, rdx=0)
    0x48, 0xC7, 0xC1, 0x18, 0x00, 0x00, 0x00, // mov rcx, 24
    0x48, 0xF7, 0xF9,                         // idiv rcx           (rax=96, rdx=0)
    0x48, 0x89, 0xC3,                         // mov rbx, rax       (rbx=96)
};

static void test_mul_imul_div(void)
{
    constexpr uint64_t kCodeVa = 0x140001000ULL;
    constexpr uint64_t kAnchorVa = 0x140001000ULL;
    constexpr size_t kMinBytes = 5;

    auto lifted = try_lift(kMulDivCode, sizeof(kMulDivCode), kMinBytes, kCodeVa, kAnchorVa);
    CHECK(lifted.has_value(), "try_lift accepts imul/mul/div/idiv");
    if (!lifted) return;

    karity_vmctx ctx;
    run_bytecode(lifted->bytecode, kAnchorVa, ctx);

    CHECK(ctx.vreg[0] == 96, "imul2->div->mul->imul1->idiv chain ends with rax=96");
    CHECK(ctx.vreg[2] == 0, "final idiv's remainder (rdx) is 0 (2304 divides evenly by 24)");
    CHECK(ctx.vreg[3] == 96, "mov rbx,rax captures the final idiv quotient");
}

// mov rax,10 / movzx rbx,al / mov rax,-20 / movsx rcx,al / neg rcx /
// add rbx,rcx / mov rax,-1 / movsxd rcx,eax / neg rcx / add rbx,rcx /
// mov rax,11 / movsx ecx,al / add rbx,rcx / mov rcx,rbx
//
// Chains all three new MOVZX/MOVSX/MOVSXD opcode shapes (look/todo.md A-4)
// through try_lift() end to end: VOP_MOVZX (src=1 byte), VOP_MOVSX with a
// 64-bit destination (src=1 byte), VOP_MOVSX via the MOVSXD encoding
// (src=4 bytes), and VOP_MOVSX with a 32-bit destination (src=1 byte) --
// the one whose dst_size operand actually changes the result (see isa.h).
// 10 + 20 + 1 + 11 = 42, same running-total convention as
// test_mul_imul_div above. Bytes captured verbatim from
// examples/movzx_movsx_demo.S via objdump, same as that file documents.
static const uint8_t kMovzxMovsxCode[] = {
    0x48, 0xC7, 0xC0, 0x0A, 0x00, 0x00, 0x00, // mov rax, 10
    0x48, 0x0F, 0xB6, 0xD8,                   // movzx rbx, al   (rbx=10)
    0x48, 0xC7, 0xC0, 0xEC, 0xFF, 0xFF, 0xFF, // mov rax, -20
    0x48, 0x0F, 0xBE, 0xC8,                   // movsx rcx, al   (rcx=-20)
    0x48, 0xF7, 0xD9,                         // neg rcx         (rcx=20)
    0x48, 0x01, 0xCB,                         // add rbx, rcx    (rbx=30)
    0x48, 0xC7, 0xC0, 0xFF, 0xFF, 0xFF, 0xFF, // mov rax, -1
    0x48, 0x63, 0xC8,                         // movsxd rcx, eax (rcx=-1)
    0x48, 0xF7, 0xD9,                         // neg rcx         (rcx=1)
    0x48, 0x01, 0xCB,                         // add rbx, rcx    (rbx=31)
    0x48, 0xC7, 0xC0, 0x0B, 0x00, 0x00, 0x00, // mov rax, 11
    0x0F, 0xBE, 0xC8,                         // movsx ecx, al   (rcx=11)
    0x48, 0x01, 0xCB,                         // add rbx, rcx    (rbx=42)
    0x48, 0x89, 0xD9,                         // mov rcx, rbx
};

static void test_movzx_movsx(void)
{
    constexpr uint64_t kCodeVa = 0x140001000ULL;
    constexpr uint64_t kAnchorVa = 0x140001000ULL;
    constexpr size_t kMinBytes = 5;

    auto lifted = try_lift(kMovzxMovsxCode, sizeof(kMovzxMovsxCode), kMinBytes, kCodeVa, kAnchorVa);
    CHECK(lifted.has_value(), "try_lift accepts movzx/movsx/movsxd");
    if (!lifted) return;

    karity_vmctx ctx;
    run_bytecode(lifted->bytecode, kAnchorVa, ctx);

    CHECK(ctx.vreg[3] == 42, "movzx+movsx(64)+movsxd+movsx(32) chain ends with rbx=42"); // RBX is vreg[3]
    CHECK(ctx.vreg[1] == 42, "mov rcx,rbx captures the final total"); // RCX is vreg[1]
}

// mov rax,6 / cvtsi2sd xmm0,rax / mov rax,7 / cvtsi2sd xmm1,rax /
// mulsd xmm0,xmm1 / cvttsd2si rax,xmm0 / mov rcx,rax
//
// Chains VOP_CVTSI2SD, VOP_MULSD (register-register, via VOP_PUSH_XREG/
// VOP_POP_XREG for both operands), and VOP_CVTTSD2SI through try_lift() end
// to end: 6.0*7.0=42.0, truncated back to the integer 42, same running-total
// convention as test_mul_imul_div/test_movzx_movsx above. No branch anywhere
// in this buffer, so (like kMulDivCode) it's routed through the CFG
// machinery as a single block with a natural end-of-buffer exit.
static const uint8_t kSseCode[] = {
    0x48, 0xC7, 0xC0, 0x06, 0x00, 0x00, 0x00, // mov rax, 6
    0xF2, 0x48, 0x0F, 0x2A, 0xC0,             // cvtsi2sd xmm0, rax   (xmm0=6.0)
    0x48, 0xC7, 0xC0, 0x07, 0x00, 0x00, 0x00, // mov rax, 7
    0xF2, 0x48, 0x0F, 0x2A, 0xC8,             // cvtsi2sd xmm1, rax   (xmm1=7.0)
    0xF2, 0x0F, 0x59, 0xC1,                   // mulsd xmm0, xmm1     (xmm0=42.0)
    0xF2, 0x48, 0x0F, 0x2C, 0xC0,             // cvttsd2si rax, xmm0  (rax=42)
    0x48, 0x89, 0xC1,                         // mov rcx, rax
};

static void test_sse(void)
{
    constexpr uint64_t kCodeVa = 0x140001000ULL;
    constexpr uint64_t kAnchorVa = 0x140001000ULL;
    constexpr size_t kMinBytes = 5;

    auto lifted = try_lift(kSseCode, sizeof(kSseCode), kMinBytes, kCodeVa, kAnchorVa);
    CHECK(lifted.has_value(), "try_lift accepts cvtsi2sd/mulsd/cvttsd2si");
    if (!lifted) return;

    karity_vmctx ctx;
    run_bytecode(lifted->bytecode, kAnchorVa, ctx);

    CHECK(ctx.vreg[0] == 42, "cvttsd2si leaves the truncated result in rax"); // RAX is vreg[0]
    CHECK(ctx.vreg[1] == 42, "cvtsi2sd->mulsd->cvttsd2si chain ends with rcx=42"); // RCX is vreg[1]
}

// Same chain as test_sse above, but round-tripping the 42.0 through a real
// [rbx] memory operand (MOVSD store then load) instead of staying in
// registers/xreg the whole time -- isolates the MOVSD-with-memory-operand
// lift/codegen path (untested by test_sse, which only exercises the
// register-register CVTSI2SD/MULSD/CVTTSD2SI forms).
static const uint8_t kSseMemCode[] = {
    0x48, 0xC7, 0xC0, 0x06, 0x00, 0x00, 0x00, // mov rax, 6
    0xF2, 0x48, 0x0F, 0x2A, 0xC0,             // cvtsi2sd xmm0, rax   (xmm0=6.0)
    0x48, 0xC7, 0xC0, 0x07, 0x00, 0x00, 0x00, // mov rax, 7
    0xF2, 0x48, 0x0F, 0x2A, 0xC8,             // cvtsi2sd xmm1, rax   (xmm1=7.0)
    0xF2, 0x0F, 0x59, 0xC1,                   // mulsd xmm0, xmm1     (xmm0=42.0)
    0xF2, 0x0F, 0x11, 0x03,                   // movsd qword ptr [rbx], xmm0 (store)
    0xF2, 0x0F, 0x10, 0x13,                   // movsd xmm2, qword ptr [rbx] (load)
    0xF2, 0x48, 0x0F, 0x2C, 0xC2,             // cvttsd2si rax, xmm2  (rax=42)
    0x48, 0x89, 0xC1,                         // mov rcx, rax
};

static void test_sse_mem(void)
{
    constexpr uint64_t kCodeVa = 0x140001000ULL;
    constexpr uint64_t kAnchorVa = 0x140001000ULL;
    constexpr size_t kMinBytes = 5;

    auto lifted = try_lift(kSseMemCode, sizeof(kSseMemCode), kMinBytes, kCodeVa, kAnchorVa);
    CHECK(lifted.has_value(), "try_lift accepts movsd [mem] store/load");
    if (!lifted) return;

    static double buf = 0.0;
    static uint8_t vstack[4096];
    std::vector<uint8_t> encrypted = lifted->bytecode;
    karity_bytecode_xor_crypt(encrypted.data() + sizeof(karity_program_hdr),
                               encrypted.size() - sizeof(karity_program_hdr), 0, kTestSeed);
    karity_vmctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.anchor = kAnchorVa;
    ctx.vreg[3] = reinterpret_cast<uint64_t>(&buf); // vreg[3] == RBX
    ctx.vip = reinterpret_cast<uint64_t>(encrypted.data() + sizeof(karity_program_hdr));
    ctx.vsp = reinterpret_cast<uint64_t>(vstack + sizeof(vstack));
    ctx.bytecode_base = ctx.vip;
    ctx.bytecode_key_seed = kTestSeed;
    karity_vm_run(&ctx);

    CHECK(buf == 42.0, "movsd store actually wrote 42.0 to [rbx]");
    CHECK(ctx.vreg[0] == 42, "cvttsd2si after the movsd round trip leaves rax=42");
    CHECK(ctx.vreg[1] == 42, "mov rcx,rax after the movsd round trip ends with rcx=42");
}

int main(void)
{
    test_backward_loop();
    test_backward_loop_longer_prefix();
    test_forward_if_else();
    test_push_pop_imm_mem_and_inc();
    test_mul_imul_div();
    test_movzx_movsx();
    test_sse();
    test_sse_mem();
    if (g_fail == 0) { printf("all lifter branch/loop tests passed\n"); return 0; }
    fprintf(stderr, "%d failure(s)\n", g_fail);
    return 1;
}
