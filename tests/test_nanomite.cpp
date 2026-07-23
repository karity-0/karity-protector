/* End-to-end tests of the nanomite trap/decrypt/execute/resume cycle: build
 * nanomite blocks from real machine code, write them into RWX memory,
 * install the real handler (runtime/nanomite_veh.c, hosted build), and
 * *actually call into it* -- so these exercise real CPU faults, real
 * decryption, and real resumes, not a simulation of the mechanism. */
#include <cstdio>
#include <cstring>
#include <vector>
#include <windows.h>

#include "karity/nanomite.h"
#include "nanomite_encoder.h"
#include "nanomite_scan.h"
#include "nanomite_veh.h"

static int g_failures = 0;

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__); \
            g_failures++; \
        } \
    } while (0)

// Two chained plain blocks: mov eax,10 / add eax,32 ; ret. Block B's `ret`
// hands control back to this test exactly like an ordinary function call --
// the trap/decrypt/resume machinery is fully transparent to it.
static void test_basic_chain(void)
{
    const uint8_t block_a[] = {0xB8, 0x0A, 0x00, 0x00, 0x00}; // mov eax, 10
    const uint8_t block_b[] = {0x83, 0xC0, 0x20, 0xC3};       // add eax, 32 ; ret

    void *mem = VirtualAlloc(nullptr, sizeof(block_a) + sizeof(block_b),
                              MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    CHECK(mem != nullptr, "VirtualAlloc for test_basic_chain succeeded");
    if (!mem) return;

    uint8_t *base = static_cast<uint8_t *>(mem);
    const uint64_t anchor = reinterpret_cast<uint64_t>(base);

    std::mt19937_64 rng(12345);
    karity::NanomiteEncodedBlock enc_a = karity::encode_nanomite_block(block_a, sizeof(block_a), rng);
    karity::NanomiteEncodedBlock enc_b = karity::encode_nanomite_block(block_b, sizeof(block_b), rng);

    // block A's resume point is block B's start; block B ends in `ret`, so
    // its resume point is never actually reached -- past-the-end is fine.
    enc_a.site.trap_delta = 0;
    enc_a.site.resume_delta = static_cast<int64_t>(sizeof(block_a));
    enc_b.site.trap_delta = static_cast<int64_t>(sizeof(block_a));
    enc_b.site.resume_delta = static_cast<int64_t>(sizeof(block_a) + sizeof(block_b));

    std::memcpy(base, enc_a.patched_bytes.data(), enc_a.patched_bytes.size());
    std::memcpy(base + sizeof(block_a), enc_b.patched_bytes.data(), enc_b.patched_bytes.size());

    // Sanity check: the bytes actually sitting in the buffer must NOT equal
    // the original plaintext (otherwise the "encryption" step is a no-op
    // and this test would pass for the wrong reason).
    CHECK(std::memcmp(base, block_a, sizeof(block_a)) != 0, "block A is not stored as plaintext");
    CHECK(std::memcmp(base + sizeof(block_a), block_b, sizeof(block_b)) != 0, "block B is not stored as plaintext");

    karity_nanomite_site sites[2] = {enc_a.site, enc_b.site};
    int installed = karity_nanomite_install(sites, 2, anchor);
    CHECK(installed, "karity_nanomite_install succeeded (basic_chain)");

    if (installed) {
        typedef int (*fn_t)(void);
        fn_t f = reinterpret_cast<fn_t>(mem);
        int result = f(); // two real CPU faults happen inside this call
        CHECK(result == 42, "basic_chain: decrypted-and-executed function returned the right value");
        karity_nanomite_uninstall();
    }

    VirtualFree(mem, 0, MEM_RELEASE);
}

// A block ending in a direct CALL to a plain (unprotected) helper elsewhere
// in the same buffer, then a resume that lands on a plain `ret`. Exercises
// karity_nanomite_veh's KARITY_NANOMITE_BRANCH_CALL path: the runtime must
// rewrite the (now address-wrong) E8 rel32 into an absolute indirect call
// in the scratch slot, and correctly resume where the call returns to.
//
// Buffer layout (18 bytes total):
//   [0..5)   mov eax, 10                 -- plain nanomite block
//   [5..10)  call rel32 -> [14..18)      -- CALL-terminated nanomite block
//   [10]     ret                          -- plain, native, the CALL's resume point
//   [11..14) unused padding
//   [14..18) add eax, 32 ; ret            -- plain, native helper (the call's target)
static void test_call_fixup(void)
{
    constexpr size_t kBufSize = 18;
    void *mem = VirtualAlloc(nullptr, kBufSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    CHECK(mem != nullptr, "VirtualAlloc for test_call_fixup succeeded");
    if (!mem) return;

    uint8_t *base = static_cast<uint8_t *>(mem);
    const uint64_t anchor = reinterpret_cast<uint64_t>(base);

    const uint8_t block_a[] = {0xB8, 0x0A, 0x00, 0x00, 0x00};             // mov eax, 10
    const uint8_t call_insn[] = {0xE8, 0x04, 0x00, 0x00, 0x00};           // call rel32 (+4 -> offset 14)
    const uint8_t helper[] = {0x83, 0xC0, 0x20, 0xC3};                    // add eax, 32 ; ret

    std::memset(base, 0x90, kBufSize);
    base[10] = 0xC3; // ret, plain -- the call's resume point
    std::memcpy(base + 14, helper, sizeof(helper));

    std::mt19937_64 rng(67890);
    karity::NanomiteEncodedBlock enc_a = karity::encode_nanomite_block(block_a, sizeof(block_a), rng);
    karity::NanomiteEncodedBlock enc_call = karity::encode_nanomite_block(call_insn, sizeof(call_insn), rng);

    enc_a.site.trap_delta = 0;
    enc_a.site.resume_delta = 5;

    enc_call.site.trap_delta = 5;
    enc_call.site.resume_delta = 10;                    // where the call, once it returns, continues
    enc_call.site.branch_kind = KARITY_NANOMITE_BRANCH_CALL;
    enc_call.site.branch_len = static_cast<uint8_t>(sizeof(call_insn));
    enc_call.site.branch_target_delta = 14;              // helper's offset from anchor

    std::memcpy(base, enc_a.patched_bytes.data(), enc_a.patched_bytes.size());
    std::memcpy(base + 5, enc_call.patched_bytes.data(), enc_call.patched_bytes.size());

    CHECK(std::memcmp(base + 5, call_insn, sizeof(call_insn)) != 0, "call block is not stored as plaintext");

    karity_nanomite_site sites[2] = {enc_a.site, enc_call.site};
    int installed = karity_nanomite_install(sites, 2, anchor);
    CHECK(installed, "karity_nanomite_install succeeded (call_fixup)");

    if (installed) {
        typedef int (*fn_t)(void);
        fn_t f = reinterpret_cast<fn_t>(mem);
        int result = f(); // fault -> decrypt "mov eax,10" -> fault -> decrypt+rewrite the call,
                           // call the plain helper, helper returns into the appended resume jump,
                           // which lands on the plain `ret` at offset 10
        CHECK(result == 42, "call_fixup: call-terminated block correctly called out and resumed");
        karity_nanomite_uninstall();
    }

    VirtualFree(mem, 0, MEM_RELEASE);
}

// Exercises scan_nanomite_region's bidirectional Jcc tracking end to end:
// unlike the two tests above (which hand-assemble karity_nanomite_site
// entries), this one hands the scanner real machine code containing a
// conditional branch and lets *it* discover both the taken and fallthrough
// blocks, group them, and fill in branch_cc/branch_target_delta/resume_delta
// itself. Calling the same scanned-and-encoded buffer with two different
// inputs -- one that takes the branch, one that doesn't -- proves both
// synthesized-trampoline edges (karity_nanomite_veh's BRANCH_JCC case) work
// from a single real CPU fault chain, not just one hardcoded direction.
//
// Buffer layout (16 bytes), a function taking one int argument (ECX). The
// scanner splits a plain instruction immediately followed by a branch into
// two blocks (same rule that already isolates a CALL/JMP into its own
// block -- see AcceptedInsn's comment in nanomite_scan.cpp), so this yields
// four sites, not three: [0..2) test, [2..4) the JCC block, plus the two
// targets.
//   [0..2)   test ecx, ecx              -- plain block
//   [2..4)   jz +6 -> offset 10         -- JCC-terminated block
//   [4..10)  mov eax, 111 ; ret         -- fallthrough (not-taken) block
//   [10..16) mov eax, 222 ; ret         -- taken block
static void test_jcc_bidirectional(void)
{
    constexpr size_t kBufSize = 16;
    void *mem = VirtualAlloc(nullptr, kBufSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    CHECK(mem != nullptr, "VirtualAlloc for test_jcc_bidirectional succeeded");
    if (!mem) return;

    uint8_t *base = static_cast<uint8_t *>(mem);
    const uint64_t anchor = reinterpret_cast<uint64_t>(base);

    const uint8_t source[kBufSize] = {
        0x85, 0xC9,                   // test ecx, ecx
        0x74, 0x06,                   // jz +6 -> offset 10
        0xB8, 0x6F, 0x00, 0x00, 0x00, // mov eax, 111
        0xC3,                         // ret
        0xB8, 0xDE, 0x00, 0x00, 0x00, // mov eax, 222
        0xC3,                         // ret
    };
    std::memcpy(base, source, kBufSize);

    std::mt19937_64 rng(24680);
    std::optional<karity::NanomiteScanResult> scan =
        karity::scan_nanomite_region(base, kBufSize, anchor, anchor, rng);
    CHECK(scan.has_value(), "scan_nanomite_region accepted the JCC buffer");
    if (!scan) {
        VirtualFree(mem, 0, MEM_RELEASE);
        return;
    }
    CHECK(scan->consumed_bytes == kBufSize, "scan consumed the whole buffer (both branches in-window)");
    CHECK(scan->sites.size() == 4, "scan produced four blocks: test, the JCC block, and both targets");

    bool found_jcc_site = false;
    for (const karity_nanomite_site &s : scan->sites) {
        if (s.branch_kind == KARITY_NANOMITE_BRANCH_JCC) {
            found_jcc_site = true;
            CHECK(s.branch_cc == 0x4, "branch_cc captured JZ's condition nibble (KARITY_CC_E)");
        }
    }
    CHECK(found_jcc_site, "one of the emitted sites is the JCC-terminated block");

    CHECK(std::memcmp(scan->patched_bytes.data(), source, kBufSize) != 0,
          "scanned buffer is not stored as plaintext");

    std::memcpy(base, scan->patched_bytes.data(), scan->patched_bytes.size());

    int installed = karity_nanomite_install(scan->sites.data(), static_cast<uint32_t>(scan->sites.size()), anchor);
    CHECK(installed, "karity_nanomite_install succeeded (jcc_bidirectional)");

    if (installed) {
        typedef int (*fn_t)(int);
        fn_t f = reinterpret_cast<fn_t>(mem);

        int not_taken = f(1); // ecx != 0 -> ZF=0 -> falls through to the "mov eax,111" block
        CHECK(not_taken == 111, "jcc_bidirectional: not-taken (fallthrough) edge resumed correctly");

        int taken = f(0); // ecx == 0 -> ZF=1 -> jumps to the "mov eax,222" block
        CHECK(taken == 222, "jcc_bidirectional: taken edge jumped correctly");

        karity_nanomite_uninstall();
    }

    VirtualFree(mem, 0, MEM_RELEASE);
}

int main(void)
{
    test_basic_chain();
    test_call_fixup();
    test_jcc_bidirectional();

    if (g_failures == 0) {
        printf("all nanomite tests passed\n");
        return 0;
    }
    fprintf(stderr, "%d nanomite test(s) failed\n", g_failures);
    return 1;
}
