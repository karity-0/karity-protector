#include <cstdio>
#include <cstring>
#include <set>
#include <vector>
#include <windows.h>
#include <Zydis/Zydis.h>
#include "x86_junk.h"

extern "C" int test_call_junk_buffer(void *buf);

static bool run_buffer(const std::vector<uint8_t> &code, const char *label)
{
    std::vector<uint8_t> full = code;
    full.push_back(0xC3); // ret

    void *mem = VirtualAlloc(nullptr, full.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(mem, full.data(), full.size());

    int rc = test_call_junk_buffer(mem);
    VirtualFree(mem, 0, MEM_RELEASE);

    if (rc == 0) {
        printf("%s: PASS (size=%zu)\n", label, full.size());
        return true;
    }
    printf("%s: FAIL rc=%d (size=%zu)\n", label, rc, full.size());
    return false;
}

// Instruction start offsets a linear-sweep disassembler would report,
// decoding straight through from `start` (the model of an analyst who
// doesn't/can't follow the overlap jump). Used to prove that the real
// post-decoy instruction boundary is NOT one the linear sweep lands on.
static std::set<size_t> linear_boundaries(const std::vector<uint8_t> &buf, size_t start)
{
    std::set<size_t> boundaries;
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    size_t off = start;
    while (off < buf.size()) {
        boundaries.insert(off);
        ZydisDecodedInstruction insn;
        ZyanStatus status =
            ZydisDecoderDecodeInstruction(&decoder, nullptr, buf.data() + off, buf.size() - off, &insn);
        if (!ZYAN_SUCCESS(status)) break; // sweep gives up (also a form of desync)
        off += insn.length;
    }
    return boundaries;
}

using namespace karity;

// emit_overlap_jump: EB <skip> <decoy...>. Real execution lands at 2+skip;
// a linear sweep must NOT have a boundary there (the decoy's long lead
// swallowed it). Append a real tail so the 5-byte decoy fully fits in-buffer.
static bool check_overlap_jump_desync(std::mt19937_64 &rng)
{
    std::vector<uint8_t> buf;
    emit_overlap_jump(buf, rng);
    if (buf.size() < 3 || buf[0] != 0xEB) { printf("overlap_jump_desync: FAIL (bad shape)\n"); return false; }
    size_t skip = buf[1];
    size_t real_target = 2 + skip;
    for (int i = 0; i < 8; i++) buf.push_back(0x90); // real tail (NOP)

    auto b = linear_boundaries(buf, 0);
    if (b.count(real_target)) {
        printf("overlap_jump_desync: FAIL (linear sweep resynced at real target %zu)\n", real_target);
        return false;
    }
    return true;
}

// emit_overlap_opaque: ... 75 <skip> <decoy...> 5x(pop) 9D(popfq). A recursive
// tool decodes the fall-through decoy region; the taken target (fall+skip)
// must NOT be a boundary of that fall-through linear decode.
static bool check_overlap_opaque_desync(std::mt19937_64 &rng)
{
    std::vector<uint8_t> buf;
    emit_overlap_opaque(buf, rng);
    for (int i = 0; i < 8; i++) buf.push_back(0x90); // real tail

    // The jnz is at a fixed offset in the opaque block: pushfq(1) + push(1) +
    // 2x arith(6) + test(2) = 16. (Scanning for 0x75 is unreliable -- a random
    // decoy filler byte can equal 0x75 too.)
    const size_t jnz = 16;
    if (buf[jnz] != 0x75) { printf("overlap_opaque_desync: FAIL (no jnz at offset 16)\n"); return false; }

    size_t fall = jnz + 2;
    size_t skip = buf[jnz + 1];
    size_t taken = fall + skip;
    auto b = linear_boundaries(buf, fall);
    if (b.count(taken)) {
        printf("overlap_opaque_desync: FAIL (fall-through sweep resynced at taken target %zu)\n", taken);
        return false;
    }
    return true;
}

// emit_overlap_midinsn: the strong form. A recursive tool decoding the decoy
// (5 bytes) off the fall-through has the real taken target (decoy+3) land
// *inside* that instruction, not on a boundary. Same fixed jnz offset 16.
static bool check_overlap_midinsn_desync(std::mt19937_64 &rng)
{
    std::vector<uint8_t> buf;
    emit_overlap_midinsn(buf, rng);

    const size_t jnz = 16;
    if (buf[jnz] != 0x75 || buf[jnz + 1] != 0x03) {
        printf("overlap_midinsn_desync: FAIL (no `jnz +3` at offset 16)\n");
        return false;
    }
    size_t decoy = jnz + 2;      // fall-through decoy start
    size_t taken = decoy + 3;    // real executed target

    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    ZydisDecodedInstruction insn;
    if (!ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(
            &decoder, nullptr, buf.data() + decoy, buf.size() - decoy, &insn))) {
        printf("overlap_midinsn_desync: FAIL (decoy did not decode)\n");
        return false;
    }
    // The taken target must sit strictly inside the decoy instruction the
    // recursive tool commits to (decoy < taken < decoy+len), i.e. mid-insn.
    if (!(insn.length > 3)) {
        printf("overlap_midinsn_desync: FAIL (decoy len %u, taken %zu not interior)\n",
               insn.length, taken);
        return false;
    }
    return true;
}

int main()
{
    std::mt19937_64 rng(12345);
    int fails = 0;

    for (int i = 0; i < 20; i++) {
        std::vector<uint8_t> code;
        emit_native_junk(code, rng);
        if (!run_buffer(code, "junk")) fails++;
    }
    for (int i = 0; i < 20; i++) {
        std::vector<uint8_t> code;
        emit_native_opaque_predicate(code, rng);
        if (!run_buffer(code, "opaque_predicate")) fails++;
    }
    for (int i = 0; i < 20; i++) {
        std::vector<uint8_t> code;
        emit_junk_call(code, rng);
        if (!run_buffer(code, "junk_call")) fails++;
    }
    for (int i = 0; i < 20; i++) {
        std::vector<uint8_t> code;
        emit_overlap_jump(code, rng);
        if (!run_buffer(code, "overlap_jump")) fails++;
    }
    for (int i = 0; i < 20; i++) {
        std::vector<uint8_t> code;
        emit_overlap_opaque(code, rng);
        if (!run_buffer(code, "overlap_opaque")) fails++;
    }
    for (int i = 0; i < 20; i++) {
        std::vector<uint8_t> code;
        emit_overlap_midinsn(code, rng);
        if (!run_buffer(code, "overlap_midinsn")) fails++;
    }
    // combined, multi-round, like the real entry stub will look
    for (int i = 0; i < 10; i++) {
        std::vector<uint8_t> code;
        emit_native_junk(code, rng);
        emit_native_opaque_predicate(code, rng);
        emit_junk_call(code, rng);
        emit_overlap_jump(code, rng);
        emit_overlap_opaque(code, rng);
        emit_overlap_midinsn(code, rng);
        emit_native_junk(code, rng);
        if (!run_buffer(code, "combined")) fails++;
    }

    // Desync verification: the overlap primitives must actually mislead a real
    // linear/recursive decode, not just be safe no-ops.
    int desync_fails = 0;
    for (int i = 0; i < 100; i++) {
        if (!check_overlap_jump_desync(rng)) desync_fails++;
        if (!check_overlap_opaque_desync(rng)) desync_fails++;
        if (!check_overlap_midinsn_desync(rng)) desync_fails++;
    }
    if (desync_fails == 0) printf("overlap_desync: PASS (300 checks)\n");
    else { printf("overlap_desync: %d FAILURES\n", desync_fails); fails += desync_fails; }

    if (fails == 0) { printf("ALL PASS\n"); return 0; }
    printf("%d FAILURES\n", fails);
    return 1;
}
