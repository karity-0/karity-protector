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

// emit_indirect_jump: push reg (1) + lea reg,[rip+disp] (7) => `jmp reg` (FF /4)
// at a fixed offset 8. It must be a *register*-indirect jump (mod=11, /4), so a
// recursive-traversal disassembler has no static target and stops following the
// flow -- unlike EB/E9 relative jumps it can resync on.
static bool check_indirect_jump(std::mt19937_64 &rng)
{
    std::vector<uint8_t> buf;
    emit_indirect_jump(buf, rng);

    const size_t jmp = 8;
    if (buf.size() < jmp + 2 || buf[jmp] != 0xFF) {
        printf("indirect_jump: FAIL (no FF opcode at offset 8)\n");
        return false;
    }
    uint8_t modrm = buf[jmp + 1];
    if ((modrm & 0xC0) != 0xC0 || ((modrm >> 3) & 7) != 4) {
        printf("indirect_jump: FAIL (modrm %02x is not `jmp reg` /4 mod=11)\n", modrm);
        return false;
    }
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    ZydisDecodedInstruction insn;
    if (!ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(
            &decoder, nullptr, buf.data() + jmp, buf.size() - jmp, &insn)) ||
        insn.mnemonic != ZYDIS_MNEMONIC_JMP || insn.length != 2) {
        printf("indirect_jump: FAIL (not decoded as a 2-byte register jmp)\n");
        return false;
    }
    return true;
}

// emit_stack_noise: pushfq(1) push(1) mov reg,rsp(3) and(4) add(4) => `sub rsp,
// reg` at a fixed offset 13. It must be a *register* (variable) rsp adjustment
// (48 29 modrm, mod=11, rm=4=rsp) -- that non-constant sub rsp is what makes
// Hex-Rays' sp-analysis fail; a constant `sub rsp, imm` would just fold.
static bool check_stack_noise(std::mt19937_64 &rng)
{
    std::vector<uint8_t> buf;
    emit_stack_noise(buf, rng);

    const size_t sub = 13;
    if (buf.size() < sub + 3 || buf[sub] != 0x48 || buf[sub + 1] != 0x29) {
        printf("stack_noise: FAIL (no `sub r/m64, r64` (48 29) at offset 13)\n");
        return false;
    }
    uint8_t modrm = buf[sub + 2];
    if ((modrm & 0xC0) != 0xC0 || (modrm & 7) != 4) { // mod=11, rm=100 (rsp)
        printf("stack_noise: FAIL (sub target is not rsp / not register form, modrm %02x)\n", modrm);
        return false;
    }
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    ZydisDecodedInstruction insn;
    if (!ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(
            &decoder, nullptr, buf.data() + sub, buf.size() - sub, &insn)) ||
        insn.mnemonic != ZYDIS_MNEMONIC_SUB || insn.length != 3) {
        printf("stack_noise: FAIL (not decoded as a 3-byte reg/reg sub)\n");
        return false;
    }
    return true;
}

// emit_antistepover_call: E8 rel32(=trap) + <trap bytes> + stub. The stub must
// rewrite the pushed return address ([rsp+8]) forward past the trap so `ret`
// lands on the blob continuation, never on the trap region. Verify the exact
// shape and that the return-address adjustment (imm8) equals trap+9 (= distance
// from the pushed return addr R to the byte just past the 9-byte stub).
static bool check_antistepover_call(std::mt19937_64 &rng)
{
    std::vector<uint8_t> buf;
    emit_antistepover_call(buf, rng);

    if (buf.empty() || buf[0] != 0xE8) {
        printf("antistepover_call: FAIL (no call opcode at offset 0)\n");
        return false;
    }
    uint32_t rel = static_cast<uint32_t>(buf[1]) | (static_cast<uint32_t>(buf[2]) << 8) |
                   (static_cast<uint32_t>(buf[3]) << 16) | (static_cast<uint32_t>(buf[4]) << 24);
    size_t trap = rel;                 // stub sits `trap` bytes past the call end
    size_t stub = 5 + trap;
    // stub prologue: pushfq + `add qword [rsp+8], imm8` (9C 48 83 44 24 08 ib).
    static const uint8_t kStub[] = {0x9C, 0x48, 0x83, 0x44, 0x24, 0x08};
    if (buf.size() != stub + 9) {
        printf("antistepover_call: FAIL (size %zu != stub_end %zu)\n", buf.size(), stub + 9);
        return false;
    }
    for (size_t i = 0; i < sizeof(kStub); i++) {
        if (buf[stub + i] != kStub[i]) {
            printf("antistepover_call: FAIL (stub prologue mismatch at +%zu)\n", i);
            return false;
        }
    }
    uint8_t imm8 = buf[stub + 6];
    if (imm8 != trap + 9) {
        printf("antistepover_call: FAIL (retaddr adjust %u != trap+9=%zu)\n", imm8, trap + 9);
        return false;
    }
    if (buf[stub + 7] != 0x9D || buf[stub + 8] != 0xC3) {
        printf("antistepover_call: FAIL (no popfq;ret epilogue)\n");
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
    for (int i = 0; i < 20; i++) {
        std::vector<uint8_t> code;
        emit_indirect_jump(code, rng);
        if (!run_buffer(code, "indirect_jump")) fails++;
    }
    for (int i = 0; i < 20; i++) {
        std::vector<uint8_t> code;
        emit_stack_noise(code, rng);
        if (!run_buffer(code, "stack_noise")) fails++;
    }
    for (int i = 0; i < 20; i++) {
        std::vector<uint8_t> code;
        emit_antistepover_call(code, rng);
        if (!run_buffer(code, "antistepover_call")) fails++;
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
        emit_indirect_jump(code, rng);
        emit_stack_noise(code, rng);
        emit_antistepover_call(code, rng);
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
        if (!check_indirect_jump(rng)) desync_fails++;
        if (!check_stack_noise(rng)) desync_fails++;
        if (!check_antistepover_call(rng)) desync_fails++;
    }
    if (desync_fails == 0) printf("anti_disasm: PASS (600 checks)\n");
    else { printf("anti_disasm: %d FAILURES\n", desync_fails); fails += desync_fails; }

    if (fails == 0) { printf("ALL PASS\n"); return 0; }
    printf("%d FAILURES\n", fails);
    return 1;
}
