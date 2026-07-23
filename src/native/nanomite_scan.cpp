#include "nanomite_scan.h"

#include <algorithm>
#include <deque>
#include <set>

#include <Zydis/Zydis.h>

#include "nanomite_encoder.h"

namespace karity {

namespace {

// Roughly how many bytes worth of instructions to group behind one trap
// marker before starting a new block. Deliberately well under
// KARITY_NANOMITE_MAX_BLOCK, which is a hard cap the runtime's fixed-size
// scratch slots enforce -- this is just how finely the region gets diced,
// smaller blocks meaning more (cheaper, but more numerous) trap sites.
constexpr uint32_t kTargetBlockBytes = 16;

// One accepted instruction: where it ends, and (if it's a direct
// CALL/JMP/Jcc) what karity_nanomite_site::branch_kind/branch_len/
// branch_target_delta/branch_cc it needs. A CALL/JMP/Jcc is always the sole
// instruction of whatever block it ends up in -- see the grouping loop
// below -- since the runtime rewrites it into a bigger absolute-indirect
// sequence that only makes sense as a block's last word
// (include/karity/nanomite.h).
struct AcceptedInsn {
    size_t start_offset;
    size_t end_offset;
    uint8_t branch_kind = 0; // KARITY_NANOMITE_BRANCH_NONE
    uint8_t branch_len = 0;
    uint8_t branch_cc = 0;         // meaningful only for BRANCH_JCC
    int64_t branch_target_delta = 0;
    int64_t branch_alt_delta = 0;  // BRANCH_JCC only: the not-taken (fallthrough) target
};

// A maximal straight-line decode starting at `start_offset`, ending at a
// terminator (RET / JMP / Jcc / decode failure / rejected instruction) or
// at the boundary of territory some other run already claimed.
struct Run {
    size_t start_offset = 0;
    std::vector<AcceptedInsn> insns;
};

// Shared state for one call to scan_nanomite_region: which bytes are
// claimed by which run (to detect two runs disagreeing about instruction
// boundaries over the same physical bytes -- see resolve_target below), and
// the worklist of not-yet-explored Jcc edges.
struct ScanState {
    size_t max_len = 0;
    uint64_t code_va = 0;
    uint64_t anchor_va = 0;
    std::vector<int32_t> owner;         // run index owning each byte, -1 if free
    std::vector<uint8_t> insn_boundary; // true at instruction-start offsets
    std::set<size_t> forced_boundaries; // offsets that must start a new block
                                         // in Phase 2 despite not being a run's
                                         // own start_offset (a later-discovered
                                         // edge landed cleanly on them)
    std::deque<size_t> worklist;
    std::vector<Run> runs;
};

enum class TargetResolution { kOutOfWindow, kOk, kConflict };

// Tries to make `target_offset` a valid edge endpoint. Out-of-window
// targets need nothing from the scanner -- they're just an absolute VA
// elsewhere in the image, exactly like an out-of-window CALL/JMP target
// (see scan_nanomite_region's caller-side reasoning: bytes we never touch
// stay correct on their own). An in-window target that's unclaimed becomes
// a new worklist entry (its own run/block); one that already sits exactly
// on some run's instruction boundary is a clean shared merge point. Only a
// target landing in the *interior* of an instruction some other run already
// decoded is unsafe: that offset is either about to become ciphertext
// (wrong to jump into) or is genuinely ambiguous about what would execute
// there, so the caller must reject the whole edge rather than resolve it.
TargetResolution resolve_target(ScanState &st, size_t target_offset)
{
    if (target_offset >= st.max_len) return TargetResolution::kOutOfWindow;

    if (st.owner[target_offset] == -1) {
        st.worklist.push_back(target_offset);
        return TargetResolution::kOk;
    }
    if (st.insn_boundary[target_offset]) {
        st.forced_boundaries.insert(target_offset);
        return TargetResolution::kOk;
    }
    return TargetResolution::kConflict;
}

// Classifies one already-decoded instruction. Returns false if it can't be
// included at all (the run stops here, keeping whatever was accepted so
// far): an unsupported category (interrupt, system, indirect call/jmp/Jcc),
// a RIP-relative memory operand, any other relative immediate operand
// Zydis reports, or a Jcc whose taken/fallthrough edge conflicts with
// territory another run already claimed (see resolve_target). On success,
// fills `out` and `is_terminator` (true for RET, unconditional JMP, and
// Jcc -- nothing after them is reachable by straight-line fallthrough
// within *this* run, though Jcc's fallthrough may still continue as its own
// run; false for CALL and every plain instruction, where scanning
// continues in the same run).
bool classify_instruction(ScanState &st, const ZydisDecodedInstruction &insn,
                           const ZydisDecodedOperand *ops, size_t offset, AcceptedInsn &out,
                           bool &is_terminator)
{
    is_terminator = false;
    const uint64_t insn_va = st.code_va + offset;

    if (insn.meta.category == ZYDIS_CATEGORY_RET) {
        is_terminator = true;
        return true; // position-independent by construction, no fixup needed
    }
    if (insn.meta.category == ZYDIS_CATEGORY_INTERRUPT || insn.meta.category == ZYDIS_CATEGORY_SYSTEM) {
        return false;
    }

    // Only the 16 real, flags-tested Jcc encodings -- short 0x70-0x7F or
    // two-byte 0x0F 0x80-0x8F -- get the bidirectional trampoline treatment
    // below. JCXZ/LOOP/LOOPE/LOOPNE also decode under ZYDIS_CATEGORY_COND_BR
    // but test an implicit counter register (and decrement it) rather than
    // EFLAGS alone, so they don't fit the "re-test real flags with a
    // rewritten short Jcc" trick and stay unsupported, same as before.
    const bool is_real_jcc =
        insn.meta.category == ZYDIS_CATEGORY_COND_BR &&
        ((insn.opcode_map == ZYDIS_OPCODE_MAP_DEFAULT && insn.opcode >= 0x70 && insn.opcode <= 0x7F) ||
         (insn.opcode_map == ZYDIS_OPCODE_MAP_0F && insn.opcode >= 0x80 && insn.opcode <= 0x8F));
    if (insn.meta.category == ZYDIS_CATEGORY_COND_BR && !is_real_jcc) {
        return false;
    }
    if (is_real_jcc) {
        const ZydisDecodedOperand &target = ops[0];
        if (target.type != ZYDIS_OPERAND_TYPE_IMMEDIATE || !target.imm.is_relative) return false;
        ZyanU64 abs_addr = 0;
        if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&insn, &target, insn_va, &abs_addr))) return false;

        const int64_t taken_off_signed = static_cast<int64_t>(abs_addr) - static_cast<int64_t>(st.code_va);
        const bool taken_in_window = taken_off_signed >= 0 && static_cast<uint64_t>(taken_off_signed) < st.max_len;
        const size_t fallthrough_offset = offset + insn.length;
        const bool fallthrough_in_window = fallthrough_offset < st.max_len;

        const TargetResolution taken_res =
            taken_in_window ? resolve_target(st, static_cast<size_t>(taken_off_signed)) : TargetResolution::kOutOfWindow;
        const TargetResolution fall_res =
            fallthrough_in_window ? resolve_target(st, fallthrough_offset) : TargetResolution::kOutOfWindow;

        if (taken_res == TargetResolution::kConflict || fall_res == TargetResolution::kConflict) {
            return false; // can't safely land on either edge -- reject the whole instruction
        }

        out.branch_kind = KARITY_NANOMITE_BRANCH_JCC;
        out.branch_len = static_cast<uint8_t>(insn.length);
        out.branch_cc = static_cast<uint8_t>(insn.opcode & 0x0F);
        out.branch_target_delta = static_cast<int64_t>(abs_addr) - static_cast<int64_t>(st.anchor_va);
        out.branch_alt_delta =
            static_cast<int64_t>(st.code_va + fallthrough_offset) - static_cast<int64_t>(st.anchor_va);
        is_terminator = true;
        return true;
    }

    if (insn.meta.category == ZYDIS_CATEGORY_CALL || insn.meta.category == ZYDIS_CATEGORY_UNCOND_BR) {
        const ZydisDecodedOperand &target = ops[0];
        if (target.type != ZYDIS_OPERAND_TYPE_IMMEDIATE || !target.imm.is_relative) {
            return false; // indirect call/jmp (register or [mem] target) -- out of scope
        }
        ZyanU64 abs_addr = 0;
        if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&insn, &target, insn_va, &abs_addr))) return false;

        out.branch_kind = insn.meta.category == ZYDIS_CATEGORY_CALL ? KARITY_NANOMITE_BRANCH_CALL
                                                                      : KARITY_NANOMITE_BRANCH_JMP;
        out.branch_len = static_cast<uint8_t>(insn.length);
        out.branch_target_delta = static_cast<int64_t>(abs_addr - st.anchor_va);
        is_terminator = (out.branch_kind == KARITY_NANOMITE_BRANCH_JMP); // CALL falls through, JMP doesn't
        return true;
    }

    // Plain instruction: still must not touch RIP (its effective address
    // would be wrong once re-executed from the scratch slot) or carry a
    // relative operand (shouldn't happen outside CALL/UNCOND_BR/Jcc, but
    // this is the same "wrong thing is worse than nothing" conservatism as
    // src/vm/lifter.h).
    for (uint8_t i = 0; i < insn.operand_count; i++) {
        const ZydisDecodedOperand &op = ops[i];
        if (op.type == ZYDIS_OPERAND_TYPE_MEMORY && op.mem.base == ZYDIS_REGISTER_RIP) return false;
        if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && op.imm.is_relative) return false;
    }
    return true;
}

void emit_block(NanomiteScanResult &result, const uint8_t *code, size_t block_start, size_t block_end,
                 uint64_t code_va, uint64_t anchor_va, const AcceptedInsn *branch, std::mt19937_64 &rng)
{
    auto block_len = static_cast<uint32_t>(block_end - block_start);
    NanomiteEncodedBlock enc = encode_nanomite_block(code + block_start, block_len, rng);
    enc.site.trap_delta = static_cast<int64_t>((code_va + block_start) - anchor_va);

    if (branch && branch->branch_kind == KARITY_NANOMITE_BRANCH_JCC) {
        enc.site.resume_delta = branch->branch_alt_delta; // not-taken (fallthrough) target
        enc.site.branch_target_delta = branch->branch_target_delta; // taken target
        enc.site.branch_kind = branch->branch_kind;
        enc.site.branch_len = branch->branch_len;
        enc.site.branch_cc = branch->branch_cc;
    } else {
        enc.site.resume_delta = static_cast<int64_t>((code_va + block_end) - anchor_va);
        if (branch) {
            enc.site.branch_kind = branch->branch_kind;
            enc.site.branch_len = branch->branch_len;
            enc.site.branch_target_delta = branch->branch_target_delta;
        }
    }

    std::copy(enc.patched_bytes.begin(), enc.patched_bytes.end(),
              result.patched_bytes.begin() + static_cast<std::ptrdiff_t>(block_start));
    result.sites.push_back(enc.site);
}

// Groups one run's accepted instructions into blocks of roughly
// kTargetBlockBytes (never exceeding KARITY_NANOMITE_MAX_BLOCK), except
// that a CALL/JMP/Jcc is always alone in its own block (see AcceptedInsn's
// comment), and a `forced_boundaries` offset always starts a fresh block
// even mid-run (a later-discovered edge from elsewhere lands exactly here).
void group_and_emit(NanomiteScanResult &result, const uint8_t *code, const Run &run, const ScanState &st,
                     std::mt19937_64 &rng)
{
    const std::vector<AcceptedInsn> &accepted = run.insns;
    if (accepted.empty()) return;

    size_t block_start = run.start_offset;
    size_t i = 0;
    while (i < accepted.size()) {
        const AcceptedInsn &first = accepted[i];

        if (first.branch_kind != KARITY_NANOMITE_BRANCH_NONE) {
            emit_block(result, code, block_start, first.end_offset, st.code_va, st.anchor_va, &first, rng);
            block_start = first.end_offset;
            i++;
            continue;
        }

        size_t block_end = first.end_offset;
        i++;
        while (i < accepted.size() && accepted[i].branch_kind == KARITY_NANOMITE_BRANCH_NONE &&
               accepted[i].end_offset - block_start <= kTargetBlockBytes &&
               st.forced_boundaries.find(accepted[i].start_offset) == st.forced_boundaries.end()) {
            block_end = accepted[i].end_offset;
            i++;
        }

        emit_block(result, code, block_start, block_end, st.code_va, st.anchor_va, nullptr, rng);
        block_start = block_end;
    }
}

} // namespace

std::optional<NanomiteScanResult> scan_nanomite_region(const uint8_t *code, size_t max_len,
                                                         uint64_t code_va, uint64_t anchor_va,
                                                         std::mt19937_64 &rng)
{
    ZydisDecoder decoder;
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64))) {
        return std::nullopt;
    }

    ScanState st;
    st.max_len = max_len;
    st.code_va = code_va;
    st.anchor_va = anchor_va;
    st.owner.assign(max_len, -1);
    st.insn_boundary.assign(max_len, 0);
    st.worklist.push_back(0);

    // Phase 1: worklist-driven walk of the region's CFG. offset 0 is always
    // tried first; a Jcc's taken/fallthrough edges push more offsets onto
    // the worklist as they're discovered. Every run's bytes get claimed in
    // `owner` as they're decoded, which is what lets resolve_target above
    // detect two runs (including a run looping back into its own earlier
    // bytes) disagreeing over the same physical bytes.
    while (!st.worklist.empty()) {
        const size_t start = st.worklist.front();
        st.worklist.pop_front();
        if (start >= max_len || st.owner[start] != -1) continue; // already covered

        const auto run_id = static_cast<int32_t>(st.runs.size());
        Run run;
        run.start_offset = start;

        size_t offset = start;
        while (offset < max_len) {
            if (st.owner[offset] != -1) {
                if (st.insn_boundary[offset]) st.forced_boundaries.insert(offset);
                break; // ran into territory another run (or this one, looping back) already owns
            }

            ZydisDecodedInstruction insn;
            ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
            ZyanStatus status = ZydisDecoderDecodeFull(&decoder, code + offset, max_len - offset, &insn, ops);
            if (!ZYAN_SUCCESS(status)) break;

            AcceptedInsn ai;
            ai.start_offset = offset;
            bool is_terminator = false;
            if (!classify_instruction(st, insn, ops, offset, ai, is_terminator)) break;

            ai.end_offset = offset + insn.length;
            for (size_t b = offset; b < ai.end_offset; b++) st.owner[b] = run_id;
            st.insn_boundary[offset] = 1;
            run.insns.push_back(ai);
            offset = ai.end_offset;

            if (is_terminator) break;
        }

        st.runs.push_back(std::move(run));
    }

    size_t max_end = 0;
    bool any_accepted = false;
    for (const Run &run : st.runs) {
        if (!run.insns.empty()) {
            any_accepted = true;
            max_end = std::max(max_end, run.insns.back().end_offset);
        }
    }
    if (!any_accepted) return std::nullopt;

    NanomiteScanResult result;
    result.consumed_bytes = max_end;
    result.patched_bytes.assign(code, code + max_end);

    // Phase 2: now that every edge (including ones discovered by runs
    // processed later than the run they point back into) is known, group
    // each run into blocks and encode them.
    for (const Run &run : st.runs) {
        group_and_emit(result, code, run, st, rng);
    }

    return result;
}

} // namespace karity
