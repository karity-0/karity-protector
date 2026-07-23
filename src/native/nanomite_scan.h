#pragma once

#include <cstdint>
#include <optional>
#include <random>
#include <vector>

#include "karity/nanomite.h"

namespace karity {

struct NanomiteScanResult {
    std::vector<uint8_t> patched_bytes;      // covers [0, consumed_bytes) of the input --
                                              // write this back in place over the original
                                              // bytes at code_va. Bytes not claimed by any
                                              // accepted instruction (unreachable gaps left
                                              // behind by a rejected edge, see below) are
                                              // copied through unchanged.
    std::vector<karity_nanomite_site> sites; // trap_delta/resume_delta already filled in,
                                              // relative to `anchor_va`
    size_t consumed_bytes;
};

// Walks the position-independent CFG reachable from offset 0 of `code`
// (within `[0, max_len)`) and encodes every block it can safely reach into
// nanomite blocks (src/native/nanomite_encoder.h). This is a worklist-driven
// graph walk, not a single straight-line pass: a direct conditional branch
// (Jcc) forks the walk down both its taken and not-taken (fallthrough)
// edges, each independently either landing inside the window (recursively
// scanned, becoming its own block) or outside it (left as an absolute VA,
// exactly like a CALL/JMP target -- the bytes there are untouched original
// code, so no scanning is needed for that edge to work). Converging edges
// that land cleanly on an existing instruction boundary share a block; an
// edge landing in the *middle* of an instruction some other path already
// claimed is a genuine conflict (two decodings disagreeing about the same
// physical bytes) and is rejected rather than resolved, per the same
// "wrong thing is worse than nothing" reasoning below -- the triggering
// instruction (and everything after it on that path) is left unencoded, so
// its original bytes -- and thus its original control flow -- stay intact.
//
// A path stops -- successfully, keeping whatever was accepted so far on it
// -- at the first instruction Zydis can't decode, at RET, at an indirect or
// unresolvable CALL/JMP, at an interrupt/system instruction, at an
// unresolvable Jcc (see above), or at any instruction with a RIP-relative
// memory operand or relative immediate outside of CALL/JMP/Jcc. Those all
// break under copy-and-re-execute-elsewhere: see runtime/nanomite_veh.c's
// block execution model and src/vm/lifter.h's identical "the wrong thing is
// worse than nothing" reasoning for the VM's own conservatism.
//
// Returns nullopt only if nothing at all could be accepted (the very first
// instruction at offset 0 was already ineligible).
std::optional<NanomiteScanResult> scan_nanomite_region(const uint8_t *code, size_t max_len,
                                                         uint64_t code_va, uint64_t anchor_va,
                                                         std::mt19937_64 &rng);

} // namespace karity
