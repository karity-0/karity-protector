#pragma once

#include <cstdint>
#include <optional>
#include <vector>

#include "karity/opcode_map.h"

namespace karity {

struct LiftResult {
    std::vector<uint8_t> bytecode; // VOP_* stream, no header (see emitter.h)
    size_t consumed_bytes;         // native bytes replaced by the call+thunk
                                    // (always exactly the mandatory straight-
                                    // line entry prefix -- see try_lift)
    size_t max_probe_offset;       // furthest offset into `code` that any
                                    // lifted block's instructions touched,
                                    // across the whole virtualized CFG (>=
                                    // consumed_bytes always, equal to it when
                                    // no branch was found beyond the prefix).
                                    // Blocks past the entry prefix are never
                                    // physically overwritten -- their
                                    // original native bytes just become
                                    // orphaned/unreachable -- so anything
                                    // that scans the tail of `code` for more
                                    // native bytes to touch (e.g. nanomite)
                                    // must not start before this offset, or
                                    // it risks re-encoding bytes a
                                    // VOP_VMEXIT_REL edge still needs intact.
};

// Lifts the instruction stream at `code` into karity bytecode: a mandatory
// straight-line entry prefix (min_bytes worth of plain, branch-free
// instructions -- see lifter.cpp for the exact recognized subset: 64-bit
// mov/add/sub/xor/and/or between registers and immediates, [base+disp32]
// and RIP-relative memory operands (8/16/32/64-bit), and CALL, direct or
// indirect), followed by a worklist-driven walk of whatever conditional/
// unconditional branches and loops it finds after that, staying within
// `max_len` bytes of `code`. Each branch edge either continues in-VM (if its
// target decodes cleanly and doesn't conflict with territory another edge
// already claimed) or leaves the VM via VOP_VMEXIT_REL, resuming native
// execution at that address exactly as today's single-exit-point case does.
//
// The prefix still stops, successfully, once at least `min_bytes` have been
// consumed AND the cut falls on an instruction boundary; it fails (returns
// nullopt) if an unrecognized or undecodable instruction is hit before that,
// or if the buffer runs out first -- unlike the rest of the CFG, the prefix
// can't gracefully fall back to "exit to native here", since its bytes are
// unconditionally overwritten by the OEP jmp.
//
// `code_va` is the absolute VA of `code[0]` in the *original* (pre-protection)
// image, and `anchor_va` is the VA that ctx->anchor will hold at runtime
// (see runtime/vm_thunk.S) -- both are needed to turn RIP-relative operands,
// CALL targets, and branch-edge exit targets into anchor-relative deltas
// that survive the image being loaded at a different base than it was
// protected at.
//
// This is deliberately conservative: virtualizing the *wrong* thing (e.g.
// a mid-instruction cut, or an instruction we don't actually model) is worse
// than not virtualizing at all.
//
// `opcode_map` translates every emitted opcode byte (default: identity, see
// opcode_map.h) -- pass the same map used to build whichever interpreter
// this bytecode will run under (src/native/interp_codegen.cpp's
// generate_interpreter takes the same parameter) so the two agree.
std::optional<LiftResult> try_lift(const uint8_t *code, size_t max_len, size_t min_bytes,
                                    uint64_t code_va, uint64_t anchor_va,
                                    const OpcodeMap &opcode_map = OpcodeMap());

} // namespace karity
