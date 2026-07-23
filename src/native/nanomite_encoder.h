#pragma once

#include <cstdint>
#include <random>
#include <vector>

#include "karity/nanomite.h"

namespace karity {

struct NanomiteEncodedBlock {
    std::vector<uint8_t> patched_bytes; // [trap marker][ciphertext], same
                                         // length as the input plaintext --
                                         // write this back over the block's
                                         // original bytes, unchanged length
    karity_nanomite_site site;          // trap_delta/resume_delta left at 0;
                                         // caller fills those in once the
                                         // block's and resume point's VAs
                                         // relative to the site table's own
                                         // anchor are known
};

// Encrypts `plaintext` (the original bytes of one instruction run) behind a
// randomly-chosen trap marker (src/native/nanomite_markers.h) from `rng`.
// `len` must be at least the shortest marker's length (1 byte).
//
// Caller responsibility, not enforced here: `plaintext` must not contain a
// RIP-relative memory operand or a rel8/rel32 branch/call targeting outside
// the block. Those bytes get copied verbatim into a scratch buffer at a
// different address at runtime (see runtime/nanomite_veh.c) and re-executed
// as-is, so any address computed relative to the *original* location would
// silently resolve to the wrong place. Same "wrong thing is worse than not
// virtualizing" conservatism as src/vm/lifter.h -- a block-boundary scanner
// built on top of this must reject candidate runs containing such operands.
NanomiteEncodedBlock encode_nanomite_block(const uint8_t *plaintext, uint32_t len, std::mt19937_64 &rng);

} // namespace karity
