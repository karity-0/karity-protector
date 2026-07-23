#include "nanomite_encoder.h"

#include <cstring>
#include <stdexcept>

#include "nanomite_markers.h"

namespace karity {

namespace {

// Picks a marker whose length fits within `max_len` -- for very short
// blocks this excludes the 2-3 byte markers, but the pool always has at
// least the 1-byte ones (HLT/CLI/STI/IN/OUT), so any block of length >= 1
// can always be encoded.
const NanomiteMarker &pick_marker_fitting(uint32_t max_len, std::mt19937_64 &rng)
{
    std::vector<const NanomiteMarker *> candidates;
    for (size_t i = 0; i < nanomite_marker_pool_size(); i++) {
        const NanomiteMarker &m = nanomite_marker_pool(i);
        if (m.len <= max_len) candidates.push_back(&m);
    }
    std::uniform_int_distribution<size_t> dist(0, candidates.size() - 1);
    return *candidates[dist(rng)];
}

} // namespace

NanomiteEncodedBlock encode_nanomite_block(const uint8_t *plaintext, uint32_t len, std::mt19937_64 &rng)
{
    if (len < 1) {
        throw std::invalid_argument("encode_nanomite_block: block must be at least 1 byte");
    }

    const NanomiteMarker &marker = pick_marker_fitting(len, rng);

    NanomiteEncodedBlock out;
    out.patched_bytes.assign(plaintext, plaintext + len);

    std::uniform_int_distribution<uint64_t> seed_dist;
    uint64_t seed = seed_dist(rng);
    karity_nanomite_xor_crypt(out.patched_bytes.data(), len, seed);

    std::memset(&out.site, 0, sizeof(out.site));
    out.site.block_len = len;
    out.site.marker_len = marker.len;
    out.site.prng_seed = seed;
    // Save the ciphertext bytes the marker is about to clobber, then write
    // the marker over them -- see include/karity/nanomite.h for why the
    // runtime handler needs `clobbered` to reconstruct the full ciphertext.
    std::memcpy(out.site.clobbered, out.patched_bytes.data(), marker.len);
    std::memcpy(out.patched_bytes.data(), marker.bytes, marker.len);

    return out;
}

} // namespace karity
