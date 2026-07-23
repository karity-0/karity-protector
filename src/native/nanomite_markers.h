#pragma once

#include <cstdint>
#include <random>

namespace karity {

// A trap marker is a short instruction encoding guaranteed to fault in
// usermode (Ring 3) on every x86-64 CPU -- no memory operand, no dependency
// on CR4/MSR configuration, so the fault is deterministic regardless of the
// host machine. Deliberately a mix of #UD (UD2) and #GP (privileged
// instructions) rather than one repeated byte: a run of identical marker
// bytes scattered through code is exactly the kind of pattern static
// anti-tamper scanners (and human analysts skimming a hex view) key on --
// see look/roadmap.txt's nanomites discussion. The runtime handler
// (runtime/nanomite_veh.c) never inspects which marker was used, only its
// length, so this pool is a host-only concept.
//
// All entries verified to need neither a ModRM memory operand nor any
// privilege-independent behavior (e.g. RDTSC is deliberately excluded --
// it's *not* privileged unless CR4.TSD is set, so it wouldn't reliably
// fault).
struct NanomiteMarker {
    uint8_t bytes[3];
    uint8_t len;
    // Exception this raises in usermode, for documentation only:
    //   #UD  -> STATUS_ILLEGAL_INSTRUCTION
    //   #GP  -> STATUS_PRIVILEGED_INSTRUCTION
};

inline const NanomiteMarker &nanomite_marker_pool(size_t i)
{
    static const NanomiteMarker kPool[] = {
        {{0x0F, 0x0B, 0x00}, 2}, // UD2                    -> #UD
        {{0xF4, 0x00, 0x00}, 1}, // HLT                     -> #GP
        {{0xFA, 0x00, 0x00}, 1}, // CLI                     -> #GP
        {{0xFB, 0x00, 0x00}, 1}, // STI                     -> #GP
        {{0xEC, 0x00, 0x00}, 1}, // IN AL, DX               -> #GP
        {{0xEE, 0x00, 0x00}, 1}, // OUT DX, AL              -> #GP
        {{0x0F, 0x30, 0x00}, 2}, // WRMSR                   -> #GP
        {{0x0F, 0x32, 0x00}, 2}, // RDMSR                   -> #GP
        {{0x0F, 0x08, 0x00}, 2}, // INVD                    -> #GP
        {{0x0F, 0x09, 0x00}, 2}, // WBINVD                  -> #GP
        {{0x0F, 0x06, 0x00}, 2}, // CLTS                    -> #GP
        {{0x0F, 0x01, 0xF8}, 3}, // SWAPGS                  -> #GP
        {{0x0F, 0x00, 0xD0}, 3}, // LLDT AX (register form) -> #GP
        {{0x0F, 0x00, 0xD8}, 3}, // LTR AX  (register form) -> #GP
    };
    return kPool[i % (sizeof(kPool) / sizeof(kPool[0]))];
}

inline size_t nanomite_marker_pool_size()
{
    return 14;
}

inline const NanomiteMarker &pick_nanomite_marker(std::mt19937_64 &rng)
{
    std::uniform_int_distribution<size_t> dist(0, nanomite_marker_pool_size() - 1);
    return nanomite_marker_pool(dist(rng));
}

} // namespace karity
