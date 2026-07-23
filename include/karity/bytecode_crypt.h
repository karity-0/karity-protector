/*
 * include/karity/bytecode_crypt.h -- keystream for VM bytecode-at-rest
 * encryption ("opcode rolling decryption" in this project's shorthand, see
 * look/todo.md section C).
 *
 * Unlike include/karity/nanomite.h's karity_nanomite_xor_crypt (which only
 * ever decrypts one whole contiguous block, sequentially, from that block's
 * own start), the VM interpreter's instruction pointer jumps around inside
 * a bytecode blob -- branches, loops, and calls all re-enter the same site
 * at arbitrary offsets -- so decryption here must be directly seekable to
 * any absolute byte offset without replaying the keystream from position 0.
 *
 * karity_nanomite_splitmix64_next advances via `state += INC; output =
 * mix(state)`, which means state after N sequential calls from `seed` is
 * exactly `seed + N*INC` -- i.e. the keystream output for logical position
 * N is directly computable as `mix(seed + (N+1)*INC)` with no iteration.
 * This header exploits that same property, one output byte at a time
 * (rather than nanomite's 8-bytes-per-mix chunking): an 8-byte operand read
 * at an arbitrary, not-necessarily-8-aligned offset would otherwise span
 * two keystream chunks, which would need the hand-generated x64 decrypt
 * code in src/native/interp_codegen.cpp to combine two keystream words with
 * a runtime-variable shift/mask -- exactly the kind of alignment edge case
 * that has caused most of this codebase's subtler bugs historically (see
 * isa.h's INC/DEC CF-preservation and VOP_SHL/SHR's count==0 notes). Doing
 * one full splitmix64 mix per output *byte* costs ~8x the multiplies of
 * nanomite's chunked scheme, but every fetch (1 byte or 8) then decomposes
 * into fully independent single-byte XORs with zero alignment cases at
 * all -- worth it here since this project already trades interpreter
 * throughput for obfuscation density everywhere else, and this file's own
 * correctness is otherwise very hard to get right by hand.
 *
 * This header is included by both hosted host-tool code (C++,
 * src/inject/injector.cpp -- encrypts each site's finalized bytecode blob)
 * and freestanding/hosted runtime code (C, runtime/vm_interp.c's decrypt
 * side, test-only -- see that file's header for why the *real* injected
 * interpreter, src/native/interp_codegen.cpp, hand-generates the equivalent
 * logic directly as machine code instead of calling this header at all).
 * Kept struct-free, pure integer functions only, same discipline as
 * nanomite.h, so it compiles cleanly in both.
 */
#ifndef KARITY_BYTECODE_CRYPT_H
#define KARITY_BYTECODE_CRYPT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Single keystream byte for absolute byte offset `abs_offset` within a
 * bytecode blob keyed by `seed` -- see the file header for the seek-math
 * derivation. Deliberately independent of any other offset's output (no
 * shared, advancing state), so callers may request offsets in any order. */
static inline uint8_t karity_bytecode_keystream_byte(uint64_t seed, uint64_t abs_offset)
{
    uint64_t state = seed + (abs_offset + 1) * 0x9E3779B97F4A7C15ULL;
    uint64_t z = state;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    z = z ^ (z >> 31);
    return (uint8_t)z;
}

/* XORs `len` bytes at `data` in place, where `data[i]` corresponds to
 * logical bytecode offset `base_offset + i` (encryption and decryption are
 * the same operation, as always with XOR keystreams). `base_offset` lets a
 * caller encrypt/decrypt a sub-range without shifting which keystream bytes
 * apply -- the host encoder always passes 0 (the whole code region, from
 * its own first opcode byte); nothing in this codebase currently needs a
 * nonzero base_offset the way nanomite's per-block seeds do, but the
 * parameter costs nothing and keeps this the same shape as
 * karity_nanomite_xor_crypt. */
static inline void karity_bytecode_xor_crypt(uint8_t *data, uint64_t len, uint64_t base_offset, uint64_t seed)
{
    uint64_t i;
    for (i = 0; i < len; i++) {
        data[i] = (uint8_t)(data[i] ^ karity_bytecode_keystream_byte(seed, base_offset + i));
    }
}

#ifdef __cplusplus
}
#endif

#endif /* KARITY_BYTECODE_CRYPT_H */
