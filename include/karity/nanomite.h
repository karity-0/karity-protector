/*
 * include/karity/nanomite.h -- shared ISA for exception-based code
 * encryption ("nanomites" in this project's shorthand, though closer in
 * spirit to trap-decrypt-execute than classic breakpoint nanomites -- see
 * look/roadmap.txt).
 *
 * A "site" replaces a run of original instruction bytes (a "block") with
 * [trap marker][ciphertext], both occupying exactly the block's original
 * span -- no growth, so nothing after it needs to move. The marker is one
 * of a pool of instruction encodings guaranteed to fault in usermode
 * (src/native/nanomite_markers.h, host-only -- the runtime side never needs
 * to know which marker it was, only its length) and necessarily clobbers
 * the first `marker_len` ciphertext bytes, which is why those are also
 * saved in `clobbered`.
 *
 * On fault, runtime/nanomite_veh.c reconstructs the full ciphertext
 * (clobbered bytes + the untouched remainder still sitting in the image),
 * decrypts it with the keystream in this header, copies the plaintext into
 * a scratch slot with an appended indirect jump back to `resume_va`, and
 * resumes execution there. See runtime/nanomite_veh.c for the handler.
 *
 * A block whose last (real, decrypted) instruction is a direct CALL/JMP/Jcc
 * (branch_kind != KARITY_NANOMITE_BRANCH_NONE) is handled differently: its
 * original E8/E9 rel32 (or Jcc rel8/rel32) bytes are correct only when
 * executed from their original address, not from the scratch slot, so the
 * handler drops those trailing `branch_len` bytes and synthesizes an
 * absolute indirect transfer (`FF 25` + an 8-byte VA) instead --
 * address-range-independent, same trick already used for the resume jump.
 * This is what lets a nanomite region survive walking through calls and
 * branches (and terminate cleanly at an unconditional jmp/ret) instead of
 * stopping at the first one, without needing full CFG reconstruction.
 * KARITY_NANOMITE_BRANCH_CALL is *not* rewritten as a real indirect `call`:
 * a real call's auto-pushed return address would land in this VirtualAlloc'd
 * scratch slot, which has no RUNTIME_FUNCTION/UNWIND_INFO coverage, breaking
 * SEH unwinding for any exception the callee doesn't itself catch. Instead
 * the handler pushes `resume_va` (a real, already-unwindable address back in
 * the original image, via `FF 35`) itself and `jmp`s (`FF 25`) to the
 * callee, so a normal return *and* an escaping exception both land on
 * resume_va directly. See runtime/nanomite_veh.c's branch_kind handling.
 *
 * KARITY_NANOMITE_BRANCH_JCC is the one case with two live outgoing edges
 * instead of one: `branch_target_delta` is the taken target, `resume_delta`
 * doubles as the not-taken (fallthrough) target (there's no "call returns"
 * continuation to conflict with, unlike the CALL case). x86 has no
 * absolute-indirect *conditional* jump, so real EFLAGS -- already correct,
 * since every plain instruction before the Jcc was copied and re-executed
 * verbatim, same as any other block -- are tested with the original short
 * Jcc opcode (`branch_cc`), rewritten only to hop over a small local
 * trampoline of two absolute-indirect jumps instead of computing an
 * address-range-dependent rel8/rel32 target. See runtime/nanomite_veh.c.
 * See src/native/nanomite_scan.h for how the host scanner discovers and
 * links both edges (a worklist-driven walk of the region's CFG, not a
 * single straight-line pass).
 *
 * This header is included by both freestanding runtime code (C) and hosted
 * host-tool code (C++) -- kept struct-only plus small pure integer
 * functions so it compiles cleanly in both.
 */
#ifndef KARITY_NANOMITE_H
#define KARITY_NANOMITE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define KARITY_NANOMITE_MAX_CLOBBER 3u /* longest marker in the host-side pool */

/* Upper bound on a single block's plaintext/ciphertext length, shared by
 * the host-side scanner/encoder (which must never produce a bigger block)
 * and the runtime handler (whose fixed-size scratch slots and stack buffer
 * are sized off this same constant) -- see runtime/nanomite_veh.c. */
#define KARITY_NANOMITE_MAX_BLOCK 256u

#define KARITY_NANOMITE_BRANCH_NONE 0u /* plain block, ends with a resume jump */
#define KARITY_NANOMITE_BRANCH_CALL 1u /* block ends in a direct CALL rel32;
                                           execution continues (a resume jump
                                           is appended after the rewritten
                                           call, for when it returns)        */
#define KARITY_NANOMITE_BRANCH_JMP  2u /* block ends in a direct JMP rel8/32;
                                           no resume needed, nothing falls
                                           through an unconditional jump     */
#define KARITY_NANOMITE_BRANCH_JCC  3u /* block ends in a direct Jcc rel8/32;
                                           two live targets -- see
                                           branch_target_delta/resume_delta/
                                           branch_cc below and the block
                                           comment above                    */

/*
 * All VAs are stored as deltas from the nanomite region's own anchor (the
 * karity_nanomite_site array's own base address), not absolute -- same
 * ASLR-safety reasoning as karity_vmctx::anchor in isa.h: this table has no
 * PE base relocation entries, so an absolute VA baked in at protect time
 * would go stale if the image is rebased.
 */
typedef struct karity_nanomite_site {
    int64_t  trap_delta;          /* anchor + trap_delta = VA of the trap
                                      marker (== block start, == the
                                      faulting RIP)                         */
    int64_t  resume_delta;        /* anchor + resume_delta = VA to jump back
                                      to once the decrypted block finishes:
                                      the next block for a plain block, the
                                      callee-return point for a CALL block,
                                      or the not-taken (fallthrough) target
                                      for a JCC block. Unused for JMP (which
                                      has nothing to fall through to).      */
    int64_t  branch_target_delta; /* anchor + branch_target_delta = absolute
                                      VA of the block's trailing CALL/JMP
                                      target, or a JCC block's taken target;
                                      meaningful only when
                                      branch_kind != KARITY_NANOMITE_BRANCH_NONE */
    uint64_t prng_seed;           /* keystream seed, see karity_nanomite_xor_crypt */
    uint32_t block_len;           /* total block length in bytes (marker +
                                      ciphertext together == original
                                      plaintext run length; nothing grows)  */
    uint8_t  marker_len;          /* 1..KARITY_NANOMITE_MAX_CLOBBER: how many
                                      bytes at block start are the trap marker */
    uint8_t  branch_kind;         /* KARITY_NANOMITE_BRANCH_* */
    uint8_t  branch_len;          /* length of the trailing CALL/JMP/Jcc
                                      instruction within the block, if
                                      branch_kind != KARITY_NANOMITE_BRANCH_NONE */
    uint8_t  branch_cc;           /* KARITY_NANOMITE_BRANCH_JCC only: the
                                      x86 Jcc/SETcc condition nibble (0x0-0xF,
                                      same encoding as KARITY_CC_* in
                                      include/karity/isa.h) -- equal to the
                                      instruction's opcode byte & 0x0F for
                                      both the short (0x70+cc) and near
                                      (0x0F, 0x80+cc) Jcc encodings. Unused
                                      otherwise.                            */
    uint8_t  clobbered[KARITY_NANOMITE_MAX_CLOBBER]; /* original ciphertext
                                      bytes the marker overwrote in-place   */
} karity_nanomite_site;

/*
 * splitmix64 -- fast, good-enough (this isn't defending against a
 * cryptanalyst, just against static disassembly) and trivial to keep
 * bit-identical between the C++ host encoder and the freestanding C
 * runtime decoder since it's pure integer arithmetic, no library calls.
 */
static inline uint64_t karity_nanomite_splitmix64_next(uint64_t *state)
{
    uint64_t z = (*state += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

/* XORs `len` bytes at `data` in place with a keystream derived from `seed`
 * (encryption and decryption are the same operation, as always with XOR
 * keystreams). Used identically by the host encoder (to produce ciphertext)
 * and the runtime handler (to recover plaintext). */
static inline void karity_nanomite_xor_crypt(uint8_t *data, uint32_t len, uint64_t seed)
{
    uint64_t state = seed;
    uint32_t i = 0;
    while (i < len) {
        uint64_t ks = karity_nanomite_splitmix64_next(&state);
        uint32_t chunk = (len - i < 8) ? (len - i) : 8;
        uint32_t j;
        for (j = 0; j < chunk; j++) {
            data[i + j] = (uint8_t)(data[i + j] ^ (uint8_t)(ks >> (8 * j)));
        }
        i += chunk;
    }
}

#ifdef __cplusplus
}
#endif

#endif /* KARITY_NANOMITE_H */
