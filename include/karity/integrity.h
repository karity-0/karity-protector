/*
 * include/karity/integrity.h -- self-integrity ("anti-tamper") checksum that
 * feeds a value computation, not a branch. Same stance as
 * include/karity/anti_debug.h: the naive shape ("if (hash != stored) exit;")
 * is trivial to defeat -- it's a single compare + jump to a visibly-abnormal
 * exit path, and patching it out is a one-byte flip. This file's checksum is
 * instead folded directly into the VM bytecode decryption key
 * (include/karity/bytecode_crypt.h, via runtime/vm_thunk.S), so there is no
 * comparison and no stored "expected" value anywhere in the image to find.
 *
 * How the fold works (see src/inject/injector.cpp for the protect-time half
 * and runtime/integrity.c + runtime/vm_thunk.S for the runtime half):
 *
 *   - At protect time the injector hashes the finalized bytes of the one
 *     region it wants to protect (the generated interpreter -- the crown
 *     jewel an attacker must patch to defeat the VM at all) with
 *     karity_integrity_hash below, producing H_expected, and stores each
 *     virtualization site's key quad as (real_seed ^ H_expected) instead of
 *     real_seed. The bytecode itself is still encrypted with real_seed.
 *
 *   - At runtime karity_integrity_init (runtime/integrity.c) hashes the live
 *     interpreter bytes with the *same* function and publishes the result to
 *     karity_integrity_taint; runtime/vm_thunk.S XORs that value into the
 *     stored key on every VM entry. When the interpreter is pristine the live
 *     hash equals H_expected, so (real_seed ^ H_expected) ^ H_expected ==
 *     real_seed and decryption is exact. The moment any hashed byte differs,
 *     every subsequent VM invocation decrypts with the wrong key and runs
 *     garbage -- a wrong instruction stream, a crash, or a wrong result, far
 *     away (in both code distance and time) from wherever the patch actually
 *     is. A background watchdog (runtime/integrity.c) re-hashes periodically
 *     so a patch applied *after* startup is caught too, not just one present
 *     at load.
 *
 * Unlike anti_debug's taint (which is 0 when clean and a randomized poison
 * when tripped), this checksum is DETERMINISTIC by necessity: the published
 * value must equal H_expected bit-for-bit for a clean run to decrypt at all,
 * so there is no per-run randomization here. "Clean" is not a special-cased
 * zero -- it is "the live bytes still hash to exactly what they hashed to at
 * protect time".
 *
 * This is a mitigation, not a proof (same honest stance as anti_debug.h and
 * the opcode/rolling-decryption writeups in look/todo.md): the runtime hash
 * computation (runtime/integrity.c) and the vm_thunk fold instruction are
 * themselves code an attacker could locate and neutralize. Protecting the
 * interpreter raises the cost of the most valuable single patch (dumping
 * decrypted bytecode, disabling an opcode handler) from "flip a byte" to
 * "also defeat a watchdog-refreshed checksum whose failure surfaces
 * elsewhere"; it does not make the mechanism itself unpatchable.
 *
 * Opt-in: nothing here runs unless --anti-tamper was passed at protect time
 * (see src/main.cpp / src/inject/injector.cpp). When off, no install call is
 * emitted, key quads are stored as plain real_seed, and karity_integrity_taint
 * stays 0 (BSS) so vm_thunk.S's unconditional XOR is a no-op -- exactly the
 * pre-existing behavior. Self-hashing has no legitimate-use false positives
 * the way --anti-vm does (the image's own bytes are the same for every user),
 * so it is a far safer switch to enable than the anti-analysis categories.
 *
 * This header is included by both the hosted host tool (C++,
 * src/inject/injector.cpp -- computes H_expected) and the freestanding/hosted
 * runtime (C, runtime/integrity.c -- computes the live hash). Kept struct-free,
 * pure integer functions only, same discipline as include/karity/nanomite.h
 * and include/karity/bytecode_crypt.h, so it compiles cleanly in both.
 */
#ifndef KARITY_INTEGRITY_H
#define KARITY_INTEGRITY_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Order-dependent, avalanching hash of `len` bytes at `data`. Each byte is
 * folded in and run through the same splitmix64 finalizer already used
 * (independently) by include/karity/bytecode_crypt.h and
 * include/karity/nanomite.h -- a tiny, well-understood mix, reappearing here a
 * third time rather than being shared code. A cryptographic hash isn't needed:
 * the only property required is that flipping *any* single bit of the hashed
 * region changes the result (so a tampered interpreter decrypts with a
 * different key), and that the host encoder and the freestanding runtime
 * compute bit-identical results from identical bytes -- both hold because both
 * sides #include this one inline function and run on the same x64/little-endian
 * target.
 *
 * len==0 returns exactly 0: a build compiled with --anti-tamper off passes a
 * zero-length region (see runtime/integrity_thunk.S's inline params), and 0
 * keeps the vm_thunk key XOR a true no-op, matching the "clean is a real
 * no-op" contract the whole fold relies on. A real protected region is never
 * empty, so this costs nothing in the enabled case.
 *
 * The nonzero seed constant is arbitrary (any fixed value works, as long as
 * both sides agree); it only guards against an all-zero region hashing to 0
 * and colliding with the len==0 sentinel above. */
static inline uint64_t karity_integrity_hash(const uint8_t *data, uint64_t len)
{
    uint64_t h;
    uint64_t i;

    if (len == 0) {
        return 0;
    }

    h = 0x243F6A8885A308D3ULL; /* arbitrary nonzero seed (digits of pi), see above */
    for (i = 0; i < len; i++) {
        uint64_t z = h ^ (uint64_t)data[i];
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
        h = z ^ (z >> 31);
    }
    /* Pin bit 0 so a clean region can never hash to exactly 0 (which would be
     * indistinguishable from the len==0 / --anti-tamper-off no-op case); the
     * host encoder folds this same value in, so it cancels identically. */
    return h | 1ULL;
}

#ifdef __cplusplus
}
#endif

#endif /* KARITY_INTEGRITY_H */
