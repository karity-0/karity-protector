/*
 * tests/test_integrity.c -- self-integrity ("anti-tamper") checksum.
 *
 * Two things are validated here:
 *   1. The pure hash (include/karity/integrity.h), directly: determinism,
 *      len==0 -> 0, and single-bit avalanche (any flipped byte changes the
 *      result -- the one property the checksum-as-key scheme actually needs).
 *   2. That the runtime side (runtime/integrity.c, via karity_integrity_hosted)
 *      publishes exactly the same value the host header computes -- i.e. the
 *      protect-time H_expected and the runtime live hash agree bit-for-bit, so
 *      a clean run's key XOR cancels. Plus the checksum-as-key round trip
 *      itself: (real ^ H) ^ H_runtime == real iff H_runtime == H.
 *
 * See include/karity/integrity.h for the design.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "karity/integrity.h"

/* runtime/integrity.c (karity_integrity_hosted) */
extern uint64_t karity_integrity_taint;
int karity_integrity_init(const uint8_t *region_base, uint64_t region_len);

static int g_failures;

static void check(int cond, const char *msg)
{
    if (!cond) {
        printf("FAIL: %s\n", msg);
        g_failures++;
    }
}

int main(void)
{
    /* a fixed pseudo-random-ish region to hash */
    uint8_t region[256];
    uint64_t i;
    for (i = 0; i < sizeof(region); i++) {
        region[i] = (uint8_t)(i * 131u + 7u);
    }

    /* 1a. determinism */
    uint64_t h1 = karity_integrity_hash(region, sizeof(region));
    uint64_t h2 = karity_integrity_hash(region, sizeof(region));
    check(h1 == h2, "hash is not deterministic");
    check(h1 != 0, "hash of a real region must be nonzero");

    /* 1b. len==0 -> exactly 0 (the --anti-tamper-off / no-op sentinel) */
    check(karity_integrity_hash(region, 0) == 0, "hash of a zero-length region must be 0");

    /* 1c. single-bit avalanche: flip each bit of one byte, expect a different
     * hash every time (the whole point -- any patch must change the checksum) */
    for (i = 0; i < 8; i++) {
        uint8_t saved = region[100];
        region[100] ^= (uint8_t)(1u << i);
        uint64_t hp = karity_integrity_hash(region, sizeof(region));
        check(hp != h1, "flipping a bit did not change the hash");
        region[100] = saved;
    }
    /* and a change at the very last byte (guards against an off-by-one that
     * would skip the final byte) */
    {
        uint8_t saved = region[sizeof(region) - 1];
        region[sizeof(region) - 1] ^= 0x80u;
        check(karity_integrity_hash(region, sizeof(region)) != h1, "flipping the last byte did not change the hash");
        region[sizeof(region) - 1] = saved;
    }

    /* 2a. runtime side agrees with the header (this is what makes a clean run's
     * key XOR cancel: protect-time H_expected == runtime live hash) */
    karity_integrity_init(region, sizeof(region));
    check(karity_integrity_taint == h1, "runtime karity_integrity_init published a different value than the header hash");

    /* 2b. checksum-as-key round trip. real_seed is any value; the injector
     * stores (real_seed ^ H_expected); vm_thunk XORs the live hash back in. */
    {
        uint64_t real_seed = 0xDEADBEEF12345678ULL;
        uint64_t h_expected = karity_integrity_hash(region, sizeof(region));
        uint64_t stored = real_seed ^ h_expected;

        /* pristine: live hash == H_expected -> recovers real_seed exactly */
        uint64_t h_runtime_clean = karity_integrity_hash(region, sizeof(region));
        check((stored ^ h_runtime_clean) == real_seed, "clean round trip did not recover real_seed");

        /* tampered: one byte differs -> live hash differs -> wrong key */
        region[42] ^= 0x01u;
        uint64_t h_runtime_tampered = karity_integrity_hash(region, sizeof(region));
        region[42] ^= 0x01u;
        check((stored ^ h_runtime_tampered) != real_seed, "tampered round trip must NOT recover real_seed");
    }

    if (g_failures == 0) {
        printf("test_integrity: all checks passed\n");
        return 0;
    }
    printf("test_integrity: %d failure(s)\n", g_failures);
    return 1;
}
