/*
 * runtime/integrity.c -- self-integrity ("anti-tamper") checksum. See
 * include/karity/integrity.h for the *why* (checksum folded into the bytecode
 * decryption key, not compared against a stored value + branched on); this
 * file is only the *what*: hash a protected code region and publish the
 * result to karity_integrity_taint, which runtime/vm_thunk.S XORs into the
 * key on every VM entry.
 *
 * Same discipline as runtime/anti_debug.c and runtime/nanomite_veh.c: no
 * windows.h, WinAPI resolved by name hash via api_resolve.h so no plaintext
 * import names sit in the injected image. Compiled twice (see
 * runtime/CMakeLists.txt): into the freestanding runtime blob, and hosted
 * (karity_integrity_hosted) for tests/test_integrity.c.
 *
 * The protected region (base + length) is chosen at protect time -- the
 * injector passes it to karity_integrity_init through runtime/integrity_thunk.S's
 * inline params. This file's job is just to hash whatever region it's handed
 * and keep re-hashing it: it has no notion of what the bytes mean.
 */
#include "karity/integrity.h"

#include "api_resolve.h"

/* karity_hash_name() results, precomputed offline -- same values
 * runtime/anti_debug.c computes independently for the identical modules/APIs,
 * duplicated rather than shared per this runtime's "each file hand-rolls what
 * it needs" discipline (see anti_debug.c's own note on the same duplication). */
#define KARITY_HASH_KERNEL32_DLL   0xBE1260896DDB9555ULL
#define KARITY_HASH_CREATE_THREAD  0xB8BA6A0898BAAB11ULL
#define KARITY_HASH_CLOSE_HANDLE   0xBFC6A6CFFDB928E7ULL
#define KARITY_HASH_SLEEP          0x000000310E07CD7EULL

typedef void *(*karity_pfn_create_thread)(void *sec_attrs, uint64_t stack_size, void *start_addr, void *param,
                                           uint32_t flags, uint32_t *thread_id);
typedef int (*karity_pfn_close_handle)(void *handle);
typedef void (*karity_pfn_sleep)(uint32_t ms);

/* This process's live integrity checksum -- what runtime/vm_thunk.S reads
 * (via a direct symbol reference, one aligned load) on every VM invocation and
 * XORs into the bytecode key. Set once synchronously by karity_integrity_init,
 * then re-published by the watchdog below for the process's lifetime. A
 * naturally-aligned 8-byte store/load is atomic on x64, so no lock is needed
 * between the watchdog writer and vm_thunk.S's reader. Starts at 0 (BSS): a
 * build that never calls karity_integrity_init (most hosted tests, and any
 * binary protected without --anti-tamper) leaves the key XOR a no-op, so this
 * feature fails open by construction -- same stance as karity_anti_debug_taint.
 * DETERMINISTIC, unlike anti_debug's taint: a clean run must publish exactly
 * the same value the injector folded into the stored key at protect time, or
 * decryption wouldn't cancel -- see include/karity/integrity.h. */
uint64_t karity_integrity_taint = 0;

/* The region to hash, captured by karity_integrity_init so the watchdog can
 * keep re-hashing it. Plain globals, single-writer-at-init then read-only. */
static const uint8_t *g_integrity_region_base;
static uint64_t g_integrity_region_len;

static uint64_t karity_integrity_rdtsc(void)
{
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

/* Same splitmix64 finalizer reused elsewhere in this runtime -- here only for
 * watchdog sleep jitter, where "not perfectly uniform" is irrelevant. */
static uint64_t karity_integrity_mix64(uint64_t z)
{
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

/* Watchdog thread body: re-hashes the protected region and republishes the
 * checksum for as long as the process lives, closing the "hash once at
 * startup, patch the interpreter afterward" TOCTOU gap a single install-time
 * check would leave open -- exactly the reasoning karity_anti_debug.c's own
 * watchdog gives. karity_integrity_taint is a naturally-aligned 8-byte global,
 * so the plain store is atomic on x64 against vm_thunk.S's read. */
static uint32_t karity_integrity_watchdog_proc(void *param)
{
    void *kernel32;
    karity_pfn_sleep sleep_fn;
    uint64_t jitter_state = karity_integrity_rdtsc();
    (void)param;

    kernel32 = karity_resolve_module(KARITY_HASH_KERNEL32_DLL);
    sleep_fn = kernel32 ? (karity_pfn_sleep)karity_resolve_proc(kernel32, KARITY_HASH_SLEEP) : 0;
    if (!sleep_fn) {
        return 0; /* no Sleep -> can't run a bounded loop responsibly; bail. The initial hash
                     (already published before this thread started) stays live but un-refreshed
                     -- fail open, not a busy spin, same as anti_debug's watchdog. */
    }

    for (;;) {
        jitter_state = karity_integrity_mix64(jitter_state);
        sleep_fn(200u + (uint32_t)(jitter_state % 300u)); /* 200-500ms, jittered so the interval
                                                              isn't a fixed greppable constant */
        karity_integrity_taint =
            karity_integrity_hash(g_integrity_region_base, g_integrity_region_len);
    }
}

/* Captures the protected region, hashes it once synchronously (so even a
 * process killed before the watchdog's first tick is already covered), and
 * spawns the watchdog. Always returns 1 (best-effort: even if thread creation
 * fails, the synchronous hash is already live). Called once, at the first
 * virtualized site's stub, by runtime/integrity_thunk.S with the region the
 * injector baked into that call site's inline params -- see
 * src/inject/injector.cpp. `len == 0` (a binary protected without
 * --anti-tamper) hashes to 0 (see include/karity/integrity.h), leaving the
 * key XOR a no-op. */
int karity_integrity_init(const uint8_t *region_base, uint64_t region_len)
{
    void *kernel32;
    karity_pfn_create_thread create_thread;
    karity_pfn_close_handle close_handle;
    void *thread;

    g_integrity_region_base = region_base;
    g_integrity_region_len = region_len;
    karity_integrity_taint = karity_integrity_hash(region_base, region_len);

    kernel32 = karity_resolve_module(KARITY_HASH_KERNEL32_DLL);
    if (!kernel32) return 1;
    create_thread = (karity_pfn_create_thread)karity_resolve_proc(kernel32, KARITY_HASH_CREATE_THREAD);
    close_handle = (karity_pfn_close_handle)karity_resolve_proc(kernel32, KARITY_HASH_CLOSE_HANDLE);
    if (!create_thread || !close_handle) return 1;

    thread = create_thread(0, 0, (void *)karity_integrity_watchdog_proc, 0, 0, 0);
    if (thread) close_handle(thread); /* fire-and-forget: the thread keeps running without a handle */
    return 1;
}
