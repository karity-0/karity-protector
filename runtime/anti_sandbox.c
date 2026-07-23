/*
 * runtime/anti_sandbox.c -- automated-analysis-environment heuristics,
 * called from runtime/anti_debug.c's karity_anti_debug_scan() and folded
 * into the same taint value (see include/karity/anti_sandbox.h and
 * anti_debug.h's file headers for why this is one function among several
 * feeding one funnel, not a separate mechanism). Same freestanding
 * discipline as the rest of this runtime: no windows.h, structs accessed
 * by raw documented offset, WinAPI resolved by name hash.
 */
#include "karity/anti_sandbox.h"

#include "api_resolve.h"

/* karity_hash_name() results, precomputed offline -- see runtime/api_resolve.h. */
#define KARITY_HASH_KERNEL32_DLL         0xBE1260896DDB9555ULL
#define KARITY_HASH_SBIEDLL_DLL          0xC01C07E441A66E8EULL
#define KARITY_HASH_GET_SYSTEM_INFO      0x23D41DE1B50D96B6ULL
#define KARITY_HASH_GLOBAL_MEMORY_STATUS_EX 0xDF1CB0C508CCB7F0ULL
#define KARITY_HASH_GET_TICK_COUNT_64    0x9E5A92DD70EBBB03ULL
#define KARITY_HASH_SLEEP                0x000000310E07CD7EULL

#define KARITY_ASB_TAINT_SBIE           0xC6737B8B2A6A7B5FULL
#define KARITY_ASB_TAINT_LOW_CPU_COUNT  0x5531AE6DD30A286FULL
#define KARITY_ASB_TAINT_LOW_RAM        0xA28718E5623A7A75ULL
#define KARITY_ASB_TAINT_SHORT_UPTIME   0x5C1ED35FCA2410FDULL
#define KARITY_ASB_TAINT_SLEEP_SKEW     0xFEE29F53EBF644BBULL

typedef void (*karity_pfn_get_system_info)(void *info);
typedef int (*karity_pfn_global_memory_status_ex)(void *info);
typedef uint64_t (*karity_pfn_get_tick_count_64)(void);
typedef void (*karity_pfn_sleep)(uint32_t ms);

/* Sandboxie injects sbiedll.dll into every process it sandboxes -- a walk
 * of PEB->Ldr->InMemoryOrderModuleList (the exact same technique
 * karity_resolve_module already performs for ordinary API resolution) for
 * that one module name is a direct, reliable, Sandboxie-specific signal;
 * not a heuristic like the others in this file. */
static int karity_asb_check_sandboxie(void)
{
    return karity_resolve_module(KARITY_HASH_SBIEDLL_DLL) != 0;
}

/* SYSTEM_INFO.dwNumberOfProcessors, x64 offset 0x20 (wProcessorArchitecture
 * (2)+wReserved(2)+dwPageSize(4)+lpMinimumApplicationAddress(8)+
 * lpMaximumApplicationAddress(8)+dwActiveProcessorMask(8) = 32 bytes
 * before it). Real, in-use desktops/laptops have had >=2 logical cores for
 * over a decade; a single-core VM is a common minimal-footprint analysis
 * sandbox configuration (kept small so many instances can run in
 * parallel). */
static int karity_asb_check_low_cpu_count(void)
{
    void *kernel32 = karity_resolve_module(KARITY_HASH_KERNEL32_DLL);
    karity_pfn_get_system_info get_info;
    unsigned char info[64];
    uint32_t num_processors;

    if (!kernel32) return 0;
    get_info = (karity_pfn_get_system_info)karity_resolve_proc(kernel32, KARITY_HASH_GET_SYSTEM_INFO);
    if (!get_info) return 0;

    get_info(info);
    num_processors = *(uint32_t *)(info + 0x20);
    return num_processors < 2;
}

/* MEMORYSTATUSEX.ullTotalPhys, offset 8 (dwLength(4)+dwMemoryLoad(4) before
 * it) -- dwLength must be set to sizeof(MEMORYSTATUSEX) (64 bytes) before
 * the call, the one field GlobalMemoryStatusEx itself requires as input.
 * Sandboxes are routinely provisioned with 1-2 GiB to keep many concurrent
 * instances cheap; a conservative 1.5 GiB threshold avoids flagging
 * genuinely low-end but real hardware. */
static int karity_asb_check_low_ram(void)
{
    void *kernel32 = karity_resolve_module(KARITY_HASH_KERNEL32_DLL);
    karity_pfn_global_memory_status_ex mem_status;
    unsigned char status[64];
    uint64_t total_phys;

    if (!kernel32) return 0;
    mem_status = (karity_pfn_global_memory_status_ex)karity_resolve_proc(kernel32, KARITY_HASH_GLOBAL_MEMORY_STATUS_EX);
    if (!mem_status) return 0;

    *(uint32_t *)status = 64; /* dwLength */
    if (!mem_status(status)) return 0;

    total_phys = *(uint64_t *)(status + 8);
    return total_phys != 0 && total_phys < (1536ULL * 1024 * 1024);
}

/* GetTickCount64(): milliseconds since boot, plain return value, no struct.
 * An analysis VM is routinely booted fresh specifically to run one sample
 * and torn down after -- a real user's machine has typically been up far
 * longer. Deliberately conservative (3 minutes) since "just rebooted a
 * real PC" is a genuine, if less common, false-positive source this check
 * alone can't rule out -- one soft signal among several OR'd together, not
 * load-bearing on its own (see the file header). */
static int karity_asb_check_short_uptime(void)
{
    void *kernel32 = karity_resolve_module(KARITY_HASH_KERNEL32_DLL);
    karity_pfn_get_tick_count_64 tick_count_64;

    if (!kernel32) return 0;
    tick_count_64 = (karity_pfn_get_tick_count_64)karity_resolve_proc(kernel32, KARITY_HASH_GET_TICK_COUNT_64);
    if (!tick_count_64) return 0;

    return tick_count_64() < 180000ULL; /* 3 minutes */
}

/* Sleep-skew: many automated sandboxes hook Sleep/NtDelayExecution to skip
 * the actual wait (so a sample that stalls to evade time-limited analysis
 * doesn't just eat the sandbox's clock) -- requesting a short, real Sleep
 * and timing the *wall-clock* elapsed time around it catches exactly that.
 * A hooked Sleep that returns near-instantly is a strong, fairly
 * hard-to-avoid signal (the sandbox has to actually let time pass to stop
 * looking like a sandbox, which defeats its own purpose for anything that
 * *does* time-gate). Costs a genuine ~300ms at call time -- see
 * include/karity/anti_sandbox.h for why that's an acceptable, deliberate
 * one-time cost here rather than something paid on the VM-entry hot
 * path. */
static int karity_asb_check_sleep_skew(void)
{
    void *kernel32 = karity_resolve_module(KARITY_HASH_KERNEL32_DLL);
    karity_pfn_get_tick_count_64 tick_count_64;
    karity_pfn_sleep sleep_fn;
    uint64_t t0, t1;

    if (!kernel32) return 0;
    tick_count_64 = (karity_pfn_get_tick_count_64)karity_resolve_proc(kernel32, KARITY_HASH_GET_TICK_COUNT_64);
    sleep_fn = (karity_pfn_sleep)karity_resolve_proc(kernel32, KARITY_HASH_SLEEP);
    if (!tick_count_64 || !sleep_fn) return 0;

    t0 = tick_count_64();
    sleep_fn(300);
    t1 = tick_count_64();

    return (t1 - t0) < 150ULL;
}

uint64_t karity_anti_sandbox_scan(void)
{
    uint64_t taint = 0;

    if (karity_asb_check_sandboxie())      taint |= KARITY_ASB_TAINT_SBIE;
    if (karity_asb_check_low_cpu_count())  taint |= KARITY_ASB_TAINT_LOW_CPU_COUNT;
    if (karity_asb_check_low_ram())        taint |= KARITY_ASB_TAINT_LOW_RAM;
    if (karity_asb_check_short_uptime())   taint |= KARITY_ASB_TAINT_SHORT_UPTIME;
    if (karity_asb_check_sleep_skew())     taint |= KARITY_ASB_TAINT_SLEEP_SKEW;

    return taint;
}
