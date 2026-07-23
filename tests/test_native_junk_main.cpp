#include <cstdio>
#include <cstring>
#include <vector>
#include <windows.h>
#include "x86_junk.h"

extern "C" int test_call_junk_buffer(void *buf);

static bool run_buffer(const std::vector<uint8_t> &code, const char *label)
{
    std::vector<uint8_t> full = code;
    full.push_back(0xC3); // ret

    void *mem = VirtualAlloc(nullptr, full.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(mem, full.data(), full.size());

    int rc = test_call_junk_buffer(mem);
    VirtualFree(mem, 0, MEM_RELEASE);

    if (rc == 0) {
        printf("%s: PASS (size=%zu)\n", label, full.size());
        return true;
    }
    printf("%s: FAIL rc=%d (size=%zu)\n", label, rc, full.size());
    return false;
}

using namespace karity;
int main()
{
    std::mt19937_64 rng(12345);
    int fails = 0;

    for (int i = 0; i < 20; i++) {
        std::vector<uint8_t> code;
        emit_native_junk(code, rng);
        if (!run_buffer(code, "junk")) fails++;
    }
    for (int i = 0; i < 20; i++) {
        std::vector<uint8_t> code;
        emit_native_opaque_predicate(code, rng);
        if (!run_buffer(code, "opaque_predicate")) fails++;
    }
    for (int i = 0; i < 20; i++) {
        std::vector<uint8_t> code;
        emit_junk_call(code, rng);
        if (!run_buffer(code, "junk_call")) fails++;
    }
    // combined, multi-round, like the real entry stub will look
    for (int i = 0; i < 10; i++) {
        std::vector<uint8_t> code;
        emit_native_junk(code, rng);
        emit_native_opaque_predicate(code, rng);
        emit_junk_call(code, rng);
        emit_native_junk(code, rng);
        if (!run_buffer(code, "combined")) fails++;
    }

    if (fails == 0) { printf("ALL PASS\n"); return 0; }
    printf("%d FAILURES\n", fails);
    return 1;
}
