/* Hosted correctness tests for the import-free API resolver
 * (runtime/api_resolve.c), compiled normally so results can be checked
 * against real GetModuleHandle/GetProcAddress. */
#include <stdio.h>
#include <windows.h>
#include "api_resolve.h"

static int g_failures = 0;

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__); \
            g_failures++; \
        } \
    } while (0)

static void test_resolve_module(void)
{
    void *got = karity_resolve_module(karity_hash_name("kernel32.dll"));
    void *want = (void *)GetModuleHandleA("kernel32.dll");
    CHECK(got == want, "resolve_module(kernel32.dll) matches GetModuleHandleA");

    got = karity_resolve_module(karity_hash_name("KERNEL32.DLL"));
    CHECK(got == want, "resolve_module is case-insensitive");

    got = karity_resolve_module(karity_hash_name("ntdll.dll"));
    want = (void *)GetModuleHandleA("ntdll.dll");
    CHECK(got == want, "resolve_module(ntdll.dll) matches GetModuleHandleA");

    got = karity_resolve_module(karity_hash_name("this-module-does-not-exist.dll"));
    CHECK(got == NULL, "resolve_module returns NULL for an unloaded module");
}

static void test_resolve_proc(void)
{
    void *kernel32 = karity_resolve_module(karity_hash_name("kernel32.dll"));

    void *got = karity_resolve_proc(kernel32, karity_hash_name("ExitProcess"));
    void *want = (void *)GetProcAddress((HMODULE)kernel32, "ExitProcess");
    CHECK(got == want, "resolve_proc(kernel32, ExitProcess) matches GetProcAddress");

    /* CreateFileW is forwarded to kernelbase.dll on modern Windows --
     * exercises the forwarder-chasing path in karity_resolve_proc. */
    got = karity_resolve_proc(kernel32, karity_hash_name("CreateFileW"));
    want = (void *)GetProcAddress((HMODULE)kernel32, "CreateFileW");
    CHECK(got == want, "resolve_proc follows forwarded exports (CreateFileW)");

    got = karity_resolve_proc(kernel32, karity_hash_name("ThisFunctionDoesNotExist"));
    CHECK(got == NULL, "resolve_proc returns NULL for a nonexistent export");
}

static void test_resolve_api(void)
{
    void *got = karity_resolve_api(karity_hash_name("kernel32.dll"),
                                    karity_hash_name("AddVectoredExceptionHandler"));
    void *want = (void *)GetProcAddress(GetModuleHandleA("kernel32.dll"),
                                         "AddVectoredExceptionHandler");
    CHECK(got == want, "resolve_api(kernel32, AddVectoredExceptionHandler) matches GetProcAddress");
    CHECK(got != NULL, "AddVectoredExceptionHandler actually resolved to something");
}

int main(void)
{
    test_resolve_module();
    test_resolve_proc();
    test_resolve_api();

    if (g_failures == 0) {
        printf("all api_resolve tests passed\n");
        return 0;
    }
    fprintf(stderr, "%d api_resolve test(s) failed\n", g_failures);
    return 1;
}
