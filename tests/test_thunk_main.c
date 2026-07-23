#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>

#include "karity/bytecode_crypt.h"

extern int test_thunk(void);
extern int test_thunk2(void);
extern int test_thunk_nested(void);
extern int test_thunk_taint(void);
extern void karity_vm_run(void *ctx); /* karity_vm_interp_hosted's reference interpreter */
extern void karity_probe_capture_seed(void); /* test_thunk.S's stand-in interpreter for test_thunk_taint */
extern uint8_t karity_interp_rel32[4]; /* the 4-byte operand of vm_thunk's `call rel32` */

/* test_thunk.S hand-assembles its bytecode buffers as plaintext .byte
 * literals, which can't be pre-encrypted by hand at assembly time -- both
 * interpreters now unconditionally decrypt every fetch (see
 * include/karity/bytecode_crypt.h and look/todo.md section C), keyed by
 * karity_vm_thunk's now-three-field params quad (bytecode_delta,
 * exit_target_delta, raw seed -- see runtime/vm_thunk.S). This constant
 * MUST match test_thunk.S's own KARITY_TEST_SEED -- it's baked into every
 * params block's third .quad there at assemble time. */
#define KARITY_TEST_SEED 0x9E3779B97F4A7C15ULL

extern uint8_t bytecode[], bytecode_end[];
extern uint8_t bytecode2[], bytecode2_end[];
extern uint8_t bytecode_inner[], bytecode_inner_end[];
extern uint8_t bytecode_outer[], bytecode_outer_end[];

static void encrypt_test_bytecode(void)
{
    karity_bytecode_xor_crypt(bytecode, (uint64_t)(bytecode_end - bytecode), 0, KARITY_TEST_SEED);
    karity_bytecode_xor_crypt(bytecode2, (uint64_t)(bytecode2_end - bytecode2), 0, KARITY_TEST_SEED);
    karity_bytecode_xor_crypt(bytecode_inner, (uint64_t)(bytecode_inner_end - bytecode_inner), 0, KARITY_TEST_SEED);
    karity_bytecode_xor_crypt(bytecode_outer, (uint64_t)(bytecode_outer_end - bytecode_outer), 0, KARITY_TEST_SEED);
}

/* vm_thunk.S reaches the interpreter via a direct `call rel32` whose
 * displacement has no link-time value (see runtime/vm_thunk.S) -- in
 * production the injector patches it into the file before the section is
 * ever loaded, but here it's already-loaded, read+execute .text, so this
 * needs an explicit VirtualProtect to write it like the injector would. */
static void patch_interp_call_target(void *target)
{
    DWORD old_protect;
    int64_t rel;

    VirtualProtect(karity_interp_rel32, 4, PAGE_EXECUTE_READWRITE, &old_protect);
    rel = (int64_t)(uintptr_t)target - ((int64_t)(uintptr_t)karity_interp_rel32 + 4);
    memcpy(karity_interp_rel32, &rel, 4);
    VirtualProtect(karity_interp_rel32, 4, old_protect, &old_protect);
}

int main(void)
{
    patch_interp_call_target((void *)&karity_vm_run);
    encrypt_test_bytecode();

    int rc = test_thunk();
    printf("test_thunk: %s (code=%d)\n", rc == 0 ? "PASS" : "FAIL", rc);

    int rc2 = test_thunk2();
    printf("test_thunk2: %s (code=%d)\n", rc2 == 0 ? "PASS" : "FAIL", rc2);

    int rc3 = test_thunk_nested();
    printf("test_thunk_nested: %s (code=%d)\n", rc3 == 0 ? "PASS" : "FAIL", rc3);

    /* test_thunk_taint doesn't run any bytecode at all (see its own comment
     * in test_thunk.S) -- it repoints karity_interp_rel32 at a stand-in
     * "interpreter" that just captures ctx->bytecode_key_seed and returns,
     * so no encrypted bytecode buffer/seed sync with test_thunk.S is needed
     * for it the way encrypt_test_bytecode() is for the other three. */
    patch_interp_call_target((void *)&karity_probe_capture_seed);
    int rc4 = test_thunk_taint();
    patch_interp_call_target((void *)&karity_vm_run);
    printf("test_thunk_taint: %s (code=%d)\n", rc4 == 0 ? "PASS" : "FAIL", rc4);

    return rc != 0 || rc2 != 0 || rc3 != 0 || rc4 != 0;
}
