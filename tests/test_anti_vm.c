/* Sanity-checks runtime/anti_vm.c's combined scan. Unlike test_anti_debug.c
 * (which can deterministically flip real PEB bits to trigger and then
 * un-trigger a check), hypervisor presence isn't poke-able in-process --
 * this just reports what karity_anti_vm_scan() sees on the machine actually
 * running ctest, so a human can sanity-check the result (e.g. "this CI box
 * is itself a VM, so of course this is nonzero here" is expected and not a
 * bug) rather than asserting a specific value. */
#include <stdio.h>

#include "karity/anti_vm.h"

int main(void)
{
    uint64_t taint = karity_anti_vm_scan();
    printf("karity_anti_vm_scan() = 0x%016llX%s\n", (unsigned long long)taint,
           taint == 0 ? " (bare metal / no hypervisor detected)" : " (hypervisor detected)");
    return 0;
}
