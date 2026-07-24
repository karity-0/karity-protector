/*
 * include/karity/anti_vm.h -- hypervisor-presence signals, same "feed a
 * value computation, not a branch" treatment as include/karity/anti_debug.h
 * (read that file's header first -- this one only adds more contributors to
 * the same taint funnel, it doesn't introduce a second mechanism).
 *
 * karity_anti_vm_scan() is called from runtime/anti_debug.c's
 * karity_anti_debug_scan() and OR'd into the same combined result that ends
 * up in karity_anti_debug_taint -- see that file for why this project
 * deliberately keeps one covert channel into the decryption key rather than
 * a separate one per detection category (debug/VM/sandbox): three
 * independent mechanisms would just be three independent things to find and
 * neutralize instead of one.
 */
#ifndef KARITY_ANTI_VM_H
#define KARITY_ANTI_VM_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Side-effect-free hypervisor checks (CPUID present-bit, vendor leaf, CPUID
 * timing) -- the caller (runtime/anti_debug.c) runs these unconditionally
 * and masks the result by whether the VM category is enabled, so there's no
 * single "skip VM detection" branch. Returns the combined taint (0 if
 * nothing looked virtualized). */
uint64_t karity_anti_vm_scan_passive(void);

/* The VMware backdoor-port probe, which raises a self-caught first-chance
 * exception a debugger would observe -- so the caller only runs this when
 * the VM category is actually enabled (see runtime/anti_debug.c). */
uint64_t karity_anti_vm_scan_active(void);

/* Passive | active, for the standalone hosted reporter tests/test_anti_vm.c
 * (see include/karity/anti_debug.h for why only zero-ness is meaningful).
 * Safe to call from a hosted build -- see runtime/CMakeLists.txt's
 * karity_anti_debug_hosted (which bundles anti_vm.c). */
uint64_t karity_anti_vm_scan(void);

#ifdef __cplusplus
}
#endif

#endif /* KARITY_ANTI_VM_H */
