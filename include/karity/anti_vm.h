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

/* Runs every hypervisor-detection technique once and returns their combined
 * contribution (0 if nothing looked virtualized, nonzero otherwise -- see
 * include/karity/anti_debug.h for why only the zero-ness is ever meaningful
 * anywhere). Safe to call from a hosted build too -- see
 * runtime/CMakeLists.txt's karity_anti_vm_hosted. */
uint64_t karity_anti_vm_scan(void);

#ifdef __cplusplus
}
#endif

#endif /* KARITY_ANTI_VM_H */
