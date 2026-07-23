/*
 * runtime/api_resolve.h -- import-free WinAPI resolution (x64, Windows).
 *
 * Injected code has no import table of its own, so it can't just `call
 * ExitProcess` -- the loader never resolved that symbol for it. This walks
 * the PEB's loaded-module list and each module's PE export directory by
 * hand to find any WinAPI function by name, the same technique virtually
 * all position-independent shellcode uses.
 *
 * Names are looked up by hash (see karity_hash_name), not by string
 * comparison, so plaintext strings like "kernel32.dll" or
 * "AddVectoredExceptionHandler" don't need to sit in the injected image.
 */
#ifndef KARITY_API_RESOLVE_H
#define KARITY_API_RESOLVE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* djb2-style hash, case-folded (A-Z/a-z treated identically) since Windows
 * module/export names are compared case-insensitively. Used both for plain
 * ASCII C strings (export names) and, via the internal wide-char variant,
 * for the UTF-16 module names stored in the PEB. Compute this once at
 * protect-time over the literal name you want and bake in only the hash. */
uint64_t karity_hash_name(const char *ascii_name);

/* Finds a loaded module by the hash of its file name (e.g. "kernel32.dll",
 * case-insensitive, extension included) by walking
 * PEB->Ldr->InMemoryOrderModuleList. Returns the module's base address, or
 * NULL if no loaded module's name hashes to `module_name_hash`. */
void *karity_resolve_module(uint64_t module_name_hash);

/* Finds an exported function by the hash of its name within the export
 * directory of `module_base` (as returned by karity_resolve_module).
 * Transparently follows forwarder exports (e.g. many kernel32 exports on
 * modern Windows forward straight to kernelbase.dll) up to a small fixed
 * depth. Returns the function's address, or NULL if not found. */
void *karity_resolve_proc(void *module_base, uint64_t proc_name_hash);

/* karity_resolve_module + karity_resolve_proc in one call. */
void *karity_resolve_api(uint64_t module_name_hash, uint64_t proc_name_hash);

#ifdef __cplusplus
}
#endif

#endif /* KARITY_API_RESOLVE_H */
