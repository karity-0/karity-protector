#pragma once

#include <cstdint>
#include <random>
#include <string>
#include <vector>

namespace karity {

// Everything the injector needs to know about the runtime blob it appends: the
// raw bytes plus every symbol offset it patches/references. Historically these
// came from compile-time macros in the generated runtime_blob.h; factoring them
// into a struct lets the injector consume either the static blob
// (default_runtime_layout) or a freshly recompiled, junk-obfuscated one
// (build_obfuscated_runtime) with no other change. Offsets are relative to the
// flattened blob base (objcopy's lowest-VMA loadable section), same convention
// as GenerateBlobHeader.cmake.
struct RuntimeBlobLayout {
    std::vector<uint8_t> blob;
    uint32_t entry_offset;                    // karity_vm_thunk
    uint32_t thunk_fpreg_offset;              // karity_vm_thunk_fpreg_offset
    uint32_t thunk_prolog_end_offset;         // karity_vm_thunk_prolog_end
    uint32_t thunk_end_offset;                // karity_vm_thunk_end
    uint32_t interp_rel32_offset;             // karity_interp_rel32
    uint32_t native_call_offset;              // karity_vm_native_call
    uint32_t native_call_prolog_end_offset;   // karity_vm_native_call_prolog_end
    uint32_t native_call_end_offset;          // karity_vm_native_call_end
    uint32_t nanomite_thunk_offset;           // karity_nanomite_install_thunk
    uint32_t antidebug_thunk_offset;          // karity_anti_debug_install_thunk
    uint32_t integrity_thunk_offset;          // karity_integrity_install_thunk
};

// Resolved paths to the binutils/gcc programs the protect-time recompile needs.
struct ToolchainPaths {
    std::string gcc;
    std::string objcopy;
    std::string nm;
    std::string objdump;
};

// The default (obfuscation-off) layout: the statically embedded runtime_blob.h
// bytes and its compile-time offset macros. Byte-for-byte what the injector
// always used before --obf-runtime existed.
RuntimeBlobLayout default_runtime_layout();

// Locate gcc/objcopy/nm/objdump. Preference: `mingw_bin_override` (e.g. from
// --mingw-bin) > $KARITY_MINGW_BIN > bare names on PATH. Throws with an
// actionable message if gcc can't be invoked.
ToolchainPaths resolve_toolchain(const std::string &mingw_bin_override = "");

// The obfuscated path: writes the embedded runtime sources (runtime_sources.h)
// to a temp dir, junk-rewrites the obfuscatable (.c-derived) .s via
// obfuscate_asm(), re-links them with the recorded link flags into a fresh
// freestanding image, then re-derives the blob bytes (objcopy) and every symbol
// offset (nm/objdump) into a RuntimeBlobLayout. A different `rng` state yields a
// different blob every protect run. Throws (with the captured toolchain log) if
// any step fails -- never silently falls back, since the caller opted in.
RuntimeBlobLayout build_obfuscated_runtime(std::mt19937_64 &rng, const ToolchainPaths &tc, double density = 0.5);

} // namespace karity
