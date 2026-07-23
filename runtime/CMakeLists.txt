# The freestanding VM runtime: native entry/exit thunk + native-call
# passthrough, linked as a standalone flat image with no CRT and no base
# relocations, then objcopy'd to raw bytes and embedded as a C header for
# the host tool to inject into protected binaries. See vm_thunk.S for the
# ABI contract.
#
# The interpreter itself (dispatch loop + opcode handlers) is *not* part of
# this precompiled blob -- src/native/interp_codegen.h generates it fresh,
# per protect run, directly as machine code (junk/opaque-predicate-laden,
# handler order randomized). vm_thunk.S reaches it via a direct `call rel32`
# whose displacement (karity_interp_rel32) the injector patches with that
# generated code's address.

add_executable(karity_runtime_image
    vm_thunk.S
    vm_call.S
    api_resolve.c
    nanomite_veh.c
    nanomite_thunk.S
    anti_debug.c
    anti_vm.c
    anti_sandbox.c
    anti_debug_thunk.S
)

target_include_directories(karity_runtime_image PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

target_compile_options(karity_runtime_image PRIVATE
    $<$<COMPILE_LANGUAGE:C>:-ffreestanding -fno-builtin -fno-stack-protector -fno-asynchronous-unwind-tables -fno-ident -O2 -Wall -Wextra -Werror>
    $<$<COMPILE_LANGUAGE:ASM>:-fno-asynchronous-unwind-tables>
)

target_link_options(karity_runtime_image PRIVATE
    -nostdlib
    -Wl,-e,karity_vm_thunk
    -Wl,-u,karity_vm_native_call  # nothing in this link calls it (only the
                                  # generated interpreter, added later, does)
                                  # -- without this, --gc-sections below
                                  # would strip it as unreferenced.
    -Wl,-u,karity_nanomite_install_thunk # nothing in this link calls it
                                  # either (only the injector, at protect
                                  # time, jumps to it by offset) -- but it
                                  # in turn genuinely calls
                                  # karity_nanomite_install, so that symbol
                                  # doesn't need its own -u.
    -Wl,-u,karity_anti_debug_install_thunk # same reasoning as
                                  # karity_nanomite_install_thunk above --
                                  # only the injector calls this one, by
                                  # offset; it in turn genuinely calls
                                  # karity_anti_debug_init, so that (and the
                                  # karity_anti_debug_taint global
                                  # runtime/vm_thunk.S also references
                                  # directly) don't need their own -u.
    -Wl,--image-base=0x10000000
    -Wl,--file-alignment=16
    -Wl,--section-alignment=16
    -Wl,--gc-sections
)
set_target_properties(karity_runtime_image PROPERTIES LINKER_LANGUAGE C)

find_program(KARITY_OBJCOPY objcopy REQUIRED)
find_program(KARITY_NM nm REQUIRED)
find_program(KARITY_OBJDUMP objdump REQUIRED)

set(KARITY_RUNTIME_BLOB_BIN "${CMAKE_CURRENT_BINARY_DIR}/runtime_blob.bin")
set(KARITY_GENERATED_DIR "${CMAKE_BINARY_DIR}/generated")
set(KARITY_RUNTIME_BLOB_HEADER "${KARITY_GENERATED_DIR}/runtime_blob.h")

add_custom_command(
    OUTPUT "${KARITY_RUNTIME_BLOB_BIN}"
    COMMAND "${KARITY_OBJCOPY}" -O binary
            "$<TARGET_FILE:karity_runtime_image>"
            "${KARITY_RUNTIME_BLOB_BIN}"
    DEPENDS karity_runtime_image
    COMMENT "karity: flattening runtime image to raw blob"
    VERBATIM
)

add_custom_command(
    OUTPUT "${KARITY_RUNTIME_BLOB_HEADER}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${KARITY_GENERATED_DIR}"
    COMMAND "${CMAKE_COMMAND}"
            -D "EXE_FILE=$<TARGET_FILE:karity_runtime_image>"
            -D "BIN_FILE=${KARITY_RUNTIME_BLOB_BIN}"
            -D "OUT_FILE=${KARITY_RUNTIME_BLOB_HEADER}"
            -D "SYMBOLS=karity_vm_thunk:KARITY_RUNTIME_ENTRY_OFFSET;karity_vm_thunk_fpreg_offset:KARITY_RUNTIME_THUNK_FPREG_OFFSET;karity_vm_thunk_prolog_end:KARITY_RUNTIME_THUNK_PROLOG_END_OFFSET;karity_vm_thunk_end:KARITY_RUNTIME_THUNK_END_OFFSET;karity_interp_rel32:KARITY_RUNTIME_INTERP_REL32_OFFSET;karity_vm_native_call:KARITY_RUNTIME_NATIVE_CALL_OFFSET;karity_vm_native_call_prolog_end:KARITY_RUNTIME_NATIVE_CALL_PROLOG_END_OFFSET;karity_vm_native_call_end:KARITY_RUNTIME_NATIVE_CALL_END_OFFSET;karity_nanomite_install_thunk:KARITY_RUNTIME_NANOMITE_THUNK_OFFSET;karity_anti_debug_install_thunk:KARITY_RUNTIME_ANTIDEBUG_THUNK_OFFSET"
            -D "NM_EXECUTABLE=${KARITY_NM}"
            -D "OBJDUMP_EXECUTABLE=${KARITY_OBJDUMP}"
            -P "${CMAKE_SOURCE_DIR}/cmake/GenerateBlobHeader.cmake"
    DEPENDS "${KARITY_RUNTIME_BLOB_BIN}" karity_runtime_image
            "${CMAKE_SOURCE_DIR}/cmake/GenerateBlobHeader.cmake"
    COMMENT "karity: generating runtime_blob.h"
    VERBATIM
)

add_custom_target(karity_runtime_blob_header DEPENDS "${KARITY_RUNTIME_BLOB_HEADER}")

add_library(karity_runtime_blob INTERFACE)
add_dependencies(karity_runtime_blob karity_runtime_blob_header)
target_include_directories(karity_runtime_blob INTERFACE "${KARITY_GENERATED_DIR}")

# Hosted (normal, linkable, testable) build of the interpreter core, used by
# tests/ -- same source files as the freestanding blob, ordinary codegen.
add_library(karity_vm_interp_hosted STATIC vm_interp.c vm_call.S)
target_include_directories(karity_vm_interp_hosted PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Hosted build of the import-free API resolver, used by tests/ -- same
# source as the freestanding blob, ordinary codegen so it can be checked
# against real GetModuleHandle/GetProcAddress results.
add_library(karity_api_resolve_hosted STATIC api_resolve.c)
target_include_directories(karity_api_resolve_hosted PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Hosted build of the nanomite exception handler, used by tests/ -- same
# sources as the freestanding blob, so a real fault/decrypt/resume cycle can
# be exercised as an ordinary process.
add_library(karity_nanomite_hosted STATIC nanomite_veh.c api_resolve.c)
target_include_directories(karity_nanomite_hosted PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Hosted build of the anti-debug/anti-vm/anti-sandbox checks, used by
# tests/ -- same sources as the freestanding blob, so the individual
# techniques can be validated against the test process's own real
# (poke-able) PEB/heap state. anti_debug.c's karity_anti_debug_scan() calls
# straight into anti_vm.c/anti_sandbox.c (see that file's header), so all
# three are always built and linked together here, not as separate hosted
# libraries -- there's no scenario where a caller wants the combined scan
# without all three contributing to it.
add_library(karity_anti_debug_hosted STATIC anti_debug.c anti_vm.c anti_sandbox.c api_resolve.c)
target_include_directories(karity_anti_debug_hosted PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}
)
