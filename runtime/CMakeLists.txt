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
    integrity.c
    integrity_thunk.S
)

target_include_directories(karity_runtime_image PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

target_compile_options(karity_runtime_image PRIVATE
    $<$<COMPILE_LANGUAGE:C>:-ffreestanding -fno-builtin -fno-stack-protector -fno-asynchronous-unwind-tables -fno-ident -O2 -Wall -Wextra -Werror>
    $<$<COMPILE_LANGUAGE:ASM>:-fno-asynchronous-unwind-tables>
)

# The exact link args that turn the runtime translation units into the
# freestanding blob. Held in a variable because two consumers must agree on
# them byte-for-byte: this target_link_options (the build-time static blob) and
# the protect-time recompile pipeline (src/native/runtime_rewrite.cpp, which
# junk-rewrites the runtime .s and re-links it), which gets this same list
# embedded via GenerateSourceHeader.cmake below.
#   -Wl,-e,karity_vm_thunk           : custom entry (the blob has no CRT start).
#   -Wl,-u,karity_vm_native_call     : nothing here calls it (only the later
#                                      generated interpreter does), so pin it
#                                      against --gc-sections.
#   -Wl,-u,karity_*_install_thunk    : likewise reached only by the injector,
#                                      by offset -- pin all three. Each in turn
#                                      genuinely calls its karity_*_init, so
#                                      those (and the taint globals vm_thunk.S
#                                      references) need no -u of their own.
set(KARITY_RUNTIME_LINK_FLAGS
    -nostdlib
    -Wl,-e,karity_vm_thunk
    -Wl,-u,karity_vm_native_call
    -Wl,-u,karity_nanomite_install_thunk
    -Wl,-u,karity_anti_debug_install_thunk
    -Wl,-u,karity_integrity_install_thunk
    -Wl,--image-base=0x10000000
    -Wl,--file-alignment=16
    -Wl,--section-alignment=16
    -Wl,--gc-sections
)

target_link_options(karity_runtime_image PRIVATE ${KARITY_RUNTIME_LINK_FLAGS})
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
            -D "SYMBOLS=karity_vm_thunk:KARITY_RUNTIME_ENTRY_OFFSET;karity_vm_thunk_fpreg_offset:KARITY_RUNTIME_THUNK_FPREG_OFFSET;karity_vm_thunk_prolog_end:KARITY_RUNTIME_THUNK_PROLOG_END_OFFSET;karity_vm_thunk_end:KARITY_RUNTIME_THUNK_END_OFFSET;karity_interp_rel32:KARITY_RUNTIME_INTERP_REL32_OFFSET;karity_vm_native_call:KARITY_RUNTIME_NATIVE_CALL_OFFSET;karity_vm_native_call_prolog_end:KARITY_RUNTIME_NATIVE_CALL_PROLOG_END_OFFSET;karity_vm_native_call_end:KARITY_RUNTIME_NATIVE_CALL_END_OFFSET;karity_nanomite_install_thunk:KARITY_RUNTIME_NANOMITE_THUNK_OFFSET;karity_anti_debug_install_thunk:KARITY_RUNTIME_ANTIDEBUG_THUNK_OFFSET;karity_integrity_install_thunk:KARITY_RUNTIME_INTEGRITY_THUNK_OFFSET"
            -D "NM_EXECUTABLE=${KARITY_NM}"
            -D "OBJDUMP_EXECUTABLE=${KARITY_OBJDUMP}"
            -P "${CMAKE_SOURCE_DIR}/cmake/GenerateBlobHeader.cmake"
    DEPENDS "${KARITY_RUNTIME_BLOB_BIN}" karity_runtime_image
            "${CMAKE_SOURCE_DIR}/cmake/GenerateBlobHeader.cmake"
    COMMENT "karity: generating runtime_blob.h"
    VERBATIM
)

add_custom_target(karity_runtime_blob_header DEPENDS "${KARITY_RUNTIME_BLOB_HEADER}")

# --- embed the runtime sources for the protect-time obfuscation pipeline -----
# The ".c" TUs are pre-compiled to .s at build time (so protect time only has
# to assemble+link, never run the C frontend) and marked obfuscatable -- the
# host inserts junk .byte runs between their instructions before re-linking.
# The hand-written ".S" thunks are embedded verbatim and marked NOT
# obfuscatable: their prologue shape backs the injector's SEH unwind entries
# (src/inject/injector.cpp), so they must reassemble byte-for-byte.
set(KARITY_RUNTIME_C_TUS   api_resolve nanomite_veh anti_debug anti_vm anti_sandbox integrity)
set(KARITY_RUNTIME_ASM_TUS vm_thunk vm_call nanomite_thunk anti_debug_thunk integrity_thunk)

set(KARITY_RUNTIME_S_FLAGS
    -ffreestanding -fno-builtin -fno-stack-protector
    -fno-asynchronous-unwind-tables -fno-ident -O2
    -I "${CMAKE_SOURCE_DIR}/include")

set(KARITY_ASM_DIR "${KARITY_GENERATED_DIR}/runtime_asm")
set(KARITY_SOURCE_ENTRIES "")

foreach(tu IN LISTS KARITY_RUNTIME_C_TUS)
    set(_s "${KARITY_ASM_DIR}/${tu}.s")
    add_custom_command(
        OUTPUT "${_s}"
        COMMAND "${CMAKE_COMMAND}" -E make_directory "${KARITY_ASM_DIR}"
        COMMAND "${CMAKE_C_COMPILER}" -S ${KARITY_RUNTIME_S_FLAGS}
                "${CMAKE_CURRENT_SOURCE_DIR}/${tu}.c" -o "${_s}"
        DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/${tu}.c"
        COMMENT "karity: gcc -S ${tu}.c -> ${tu}.s"
        VERBATIM
    )
    list(APPEND KARITY_RUNTIME_S_OUTPUTS "${_s}")
    list(APPEND KARITY_SOURCE_ENTRIES "${tu}.s|1|${_s}")
endforeach()

foreach(tu IN LISTS KARITY_RUNTIME_ASM_TUS)
    # embedded verbatim (self-contained cpp #defines, no #include) -- protect
    # time writes it back as ".S" so gcc preprocesses+assembles it.
    list(APPEND KARITY_SOURCE_ENTRIES "${tu}.S|0|${CMAKE_CURRENT_SOURCE_DIR}/${tu}.S")
    list(APPEND KARITY_RUNTIME_ASM_FILES "${CMAKE_CURRENT_SOURCE_DIR}/${tu}.S")
endforeach()

set(KARITY_RUNTIME_SOURCES_HEADER "${KARITY_GENERATED_DIR}/runtime_sources.h")
add_custom_command(
    OUTPUT "${KARITY_RUNTIME_SOURCES_HEADER}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${KARITY_GENERATED_DIR}"
    COMMAND "${CMAKE_COMMAND}"
            -D "OUT_FILE=${KARITY_RUNTIME_SOURCES_HEADER}"
            -D "SOURCES=${KARITY_SOURCE_ENTRIES}"
            -D "LINK_FLAGS=${KARITY_RUNTIME_LINK_FLAGS}"
            -P "${CMAKE_SOURCE_DIR}/cmake/GenerateSourceHeader.cmake"
    DEPENDS ${KARITY_RUNTIME_S_OUTPUTS}
            ${KARITY_RUNTIME_ASM_FILES}
            "${CMAKE_SOURCE_DIR}/cmake/GenerateSourceHeader.cmake"
    COMMENT "karity: generating runtime_sources.h"
    VERBATIM
)
add_custom_target(karity_runtime_sources_header DEPENDS "${KARITY_RUNTIME_SOURCES_HEADER}")

add_library(karity_runtime_blob INTERFACE)
add_dependencies(karity_runtime_blob karity_runtime_blob_header karity_runtime_sources_header)
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

# Hosted build of the self-integrity checksum, used by tests/ -- same source
# as the freestanding blob, so the live-hash side can be checked against the
# host encoder's protect-time hash (they share include/karity/integrity.h).
add_library(karity_integrity_hosted STATIC integrity.c api_resolve.c)
target_include_directories(karity_integrity_hosted PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}
)
