add_executable(karity-protector
    main.cpp
    pe/pe_image.cpp
    vm/emitter.cpp
    vm/lifter.cpp
    vm/obfuscate.cpp
    native/x86_junk.cpp
    native/x64_asm.cpp
    native/interp_codegen.cpp
    native/nanomite_encoder.cpp
    native/nanomite_scan.cpp
    native/seh_unwind.cpp
    inject/injector.cpp
)

target_include_directories(karity-protector PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(karity-protector PRIVATE
    Zydis
    karity_runtime_blob
)

target_compile_options(karity-protector PRIVATE -Wall -Wextra)
