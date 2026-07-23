# Two independent correctness checks:
#   - karity_test_vm_interp: pure interpreter logic (runtime/vm_interp.c),
#     hosted build, exercises every opcode via C.
#   - karity_test_vm_thunk: the native entry/exit trampoline (vm_thunk.S),
#     hosted build (not freestanding) so it can run as a normal process;
#     validates that all 16 GPRs + RFLAGS + RSP survive a virtualization
#     round trip untouched except where bytecode explicitly mutates them.

add_executable(karity_test_vm_interp test_vm_interp.c)
target_link_libraries(karity_test_vm_interp PRIVATE karity_vm_interp_hosted)
add_test(NAME vm_interp COMMAND karity_test_vm_interp)

add_executable(karity_test_vm_new_ops test_vm_new_ops.c)
target_link_libraries(karity_test_vm_new_ops PRIVATE karity_vm_interp_hosted)
add_test(NAME vm_new_ops COMMAND karity_test_vm_new_ops)

add_executable(karity_test_vm_branch test_vm_branch.c)
target_link_libraries(karity_test_vm_branch PRIVATE karity_vm_interp_hosted)
add_test(NAME vm_branch COMMAND karity_test_vm_branch)

# Executes the generated native junk/opaque-predicate bytes as real machine
# code (via VirtualAlloc'd RWX memory) and checks they're true no-ops.
add_executable(karity_test_native_junk
    test_native_junk_main.cpp
    test_native_junk_call.S
    ${CMAKE_SOURCE_DIR}/src/native/x86_junk.cpp
)
target_include_directories(karity_test_native_junk PRIVATE ${CMAKE_SOURCE_DIR}/src/native)
add_test(NAME native_junk COMMAND karity_test_native_junk)

# Exercises every x64_asm.h encoder by generating tiny snippets, executing
# them via VirtualAlloc'd RWX memory, and checking real register/memory
# state against expected results (x64_run_with_regs.S is a general-purpose
# "load these 15 GPRs, call code, save the 15 GPRs back" runner).
add_executable(karity_test_x64asm
    test_x64asm_main.cpp
    x64_run_with_regs.S
    ${CMAKE_SOURCE_DIR}/src/native/x64_asm.cpp
)
target_include_directories(karity_test_x64asm PRIVATE ${CMAKE_SOURCE_DIR}/src/native)
add_test(NAME x64_asm COMMAND karity_test_x64asm)

# Generates the interpreter (dispatch loop + every handler) 40 times with
# different seeds -- different handler order, dispatch order, and junk each
# time -- and runs every opcode through each build, checking real results.
add_executable(karity_test_interp_codegen
    test_interp_codegen_main.cpp
    ${CMAKE_SOURCE_DIR}/src/native/interp_codegen.cpp
    ${CMAKE_SOURCE_DIR}/src/native/x64_asm.cpp
    ${CMAKE_SOURCE_DIR}/src/native/x86_junk.cpp
    ${CMAKE_SOURCE_DIR}/src/vm/emitter.cpp
    ${CMAKE_SOURCE_DIR}/runtime/vm_call.S
)
target_include_directories(karity_test_interp_codegen PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/native
    ${CMAKE_SOURCE_DIR}/include
)
add_test(NAME interp_codegen COMMAND karity_test_interp_codegen)

# End-to-end lifter test: hand-assembled machine code containing a real
# backward Jcc loop, run through try_lift() (the actual CFG walker), then
# the resulting bytecode is executed for real via the reference interpreter
# and checked against the loop's arithmetic -- catches lift-time bugs
# (patch-position bookkeeping, edge resolution) that opcode-level tests,
# which only ever hand-write already-correct bytecode, can't reach.
add_executable(karity_test_lifter_branch
    test_lifter_branch.cpp
    ${CMAKE_SOURCE_DIR}/src/vm/lifter.cpp
    ${CMAKE_SOURCE_DIR}/src/vm/emitter.cpp
    ${CMAKE_SOURCE_DIR}/src/vm/obfuscate.cpp
)
target_include_directories(karity_test_lifter_branch PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/include
)
target_link_libraries(karity_test_lifter_branch PRIVATE karity_vm_interp_hosted Zydis)
add_test(NAME lifter_branch COMMAND karity_test_lifter_branch)

add_executable(karity_test_vm_thunk
    test_thunk_main.c
    test_thunk.S
    ${CMAKE_SOURCE_DIR}/runtime/vm_thunk.S
)
# vm_thunk.S references karity_anti_debug_taint directly (see runtime/
# anti_debug.c and its own comment in vm_thunk.S) -- link the hosted build
# so that symbol resolves; test_thunk_main.c also exercises it directly
# (test_thunk_taint) to validate the XOR-into-bytecode_key_seed wiring.
target_link_libraries(karity_test_vm_thunk PRIVATE karity_vm_interp_hosted karity_anti_debug_hosted)
add_test(NAME vm_thunk COMMAND karity_test_vm_thunk)

# Import-free WinAPI resolver (PEB walk + hand-parsed export directory),
# checked against real GetModuleHandle/GetProcAddress results.
add_executable(karity_test_api_resolve test_api_resolve.c)
target_link_libraries(karity_test_api_resolve PRIVATE karity_api_resolve_hosted)
add_test(NAME api_resolve COMMAND karity_test_api_resolve)

# End-to-end nanomite test: encodes real machine code into trap/ciphertext
# blocks, installs the real handler, and calls into it -- real CPU faults,
# real decryption, real resume, including a real conditional branch (Jcc)
# whose taken/fallthrough targets are discovered by scan_nanomite_region
# itself, not hand-assembled like the other cases.
add_executable(karity_test_nanomite
    test_nanomite.cpp
    ${CMAKE_SOURCE_DIR}/src/native/nanomite_encoder.cpp
    ${CMAKE_SOURCE_DIR}/src/native/nanomite_scan.cpp
)
target_include_directories(karity_test_nanomite PRIVATE ${CMAKE_SOURCE_DIR}/src/native)
target_link_libraries(karity_test_nanomite PRIVATE karity_nanomite_hosted Zydis)
add_test(NAME nanomite COMMAND karity_test_nanomite)

# Anti-debug checks (runtime/anti_debug.c): pokes the test process's own
# real PEB fields to confirm individual techniques actually move
# karity_anti_debug_scan()'s result -- see that file's header.
add_executable(karity_test_anti_debug test_anti_debug.c)
target_link_libraries(karity_test_anti_debug PRIVATE karity_anti_debug_hosted)
add_test(NAME anti_debug COMMAND karity_test_anti_debug)

# Reports (doesn't assert -- hypervisor presence isn't poke-able the way
# PEB fields are) what runtime/anti_vm.c sees on the machine running ctest.
add_executable(karity_test_anti_vm test_anti_vm.c)
target_link_libraries(karity_test_anti_vm PRIVATE karity_anti_debug_hosted)
add_test(NAME anti_vm COMMAND karity_test_anti_vm)
