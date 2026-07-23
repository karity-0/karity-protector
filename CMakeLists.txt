cmake_minimum_required(VERSION 3.20)
project(karity-protector LANGUAGES C CXX ASM)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 99)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "" FORCE)
endif()

option(KARITY_BUILD_TESTS "Build karity-protector unit/integration tests" ON)

# --- Zydis (vendored, disassembler used by the host lifter) -----------------
set(ZYDIS_BUILD_SHARED_LIB OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_MAN OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_DOXYGEN OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_TESTS OFF CACHE BOOL "" FORCE)
add_subdirectory(third_party/zydis)

# --- runtime (freestanding blob, embedded into protected binaries) ---------
add_subdirectory(runtime)

# --- host tool (C++20, PE lifter/injector) ----------------------------------
add_subdirectory(src)

if(KARITY_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
