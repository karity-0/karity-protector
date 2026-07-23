@echo off
REM build.cmd -- configure + build + test karity-protector.
REM
REM Why this exists instead of a plain `cmake -B build .`:
REM   - This repo's own path contains "#" (x:\# LOCAL\# karity\...), and
REM     CMake's default generator on this machine (Ninja) hard-refuses any
REM     path containing "#" in a custom command OUTPUT -- runtime/CMakeLists.txt
REM     needs that for generating runtime_blob.h, so Ninja can never finish
REM     configuring here. MinGW Makefiles has no such restriction.
REM   - The build directory is kept OUTSIDE the repo (X:\karity_build) for the
REM     same reason: it must not sit under a "#" path either.
REM   - The toolchain is pinned explicitly to the mingw64 GCC install below --
REM     CMake would otherwise happily pick up e.g. clang from elsewhere on
REM     PATH, which links with lld-link instead of GNU ld and chokes on the
REM     runtime's GNU-ld-specific link flags (--image-base, -u, --gc-sections).
REM
REM Edit MINGW_BIN below if your mingw64 toolchain lives somewhere else.

setlocal

set "SRC_DIR=%~dp0"
if "%SRC_DIR:~-1%"=="\" set "SRC_DIR=%SRC_DIR:~0,-1%"
set "BUILD_DIR=X:\karity_build"
set "MINGW_BIN=X:\msys64\mingw64\bin"

where cmake >nul 2>nul
if errorlevel 1 (
    echo [build.cmd] cmake not found in PATH.
    exit /b 1
)

if not exist "%MINGW_BIN%\gcc.exe" (
    echo [build.cmd] mingw64 gcc not found at "%MINGW_BIN%" -- edit MINGW_BIN in this script.
    exit /b 1
)

if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

echo [build.cmd] configuring in %BUILD_DIR% ...
cmake -S "%SRC_DIR%" -B "%BUILD_DIR%" -G "MinGW Makefiles" ^
    -DCMAKE_C_COMPILER="%MINGW_BIN%\gcc.exe" ^
    -DCMAKE_CXX_COMPILER="%MINGW_BIN%\g++.exe" ^
    -DCMAKE_ASM_COMPILER="%MINGW_BIN%\gcc.exe"
if errorlevel 1 (
    echo [build.cmd] configure failed.
    exit /b 1
)

echo [build.cmd] building ...
cmake --build "%BUILD_DIR%" -j4
if errorlevel 1 (
    echo [build.cmd] build failed.
    exit /b 1
)

echo.
echo [build.cmd] build succeeded:
echo   %BUILD_DIR%\src\karity-protector.exe
echo.

echo [build.cmd] running tests ...
pushd "%BUILD_DIR%"
ctest --output-on-failure
set "TEST_RESULT=%ERRORLEVEL%"
popd

endlocal & exit /b %TEST_RESULT%
