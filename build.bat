@echo off
REM HGS Attestation Path Analyzer — canonical user-mode build script.
REM Produces bin\hgs_manipulator.exe.
REM
REM Auto-detects (in priority order): cl (MSVC), gcc (MinGW), clang.
REM For MSVC, run from "x64 Native Tools Command Prompt for VS" so cl
REM and the Windows SDK link libs are already on PATH/LIB.

setlocal enabledelayedexpansion

echo ========================================
echo   HGS Attestation Path Analyzer — Build
echo ========================================
echo.

REM ── User-mode source set. Kernel sources (hgs_kernel_*.c) are built
REM ── separately via makefile.kernel and are deliberately NOT listed
REM ── here.
set SOURCES=src\main.c ^
            src\hgs_framework.c ^
            src\hgs_rpc_observer.c ^
            src\hgs_attestation_fuzzer.c ^
            src\hgs_key_protector_model.c ^
            src\hgs_vm_policy_sampler.c ^
            src\hgs_utils.c ^
            src\getopt_compat.c

REM ── Windows link libraries shared across all toolchains.
REM ── tbs.lib  : TPM Base Services (attestation modeller)
REM ── rpcrt4.lib : RPC runtime (rpc observer)
set MSVC_LIBS=kernel32.lib user32.lib advapi32.lib ole32.lib oleaut32.lib wbemuuid.lib crypt32.lib psapi.lib tbs.lib rpcrt4.lib
set GCC_LIBS=-lkernel32 -luser32 -ladvapi32 -lole32 -loleaut32 -lwbemuuid -lcrypt32 -lpsapi -ltbs -lrpcrt4

if not exist "bin" mkdir "bin"

where cl >nul 2>nul && (
    echo Using MSVC compiler.
    cl /nologo /W3 /O2 /I include /Fe:bin\hgs_manipulator.exe %SOURCES% /link %MSVC_LIBS%
    goto :result
)

where gcc >nul 2>nul && (
    echo Using GCC (MinGW^).
    gcc -Wall -Wextra -O2 -I include -o bin\hgs_manipulator.exe %SOURCES% %GCC_LIBS%
    goto :result
)

where clang >nul 2>nul && (
    echo Using Clang.
    clang -Wall -Wextra -O2 -I include -o bin\hgs_manipulator.exe %SOURCES% %GCC_LIBS%
    goto :result
)

echo ERROR: no supported compiler found ^(cl/gcc/clang^).
echo Install Visual Studio Build Tools, MinGW-w64, or LLVM-clang.
exit /b 1

:result
if %ERRORLEVEL% equ 0 (
    echo.
    echo ========================================
    echo   Build successful: bin\hgs_manipulator.exe
    echo ========================================
    echo.
    echo Smoke test:
    echo   bin\hgs_manipulator.exe --help
    echo   bin\hgs_manipulator.exe --list-vms
) else (
    echo.
    echo Build FAILED — see compiler output above.
    exit /b 1
)

endlocal
