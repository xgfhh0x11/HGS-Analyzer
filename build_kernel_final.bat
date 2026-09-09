@echo off
setlocal enabledelayedexpansion
REM HGS Kernel Driver Final Build Script
REM
REM Toolchain locations are auto-detected:
REM   - Visual Studio is found via vswhere (any edition: Community /
REM     Professional / Enterprise / BuildTools).
REM   - The Windows SDK kernel-mode include/lib paths are derived from
REM     the WindowsSdkDir / WindowsSDKVersion variables that vcvars64
REM     exports, so no SDK version is hard-coded.

echo ========================================
echo    HGS Kernel Driver Final Build
echo ========================================
echo.

REM --- Locate Visual Studio via vswhere -----------------------------------
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" set "VSWHERE=%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo ERROR: vswhere.exe not found. Install Visual Studio 2019/2022
    echo        ^(any edition^) with the C++ build tools.
    pause
    exit /b 1
)

set "VSPATH="
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSPATH=%%i"
if not defined VSPATH (
    echo ERROR: No Visual Studio installation with the C++ x64 toolset was found.
    pause
    exit /b 1
)

REM --- Initialise the x64 build environment -------------------------------
call "%VSPATH%\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo ERROR: Failed to initialize Visual Studio environment
    pause
    exit /b 1
)
echo Visual Studio environment initialized: %VSPATH%

REM --- Derive the kernel-mode SDK paths from the SDK vcvars exported -------
if not defined WindowsSdkDir (
    echo ERROR: WindowsSdkDir not set by vcvars64 — is the Windows SDK installed?
    pause
    exit /b 1
)
if not defined WindowsSDKVersion (
    echo ERROR: WindowsSDKVersion not set by vcvars64 — is the Windows SDK installed?
    pause
    exit /b 1
)

set "SDK_KM_INC=%WindowsSdkDir%Include\%WindowsSDKVersion%km"
set "SDK_SHARED_INC=%WindowsSdkDir%Include\%WindowsSDKVersion%shared"
set "SDK_KM_LIB=%WindowsSdkDir%Lib\%WindowsSDKVersion%km\x64"

if not exist "%SDK_KM_INC%" (
    echo ERROR: Kernel-mode SDK headers not found at:
    echo        %SDK_KM_INC%
    echo        Install the WDK / "Windows Driver Kit" matching this SDK.
    pause
    exit /b 1
)
echo SDK version: %WindowsSDKVersion%
echo.

REM --- Create output directory --------------------------------------------
if not exist "bin\kernel" mkdir "bin\kernel"

REM Kernel driver source files (only kernel files)
set KERNEL_SOURCES=src\hgs_kernel_driver.c src\hgs_kernel_framework.c src\hgs_kernel_rpc_observer.c src\hgs_kernel_attestation_fuzzer.c src\hgs_kernel_key_protector_model.c src\hgs_kernel_vm_policy_sampler.c src\hgs_kernel_utils.c

echo Building HGS Kernel Driver (.sys)...
echo Sources: %KERNEL_SOURCES%
echo.

REM Compile kernel driver. The MSVC standard headers come from the INCLUDE
REM variable that vcvars64 set; only the kernel-mode SDK headers are added
REM explicitly via /I.
cl /nologo /c /kernel /GS- /GR- /Gz /W3 /WX- /Zc:wchar_t- /Zc:forScope- /Zc:inline- /Gm- /fp:precise /errorReport:prompt /Oi /Oy- /GL /Gy /D"WIN32" /D"_WINDOWS" /D"UNICODE" /D"_UNICODE" /D"DBG=1" /D"HGS_KERNEL_DEBUG=1" /I"include" /I"%SDK_KM_INC%" /I"%SDK_SHARED_INC%" %KERNEL_SOURCES%

if %ERRORLEVEL% neq 0 (
    echo.
    echo ========================================
    echo    Kernel Driver Compilation Failed!
    echo ========================================
    echo.
    echo Please check the error messages above.
    echo.
    pause
    exit /b 1
)

echo.
echo ========================================
echo    Kernel Driver Compiled Successfully!
echo ========================================
echo.

REM Create .sys file using linker
echo Linking kernel driver...
link /nologo /DRIVER /ENTRY:DriverEntry /SUBSYSTEM:NATIVE /MACHINE:X64 /OUT:bin\kernel\HgsManipulator.sys *.obj /LIBPATH:"%SDK_KM_LIB%" ntoskrnl.lib hal.lib wmilib.lib

if %ERRORLEVEL% neq 0 (
    echo.
    echo ========================================
    echo    Kernel Driver Linking Failed!
    echo ========================================
    echo.
    pause
    exit /b 1
)

echo.
echo ========================================
echo    Kernel Driver Build Complete!
echo ========================================
echo.
echo Driver: bin\kernel\HgsManipulator.sys
echo.
echo To install the driver (test-signing must be enabled on the lab host):
echo   sc create HgsManipulator type= kernel start= demand binPath= "C:\Windows\System32\drivers\HgsManipulator.sys"
echo   sc start HgsManipulator
echo.

endlocal
pause
