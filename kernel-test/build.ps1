<#
.SYNOPSIS
  Build the HgsManipulator.sys KMDF driver (Release, x64) with the host WDK.
.DESCRIPTION
  Locates msbuild, builds driver/HgsManipulator.vcxproj, and reports the
  resulting .sys path. On failure it prints the compiler errors verbatim and
  exits non-zero -- it never reports a build it did not produce.
  Runs on the HOST (where the WDK + msbuild live), not in the guest.
#>
[CmdletBinding()]
param(
    [ValidateSet('Release','Debug')] [string]$Configuration = 'Release',
    [string]$Platform = 'x64'
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$proj = Join-Path $repo 'driver\HgsManipulator.vcxproj'
if (-not (Test-Path $proj)) { Write-Error "Project not found: $proj"; exit 2 }

# Find msbuild via vswhere, then PATH.
$msbuild = $null
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (Test-Path $vswhere) {
    $vs = & $vswhere -latest -requires Microsoft.Component.MSBuild -find 'MSBuild\**\Bin\MSBuild.exe' 2>$null | Select-Object -First 1
    if ($vs) { $msbuild = $vs }
}
if (-not $msbuild) { $msbuild = (Get-Command msbuild.exe -ErrorAction SilentlyContinue).Source }
if (-not $msbuild) { Write-Error 'msbuild.exe not found (install VS + WDK build tools).'; exit 2 }

Write-Host "[build] msbuild: $msbuild"
Write-Host "[build] $proj ($Configuration|$Platform)"
$log = Join-Path $PSScriptRoot 'build.log'
& $msbuild $proj "/p:Configuration=$Configuration" "/p:Platform=$Platform" /nologo /v:minimal /fl "/flp:logfile=$log;verbosity=normal"
$code = $LASTEXITCODE
if ($code -ne 0) {
    Write-Host "[build] FAILED (exit $code). Errors:" -ForegroundColor Red
    if (Test-Path $log) { Select-String -Path $log -Pattern 'error|fatal' -SimpleMatch:$false | ForEach-Object { $_.Line } }
    Write-Host "[build] See $log and kernel-test\README.md 'KNOWN BUILD BLOCKERS'." -ForegroundColor Yellow
    exit $code
}
$sys = Get-ChildItem -Path $repo -Recurse -Filter 'HgsManipulator.sys' -ErrorAction SilentlyContinue |
       Where-Object { $_.FullName -match "\\$Platform\\" -or $_.FullName -match "\\$Configuration\\" } |
       Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $sys) { Write-Error 'Build reported success but HgsManipulator.sys was not found.'; exit 3 }
Write-Host "[build] OK: $($sys.FullName)" -ForegroundColor Green
Write-Output $sys.FullName
