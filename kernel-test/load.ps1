<#
.SYNOPSIS
  Deploy and load HgsManipulator.sys as a kernel service. SAFETY-GATED.
.DESCRIPTION
  Meant to run INSIDE the disposable guest (deliver it via your kdnet/console
  channel). Without -Arm it is a DRY-RUN: it only prints the exact commands it
  would run. With -Arm it actually creates and starts the kernel service.
  Loading a kernel driver can bugcheck the machine -- checkpoint first.
.PARAMETER SysPath
  Path to HgsManipulator.sys on the guest.
.PARAMETER Arm
  Actually perform the load. Omit for a dry-run.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$SysPath,
    [string]$Service = 'HgsManipulator',
    [switch]$Arm
)
$ErrorActionPreference = 'Stop'
$steps = @(
    "sc.exe create $Service type= kernel start= demand binPath= `"$SysPath`"",
    "verifier /standard /driver HgsManipulator.sys   # enable BEFORE start; needs reboot to take effect",
    "sc.exe start $Service",
    "sc.exe query $Service"
)
if (-not $Arm) {
    Write-Host "[load] DRY-RUN (no -Arm). Would run, inside the guest:" -ForegroundColor Yellow
    $steps | ForEach-Object { Write-Host "    $_" }
    Write-Host "[load] Re-run with -Arm on the DISPOSABLE guest, after a checkpoint, to execute." -ForegroundColor Yellow
    return
}
if (-not (Test-Path $SysPath)) { Write-Error "SysPath not found on this machine: $SysPath"; exit 2 }
Write-Host "[load] ARMED. Creating service $Service ..." -ForegroundColor Red
& sc.exe create $Service type= kernel start= demand binPath= "$SysPath"
Write-Host "[load] Starting $Service ..."
& sc.exe start $Service
& sc.exe query $Service
