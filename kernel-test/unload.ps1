<#
.SYNOPSIS
  Stop and delete the HgsManipulator kernel service. Runs inside the guest.
#>
[CmdletBinding()]
param([string]$Service = 'HgsManipulator', [switch]$Arm)
$steps = @("sc.exe stop $Service", "sc.exe delete $Service")
if (-not $Arm) {
    Write-Host "[unload] DRY-RUN (no -Arm). Would run, inside the guest:" -ForegroundColor Yellow
    $steps | ForEach-Object { Write-Host "    $_" }
    return
}
& sc.exe stop $Service
& sc.exe delete $Service
Write-Host "[unload] done."
