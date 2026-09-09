<#
.SYNOPSIS
  Smoke-test the loaded HgsManipulator driver via its IOCTL surface. SAFETY-GATED.
.DESCRIPTION
  Runs INSIDE the guest after the driver is loaded. Opens \\.\HgsManipulator and
  issues each IOCTL twice: once with a correctly-sized buffer, once deliberately
  undersized to confirm the STATUS_BUFFER_TOO_SMALL guards added in the review fix.
  Dry-run unless -Arm (opening the device and issuing IOCTLs is what exercises
  kernel code paths, so it is gated).
#>
[CmdletBinding()]
param([switch]$Arm)

# CTL_CODE(FILE_DEVICE_UNKNOWN=0x22, func, METHOD_BUFFERED=0, FILE_ANY_ACCESS=0)
function Ctl([int]$func) { return (0x22 -shl 16) -bor ($func -shl 2) }
$ioctls = [ordered]@{
    IOCTL_HGS_START_ANALYSIS = Ctl 0x8001
    IOCTL_HGS_STOP_ANALYSIS  = Ctl 0x8002
    IOCTL_HGS_LIST_VMS       = Ctl 0x8003
    IOCTL_HGS_GET_STATUS     = Ctl 0x8004
    IOCTL_HGS_SAMPLE_DATA    = Ctl 0x8005
}

if (-not $Arm) {
    Write-Host "[smoke] DRY-RUN (no -Arm). Would open \\.\HgsManipulator and issue:" -ForegroundColor Yellow
    $ioctls.GetEnumerator() | ForEach-Object { Write-Host ("    {0} = 0x{1:X8}  (sized + undersized)" -f $_.Key, $_.Value) }
    Write-Host "[smoke] Undersized calls must return STATUS_BUFFER_TOO_SMALL (0xC0000023), not crash." -ForegroundColor Yellow
    Write-Host "[smoke] Re-run with -Arm inside the DISPOSABLE guest (driver loaded, verifier on)." -ForegroundColor Yellow
    return
}

$sig = @'
using System;
using System.Runtime.InteropServices;
public static class Dev {
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern IntPtr CreateFile(string n, uint acc, uint share, IntPtr sa, uint disp, uint flags, IntPtr tmpl);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool DeviceIoControl(IntPtr h, uint code, byte[] inb, uint inl, byte[] outb, uint outl, out uint ret, IntPtr ov);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool CloseHandle(IntPtr h);
}
'@
Add-Type -TypeDefinition $sig
$GENERIC_RW = 0xC0000000; $OPEN_EXISTING = 3
$h = [Dev]::CreateFile('\\.\HgsManipulator', $GENERIC_RW, 0, [IntPtr]::Zero, $OPEN_EXISTING, 0, [IntPtr]::Zero)
if ($h -eq [IntPtr](-1) -or $h -eq [IntPtr]::Zero) {
    Write-Error "CreateFile \\.\HgsManipulator failed (Win32 $([Runtime.InteropServices.Marshal]::GetLastWin32Error())). Is the driver loaded?"; exit 2
}
try {
    foreach ($e in $ioctls.GetEnumerator()) {
        foreach ($mode in @('sized','undersized')) {
            $inb  = New-Object byte[] ($(if ($mode -eq 'undersized') {1} else {256}))
            $outb = New-Object byte[] ($(if ($mode -eq 'undersized') {1} else {4096}))
            $ret = 0
            $ok = [Dev]::DeviceIoControl($h, [uint32]$e.Value, $inb, [uint32]$inb.Length, $outb, [uint32]$outb.Length, [ref]$ret, [IntPtr]::Zero)
            $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Host ("[smoke] {0,-26} {1,-11} ok={2} bytes={3} win32err={4}" -f $e.Key, $mode, $ok, $ret, $err)
        }
    }
} finally { [Dev]::CloseHandle($h) | Out-Null }
Write-Host "[smoke] done. Expect undersized -> failure (ERROR_INSUFFICIENT_BUFFER/122), no bugcheck."
