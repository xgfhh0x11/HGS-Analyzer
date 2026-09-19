# HGS-Analyzer — dynamic kernel-test harness

Runbook for exercising the `HgsAnalyzer.sys` KMDF driver on a **disposable**
Hyper-V kdnet guest. Read the safety section before doing anything.

## Target / channel

- Guest: a throwaway Hyper-V VM (here: `WinKDbg`), kernel-debugged over the
  network with `kd.exe` / `kdnet.exe` from the host.
- Attach template (run on the host, key/port from the guest's
  `bcdedit /dbgsettings`):

  ```
  kd -k net:port=<PORT>,key=<KEY>
  ```

## Prerequisites

1. **Take a Hyper-V checkpoint first.** Loading a kernel driver can bugcheck
   the guest; reverting the checkpoint is the recovery path.
2. On the guest, enable test-signing and reboot (the driver is not WHQL-signed):

   ```
   bcdedit /set testsigning on
   shutdown /r /t 0
   ```

3. The driver must **build** first (see "Known build blockers" below).

## KNOWN BUILD BLOCKERS (from code review, must be fixed before testing)

The **user-mode** framework (`src/main.c`, `src/hgs_framework.c`, …) does not
compile as committed:

- `detours.h` is included but not vendored / not on the include path.
- a C++-style `(PVOID&)` reference cast appears in a `.c` file.
- `vmbusapi.h` is referenced but is not a public SDK header.
- `Tbsi_GetDeviceInfo` is called with the wrong arity.

The **kernel driver** (`driver/HgsAnalyzer.vcxproj`, KMDF) is a separate
build target and may compile independently; `build.ps1` builds the driver
target. Fix the user-mode blockers before relying on the user-mode client.

## Files

| File | Purpose |
|------|---------|
| `build.ps1` | Build `HgsAnalyzer.sys` (Release, x64) with the host WDK. Prints exact errors and exits non-zero on failure — never fakes success. |
| `load.ps1` | Deploy + `sc create` + `sc start` **inside the guest**. Dry-run by default; pass `-Arm` to actually act. |
| `unload.ps1` | `sc stop` + `sc delete`. |
| `kd-triage.txt` | `kd` command script: crash triage, Driver Verifier, pool checks. |
| `smoke-test.ps1` | Opens `\\.\HgsAnalyzer` and issues the 5 IOCTLs, including deliberately-undersized buffers to confirm the `STATUS_BUFFER_TOO_SMALL` guards. Dry-run unless `-Arm`. |

## Device / IOCTL surface

- User-mode device path: `\\.\HgsAnalyzer` (symlink `\DosDevices\HgsAnalyzer`).
- Service name used by the scripts: `HgsAnalyzer`.
- IOCTLs (all `METHOD_BUFFERED`, `FILE_DEVICE_UNKNOWN`, base `0x8000`):
  `IOCTL_HGS_START_ANALYSIS` (0x8001), `_STOP_ANALYSIS` (0x8002),
  `_LIST_VMS` (0x8003), `_GET_STATUS` (0x8004), `_SAMPLE_DATA` (0x8005).

## SAFETY

- **Always checkpoint the guest before loading.** Revert on any bugcheck.
- Enable **Driver Verifier** (`verifier /standard /driver HgsAnalyzer.sys`)
  on the guest before load — it turns latent pool/handle bugs into clean,
  attributable bugchecks the debugger can analyze, instead of silent corruption.
- Never load on a machine you care about. This is for the disposable guest only.
- The scripts touch the guest **only** when given `-Arm`; the default run is a
  dry-run that prints the exact commands it would execute.
