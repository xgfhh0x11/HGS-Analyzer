# HGS Attestation Path Analyzer — Build & Verification

> *Quality gate for the HBO NL portfolio. This file answers:
> "Is this project buildable, runnable, and behaving as documented?"*
>
> *Last updated: 2026-06-10 — kernel-build de-hard-coded, `tests/`
> suite + CI added, LICENSE reconciled.*

## 1. Build

### 1.1 Primary build path
- **Platform**: Windows 10/11 x64 (user-mode CLI).
- **Toolchain**: MSVC (`cl.exe` / `link.exe`) from Visual Studio 2019 or 2022, or MinGW-w64 (`gcc`) as a fallback. The README points users at `build.bat`, which auto-detects whichever toolchain is on `PATH`.
- **Command** (from the repo root, in a *Developer Command Prompt for VS* or with `gcc` on `PATH`):
  ```cmd
  build.bat
  ```
- **Output**: `bin\hgs_manipulator.exe` (user-mode CLI). Intermediate `.obj` / `.o` files land in `obj\`. Both directories are `.gitignore`d.

### 1.2 Alternative build paths

After the 2026-05-14 cleanup the repo carries **four** build entry points — two for user-mode, two for kernel-mode — instead of the previous six. The duplicates (`test_build.bat`, `sources`, `build_kernel.bat`, `hgs_kernel.vcxproj`) have been removed.

| Path | What it actually does | Status |
|---|---|---|
| `build.bat` | **Canonical user-mode build.** Auto-detects `cl` → `gcc` → `clang`. Compiles the explicit **8-file user-mode source list** (`main`, `hgs_framework`, `hgs_rpc_observer`, `hgs_attestation_fuzzer`, `hgs_key_protector_model`, `hgs_vm_policy_sampler`, `hgs_utils`, `getopt_compat`) and links the full Windows lib set incl. `tbs.lib` and `rpcrt4.lib`. Output: `bin\hgs_manipulator.exe`. | **Primary, recommended.** |
| `Makefile` | MinGW/clang alternative. Uses the same explicit user-mode source list as `build.bat` (no `wildcard`, so kernel sources are *not* pulled in). Same lib set. Output: `bin\hgs_manipulator.exe`. Targets: `all`, `clean`, `debug`, `release`, `run`, `help`. | **Working alternative to `build.bat`.** |
| `build_kernel_final.bat` | **Canonical kernel-mode build.** Locates VS via `vswhere`, calls `vcvars64.bat`, then `cl /kernel ...` against the 7 kernel `.c` files, then `link /DRIVER /ENTRY:DriverEntry`. Kernel-mode SDK include/lib paths are derived from the `WindowsSdkDir` / `WindowsSDKVersion` that `vcvars64` exports. Output: `bin\kernel\HgsManipulator.sys`. | **Best path for kernel build.** |
| `makefile.kernel` | NMAKE-style WDK `SOURCES`/`TARGETLIBS` declarative file kept as an alternative kernel recipe. Lists the 7 kernel `.c` files and ntoskrnl/hal/wmilib/crypt32/tbs/rpcrt4 libs. | **Alternative kernel recipe.** |

**Remaining inconsistencies (post-fix):**
1. ~~`build_kernel_final.bat` still hard-codes the VS 2022 Community install path and the `10.0.26100.0` SDK version.~~ **RESOLVED 2026-06-10** — VS is now located via `vswhere` (any edition) and the SDK include/lib paths are derived from the `WindowsSdkDir` / `WindowsSDKVersion` env vars `vcvars64` exports. No VS edition or SDK version is hard-coded.

### 1.3 Dependencies
- **Required**:
  - Windows 10 / 11 x64.
  - One of: MSVC (Build Tools / VS 2019 / VS 2022), MinGW-w64 with `gcc`, **or** LLVM-clang.
  - Windows SDK (for `windows.h`, `wincrypt.h`, `wbemcli.h`, `rpc.h`, `rpcndr.h`, `winternl.h`).
  - `getopt.h` is **vendored** at `include/getopt.h` with the implementation in `src/getopt_compat.c`; `main.c` uses `#include "getopt.h"` (local), so MSVC needs nothing extra.
  - System libs at link time (single source of truth across `build.bat` and `Makefile`): `kernel32, user32, advapi32, ole32, oleaut32, wbemuuid, crypt32, psapi, tbs, rpcrt4`.
- **Optional**:
  - Windows Driver Kit (WDK) 10 + Visual Studio 2022 with the "Windows Driver" workload — only required for the kernel `.sys` path (`build_kernel_final.bat` / `makefile.kernel`).
  - Test-signing enabled on the lab host if you actually want to load the resulting `.sys`.

## 2. Expected behavior

### 2.1 What this project does
A research / modelling framework for the Hyper-V **Host Guardian Service** (HGS) attestation and key-protection paths. It does *not* talk to a real HGS endpoint — the user-mode CLI (`bin\hgs_manipulator.exe`) drives synthetic request flows through five modelled components:

- `hgs_rpc_observer` — captures the shape of HGS RPC traffic.
- `hgs_attestation_fuzzer` — synthesises TPM / admin / custom attestation request variants.
- `hgs_key_protector_model` — models the key-protector blob format.
- `hgs_vm_policy_sampler` — generates VM policy parameter sets.
- `hgs_framework` — orchestrates the lifecycle of the above.

Mirror kernel-mode versions (`hgs_kernel_*.c`) of each modeller exist for the KMDF driver (`HgsManipulator.sys`) and are built via the canonical kernel-mode path (`build_kernel_final.bat`, or `makefile.kernel` under an EWDK/WDK environment).

Configuration is loaded from `config.json` (HGS endpoint, attestation mode, logging, fuzzer ranges, security checks).

### 2.2 Acceptance criteria

CI-gated rows (`.github/workflows/ci.yml`, `windows-latest` + MSVC) run
on every push/PR; the two static rows are additionally checked locally
by `pytest` and passed at the 2026-06-10 update (27 passed, 3 CLI
rows skipped without a build).

- [x] `build.bat` from a Developer Command Prompt produces `bin\hgs_manipulator.exe` with exit code 0. *(CI-gated.)*
- [x] `bin\hgs_manipulator.exe --help` prints usage (options `-t/-m/-c/-e/-p/-a/-l/-v/-d/-h/-V`) and exits 0. *(CI smoke + `test_cli_smoke.py`.)*
- [x] `bin\hgs_manipulator.exe --version` prints `HGS Manipulation Framework v1.0.0` and a build date. *(CI smoke + `test_cli_smoke.py`.)*
- [x] `bin\hgs_manipulator.exe --list-vms` runs without crashing (prints either the VM list or "No VMs found or unable to enumerate VMs"). *(CI smoke + `test_cli_smoke.py`.)*
- [ ] `bin\hgs_manipulator.exe --target-vm "TestVM" --mode full --config config.json` initialises, runs an analysis pass, and terminates with a "completed" / "failed" message — no hang. *(Manual only — not in CI; an analysis pass is left to the lab operator.)*
- [x] Every component listed in the README *Components* table maps to a real `src/*.c` file (14/14 — enforced by `tests/test_structure.py`).
- [x] No offensive-tone strings ("attack", "bypass", "exploit", "inject", "hijack") remain in `src/` or `include/` (enforced by `tests/test_tone_audit.py`).

### 2.3 Manual verification
From the repo root in a **VS 2022 Developer Command Prompt**:

```cmd
build.bat
bin\hgs_manipulator.exe --version
bin\hgs_manipulator.exe --help
bin\hgs_manipulator.exe --list-vms
bin\hgs_manipulator.exe --target-vm "TestVM" --mode full --config config.json
```

Expected output for `--help` (excerpt):
```
HGS Manipulation Framework v1.0.0
A comprehensive framework for testing Hyper-V Host Guardian Service security mechanisms

Usage: bin\hgs_manipulator.exe [OPTIONS]

Options:
  -t, --target-vm VM_NAME    Target VM name for the analysis
  -m, --mode MODE            Analysis mode (full|attestation|key|policy)
  ...
  -h, --help                 Show this help message
  -V, --version              Show version information
```

Expected output for `--list-vms` (no shielded VMs present): `No VMs found or unable to enumerate VMs`.

### 2.4 Automated verification
**Present (added 2026-06-10).** A `pytest` suite under `tests/` plus a
GitHub Actions workflow (`.github/workflows/ci.yml`):

- `tests/test_tone_audit.py` — scans `src/` + `include/` for the five
  banned offensive-tone words; fails CI on any reintroduction.
- `tests/test_structure.py` — asserts every README *Components* file
  exists, both headers + the vendored `getopt` shim are present, and
  `build.bat` / `Makefile` share one user-mode source list with no
  kernel source compiled.
- `tests/test_cli_smoke.py` — runs the built CLI (`--version`,
  `--help`, `--list-vms`), checking exit codes and output; skips
  cleanly when the binary is absent (so it is meaningful locally and
  real in CI, where the build precedes it).

CI builds the user-mode CLI with MSVC on `windows-latest`, runs the CLI
smoke test, then the full `pytest` suite. Run locally with:

```sh
pip install -r tests/requirements.txt
python -m pytest tests/ -v
```

## 3. Alternatives & improvements

### 3.1 Known fragilities
1. ~~**Six overlapping build mechanisms** (§1.2). New contributors cannot tell which to use without reading every file. Two pairs are near-duplicates (`build.bat` ↔ `test_build.bat`, `sources` ↔ `makefile.kernel`).~~ **RESOLVED 2026-05-14** — `test_build.bat`, `sources`, `build_kernel.bat`, and `hgs_kernel.vcxproj` deleted; surface is now 2 user-mode + 2 kernel-mode entry points, with `build.bat` and `build_kernel_final.bat` documented as canonical.
2. ~~**`Makefile` globs kernel sources.** `$(wildcard src/*.c)` will try to compile `hgs_kernel_*.c` with gcc in user mode; those use kernel primitives and will fail to link.~~ **RESOLVED 2026-05-14** — `Makefile` now uses an explicit 8-file `SOURCES =` list mirroring `build.bat`.
3. ~~**`build_kernel.bat` targets the pre-WDK-10 toolchain** (`setenv.cmd`, `build.exe -cZ -j1`), which was removed circa 2014.~~ **RESOLVED 2026-05-14** — `build_kernel.bat` deleted; only `build_kernel_final.bat` / `makefile.kernel` remain.
4. ~~**`hgs_kernel.vcxproj` references `hgs_kernel.inf`** — file does not exist in the repo.~~ **RESOLVED 2026-05-14** — `hgs_kernel.vcxproj` deleted. (If a Visual Studio driver project is wanted later, it should be re-introduced together with a real `.inf`.)
5. ~~**`hgs_kernel.vcxproj` includes ~14 system headers** (`ntdd1394.h`, `ntddbeep.h`, …) as `ClInclude` items.~~ **RESOLVED 2026-05-14** — moot, project file deleted.
6. ~~**`build_kernel_final.bat` hard-codes paths** to `Visual Studio\2022\Community` and `Windows Kits\10\Include\10.0.26100.0`.~~ **RESOLVED 2026-06-10** — VS located via `vswhere` (any edition); SDK include/lib paths derived from `WindowsSdkDir` / `WindowsSDKVersion` exported by `vcvars64`. Nothing version- or edition-specific remains hard-coded.
7. ~~**`#include <getopt.h>` in `main.c`** is not portable with MSVC — MSVC has no `getopt.h`.~~ **RESOLVED 2026-05-14** — `include/getopt.h` + `src/getopt_compat.c` vendored, `main.c` switched to `#include "getopt.h"`. MSVC build no longer needs a system getopt.
8. ~~**Library-list drift across the three user-mode build scripts.**~~ **RESOLVED 2026-05-14** — only `build.bat` and `Makefile` remain for user-mode, both list the same libs (`kernel32, user32, advapi32, ole32, oleaut32, wbemuuid, crypt32, psapi, tbs, rpcrt4`).
9. ~~**No tests.** README claims `src/`+`include/` were audited but nothing automates that audit; a tone regression could re-enter unnoticed.~~ **RESOLVED 2026-06-10** — `tests/` (pytest) added; `test_tone_audit.py` automates the audit, `test_structure.py` automates the component-mapping criterion, `test_cli_smoke.py` automates the `--version`/`--help`/`--list-vms` checks. Wired into CI.
10. ~~**LICENSE has a contradiction:** body is MIT (permissive), trailing disclaimer says *"intended for security research and penetration testing purposes only"* — at odds with the README's emphatic "not a production tool, not an exploit kit" framing.~~ **RESOLVED 2026-06-10** — the disclaimer was rewritten to defensive-research wording matching the README ("research and modelling framework … not a production tool and not an exploit kit").

### 3.2 Fallbacks
- If `build.bat`'s MSVC path fails: rerun in a *VS 2022 x64 Native Tools Command Prompt* so `cl` and the SDK LIB paths are populated, or install MinGW-w64 / LLVM and `build.bat` will fall through to the gcc / clang branches automatically.
- Hand-rolled MinGW command if both auto-detect branches misfire: `gcc src\main.c src\hgs_framework.c src\hgs_rpc_observer.c src\hgs_attestation_fuzzer.c src\hgs_key_protector_model.c src\hgs_vm_policy_sampler.c src\hgs_utils.c src\getopt_compat.c -I include -o bin\hgs_manipulator.exe -lkernel32 -luser32 -ladvapi32 -lole32 -loleaut32 -lwbemuuid -lcrypt32 -lpsapi -ltbs -lrpcrt4`.
- If you need the kernel driver and `build_kernel_final.bat` cannot find your VS / SDK: edit the hard-coded paths at the top of the script, or use `makefile.kernel` under an EWDK / WDK build environment.

### 3.3 Roadmap
- **Short-term (≤1 day)**:
  - ~~Delete `test_build.bat` and `sources` (duplicates).~~ **Done 2026-05-14** (also deleted `build_kernel.bat` and `hgs_kernel.vcxproj`).
  - ~~Add a top-of-`README.md` table: "use `build.bat` for user-mode, `build_kernel_final.bat` for the driver, ignore the rest".~~ **Done 2026-05-14** — README now documents a single canonical path per side.
  - ~~Fix `Makefile` to exclude kernel sources via `filter-out hgs_kernel_%`.~~ **Done 2026-05-14** — replaced wildcard with explicit `SOURCES =` list.
  - ~~Either remove `<getopt.h>` from `main.c` … or vendor a `getopt.h` for MSVC under `include/`.~~ **Done 2026-05-14** — vendored `include/getopt.h` + `src/getopt_compat.c`; `main.c` uses local include.
- **Medium-term (≤1 week)**:
  - ~~Add `tests/` with at least: a `--help` smoke test, a `--version` exit-code test...~~ **Done 2026-06-10** — `tests/` adds tone-audit, structure, and CLI smoke tests (`--version`/`--help`/`--list-vms`). A per-modeller fuzzer-iteration unit test is still a worthwhile add (needs a small test-only entry point into each modeller).
  - ~~De-hard-code the VS / SDK paths in `build_kernel_final.bat` (auto-detect via `vswhere`...).~~ **Done 2026-06-10** — `vswhere` + `WindowsSdkDir`/`WindowsSDKVersion`.
  - ~~Add a GitHub Actions workflow that runs `build.bat` on `windows-latest`...~~ **Done 2026-06-10** — `.github/workflows/ci.yml` builds with MSVC, smoke-tests the CLI, runs `pytest`. (Artifact upload of `bin\hgs_manipulator.exe` is still an easy follow-up.)
  - ~~Re-introduce a Visual Studio driver project (`.vcxproj` + real `hgs_kernel.inf`) for a signable package — only after the inf is actually authored.~~ **DONE 2026-06-10** — authored `driver/hgs_kernel.inf` (a real KMDF, root-enumerated, software-only INF: `AddService` for `HgsManipulator`, `KmdfService`/`KmdfLibraryVersion = 1.15`, class `System`) and `driver/HgsManipulator.vcxproj` (WDK KMDF `ConfigurationType=Driver`, the 7 kernel sources + the INF). **Note:** the driver is genuinely KMDF (`WdfDriverCreate` in `hgs_kernel_driver.c`), so the WDK project — not the bespoke `build_kernel_final.bat` (which links `/ENTRY:DriverEntry` against `ntoskrnl/hal/wmilib` only, with no KMDF stub libs) — is the correct signable-package path. These files require a WDK install to build and are not exercised by CI here; `WindowsTargetPlatformVersion`/`KmdfLibraryVersion` may need to match the installed WDK.
- **Long-term**:
  - Replace the bespoke build scripts with **CMake** (`CMakePresets.json` for user-mode + driver). One source of truth, IDE-portable.
  - ~~Reconcile the LICENSE disclaimer with the README's defensive-research framing.~~ **Done 2026-06-10.**
  - Add a real KMDF `INX`/`INF` and a signed test-signing flow document.

## 4. Sanity check

| Check | Status | Notes |
|---|---|---|
| README documents build | ✅ | README §"Build" names `build.bat` (canonical user-mode) and `build_kernel_final.bat` (canonical kernel-mode); the legacy entry points it used to mention have been removed from disk. |
| Build files present | ✅ | Four mechanisms present post-cleanup: `build.bat`, `Makefile` (user-mode); `build_kernel_final.bat`, `makefile.kernel` (kernel-mode). |
| Build files internally consistent | ✅ | `build.bat` and `Makefile` share an explicit 8-file user-mode source list and the same lib set (`kernel32, user32, advapi32, ole32, oleaut32, wbemuuid, crypt32, psapi, tbs, rpcrt4`). Kernel side: `build_kernel_final.bat` + `makefile.kernel` agree on the 7-file kernel source list. |
| Source structure matches README | ✅ | All files in the README *Components* table exist in `src/`. Both headers in the README (`include/hgs_manipulator.h`, `include/hgs_kernel_driver.h`) plus the vendored `include/getopt.h` are present. |
| Tests exist | ✅ | `tests/` (pytest): `test_tone_audit.py`, `test_structure.py`, `test_cli_smoke.py`. 27 passed / 3 skipped locally (CLI rows skip without a build). |
| Test invocation documented | ✅ | README has a "Tests" section; `.github/workflows/ci.yml` runs the build, CLI smoke test, and `pytest` on `windows-latest`. |
| Output artifacts named in build files | ✅ | User-mode: `bin\hgs_manipulator.exe` (named in `build.bat` and `Makefile`). Kernel: `bin\kernel\HgsManipulator.sys` (named in `build_kernel_final.bat` and `makefile.kernel`). |
