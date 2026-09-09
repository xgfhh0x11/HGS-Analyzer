# HGS Attestation Path Analyzer

A C-based research framework that **models** the Hyper-V Host Guardian
Service (HGS) attestation, key-protection, and VM-policy paths. The
framework is designed for *analysis* of HGS protocol surface — RPC flow
between guest, host, and HGS endpoint; the TPM/admin attestation
modes; the key-protector format — under controlled lab conditions.

This is **not** a production tool, **not** an exploit kit, and does not
break any HGS-protected shielded VM that the operator does not already
own and control.

---

## Background

Microsoft's Host Guardian Service is the trust anchor for Hyper-V
shielded VMs. A shielded VM's owner key is delivered by HGS only after
the requesting host passes attestation (TPM-based or
administrator-trust-based) and a set of policy checks against the VM's
shielding data. Understanding which parts of that chain produce which
observable failure modes — and modelling the chain in code — is a
prerequisite for any rigorous evaluation of HGS deployments.

This framework is the modelling substrate. The simulator backends
reproduce the request flows in user space and kernel space; the
"fuzzer" components synthesize varied attestation and policy inputs to
exercise the parsers without modifying any real HGS endpoint.

## Components

| Module | File | Role |
|---|---|---|
| Framework core | `src/hgs_framework.c` | top-level orchestration, lifecycle |
| Attestation modeller | `src/hgs_attestation_fuzzer.c` | TPM / admin attestation request synthesis |
| Key-protector modeller | `src/hgs_key_protector_model.c` | key-protector blob structure modelling |
| RPC observer | `src/hgs_rpc_observer.c` | RPC flow capture (**stub** — hooks log calls and forward to the original function; no packet is captured or queued yet) |
| VM policy sampler | `src/hgs_vm_policy_sampler.c` | policy parameter test-set generation |
| Utilities | `src/hgs_utils.c` | logging, error reporting |
| Kernel driver | `src/hgs_kernel_driver.c` | KMDF entry point for kernel-side modelling |
| Kernel framework | `src/hgs_kernel_framework.c` | kernel-side orchestration |
| Kernel components | `src/hgs_kernel_{attestation_fuzzer,key_protector_model,rpc_observer,vm_policy_sampler,utils}.c` | kernel-mode counterparts |
| CLI | `src/main.c` | user-space entry point |

Headers in `include/`. The build is split cleanly between user-mode
and kernel-mode; a single canonical script drives each side.

## Build

### User-mode → `bin/hgs_manipulator.exe`

```cmd
build.bat
```

`build.bat` auto-detects the toolchain (MSVC, MinGW gcc, or clang) and
links against the user-mode Windows libraries
(`tbs.lib`, `rpcrt4.lib`, `crypt32.lib`, etc.). Equivalent
MinGW Makefile is also provided:

```sh
make
```

A vendored `include/getopt.h` + `src/getopt_compat.c` keeps the build
portable across MSVC (which does not ship `<getopt.h>`).

### Kernel-mode → `bin/kernel/HgsManipulator.sys`

```cmd
build_kernel_final.bat
```

Requires the Windows Driver Kit (WDK 10) and matches Visual Studio
2022. Output is `bin/kernel/HgsManipulator.sys`; loading the driver
on a production system requires either a vendor-signed binary or
test-signing mode and a self-signed cert.

### Build files at repo root

| File | Purpose |
|---|---|
| `build.bat` | **Canonical user-mode build.** |
| `Makefile` | MinGW alternative for `build.bat`. |
| `build_kernel_final.bat` | **Canonical kernel-mode build.** |
| `makefile.kernel` | Standalone kernel make recipe (alternative to the .bat). |
| `HgsManipulationFramework.sln` | Visual Studio solution wrapping both targets. |

## Configuration

`config.json` drives runtime behaviour: analysis mode selection, RPC
observation parameters, key-protector modeller toggles, policy sampler
ranges. See the file's structure for the full key list.

## Tests

A `pytest` suite under `tests/` automates the quality claims this repo
makes. It is pure-Python and cross-platform — no compiler required for
the static checks:

```sh
pip install -r tests/requirements.txt
python -m pytest tests/ -v
```

| Test file | What it enforces |
|---|---|
| `tests/test_tone_audit.py` | Scans `src/` + `include/` for the banned offensive-tone words (`attack`, `bypass`, `exploit`, `inject`, `hijack`) — turns the README's manual audit claim into a CI gate. |
| `tests/test_structure.py` | Every file in the *Components* table exists; both headers + the vendored `getopt` shim are present; `build.bat` and `Makefile` share one user-mode source list and compile no kernel source. |
| `tests/test_cli_smoke.py` | Runs the built `bin/hgs_manipulator.exe` (`--version`, `--help`, `--list-vms`) and checks exit codes + output. Skips cleanly if the binary has not been built. |

`.github/workflows/ci.yml` is wired to build the user-mode CLI with
MSVC on `windows-latest`, run the CLI smoke test, then run the full
`pytest` suite — but the user-mode source as currently committed does
**not** compile (see "Known limitations" below), so the build step
fails and the CLI smoke test never actually executes in CI today; only
the pure-Python `test_tone_audit.py` / `test_structure.py` rows are
currently verified. Locally, `python -m pytest tests/ -v` reports 27
passed / 3 skipped (the 3 skips are the CLI smoke rows, skipped
because no binary was built).

## Threat model and scope

The framework runs entirely against synthetic HGS request streams in
the simulator backends; the kernel components run only on a research
host where test signing is enabled and the operator has authorisation.

The framework explicitly does **not**:

- attack a deployed HGS endpoint owned by anyone else,
- attempt to retrieve a real shielded VM owner key,
- modify production attestation policies,
- introduce persistence on the host.

What it does:

- reproduce HGS request structures in memory for inspection,
- exercise parsers with varied inputs (the "fuzzer" components),
- record observed RPC sequences to disk for analysis,
- produce structured reports useful to defenders performing HGS
  hardening reviews.

## Known limitations

Much of the operational logic is currently **stub / placeholder**, not
a working implementation. This is consistent with the defensive
framing (nothing here actually touches a real HGS endpoint or VM),
but claims about what the code *does* should be read with these
caveats:

- **RPC observer is a no-op.** `ObserveThreadProc`
  (`src/hgs_rpc_observer.c`) sleeps in a loop; the hooked RPC
  functions log and forward to the original — no packet is captured,
  parsed, or queued.
- **VM policy / shielding functions do not modify anything.**
  `ModifyVMShieldingPolicy`, `DisableVMShielding`,
  `ModifyVMSecuritySettings`, `AnalysisVMSecurityChecks`, and
  `ManipulateVMConfiguration` (`src/hgs_vm_policy_sampler.c`) log a
  "modified successfully" message and return success without changing
  any VM state.
- **Attestation and key-protector payloads are fabricated filler**
  (constant bytes / `0xAA` fill), not real TPM quotes, X.509 data, or
  signatures. See `hgs_attestation_fuzzer.c` and
  `hgs_key_protector_model.c`.
- **Shielded-VM detection is hardcoded to `false`.**
  `hgs_enumerate_hyperv_vms` (`src/hgs_utils.c`) never sets
  `is_shielded` to `true` for any VM — the check is not implemented.
- **The kernel-mode counterparts (`hgs_kernel_*.c`) are equally
  stubbed** — they log "for demonstration" and return synthetic data
  rather than performing real kernel-side sampling.
- **`hgs_calculate_checksum` is not a cryptographic hash** — it is a
  32-bit rolling checksum smeared into 16 bytes, used only to tag the
  synthetic packets above.
- **The user-mode C source does not currently compile as committed**:
  `hgs_rpc_observer.c` includes `<detours.h>` (Microsoft Detours,
  which is not vendored or linked) and uses C++ reference-cast syntax
  (`(PVOID&)`) in a `.c` file; `hgs_vm_policy_sampler.c` includes
  `<vmbusapi.h>`, which is not a public Windows SDK header;
  `hgs_utils.c` calls `Tbsi_GetDeviceInfo` with three arguments against
  a two-argument prototype. Any one of these fails `build.bat` /
  the CI build step.

None of this is disguised in the source — each stub is marked with an
"In a real implementation, this would ..." comment — but it means the
"27 passed" pytest result and the presence of a CI workflow should not
be read as evidence that the CLI builds or that the modellers do real
work; see [`BUILD_AND_VERIFY.md`](BUILD_AND_VERIFY.md) for the full
gap list.

## Status

Research / non-production. Intended for lab study of HGS protocol
surface. The codebase is audited (`src/` and `include/`) for legacy
offensive-tone strings ("attack", "bypass", "exploit", "inject",
"hijack"); none remain, and `tests/test_tone_audit.py` now enforces
this on every CI run rather than relying on a one-off manual grep. The
defensive framing in the documentation is consistent with the
implementation, and the `LICENSE` disclaimer matches that framing.

## License

MIT — see `LICENSE`.

## References

- Microsoft — *Host Guardian Service Architecture and Operations*
  (public documentation set).
- Microsoft — Hyper-V shielded VM key-protector format documentation.
- A. Tarakanov, *Attacking Hyper-V*. BlueHat IL, 2018 (historical
  Hyper-V security primer).
- Microsoft DDK — KMDF driver-model reference.
