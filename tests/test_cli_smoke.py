"""CLI smoke test — automates the BUILD_AND_VERIFY §2.2 acceptance
checks for --version and --help.

The build is platform-specific (MSVC / MinGW on Windows), so this test
does not build anything itself. It runs the binary if it has already
been produced (bin/hgs_manipulator.exe) and skips cleanly otherwise.
In CI the build step runs first, so this executes for real; locally it
skips unless you have run build.bat.
"""
import os
import subprocess

import pytest

_BIN_REL = os.path.join("bin", "hgs_manipulator.exe")
_VERSION_STRING = "HGS Manipulation Framework v1.0.0"


@pytest.fixture(scope="module")
def cli_binary(repo_root):
    path = os.path.join(repo_root, _BIN_REL)
    if not os.path.isfile(path):
        pytest.skip(f"{_BIN_REL} not built — run build.bat first (built in CI)")
    return path


def _run(binary, *args):
    return subprocess.run(
        [binary, *args],
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_version_exit_code_and_string(cli_binary):
    res = _run(cli_binary, "--version")
    assert res.returncode == 0, f"--version exited {res.returncode}"
    assert _VERSION_STRING in res.stdout, f"--version stdout missing version banner:\n{res.stdout}"


def test_help_exit_code_and_usage(cli_binary):
    res = _run(cli_binary, "--help")
    assert res.returncode == 0, f"--help exited {res.returncode}"
    assert "Usage:" in res.stdout, f"--help stdout missing usage block:\n{res.stdout}"
    # The documented option flags should all be advertised.
    for flag in ("--target-vm", "--mode", "--list-vms", "--version", "--help"):
        assert flag in res.stdout, f"--help does not advertise {flag}"


def test_list_vms_does_not_crash(cli_binary):
    """--list-vms must terminate cleanly whether or not shielded VMs are
    present (it prints the list or 'No VMs found...')."""
    res = _run(cli_binary, "--list-vms")
    assert res.returncode == 0, f"--list-vms exited {res.returncode}"
