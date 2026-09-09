"""Structure check — automates two acceptance criteria from
BUILD_AND_VERIFY §2.2 that were previously verified by hand:

  * "Every component listed in the README Components table maps to a
     real src/*.c file."
  * Both documented headers plus the vendored getopt shim are present.

It also enforces the BUILD_AND_VERIFY claim that the user-mode source
list is a single source of truth shared by build.bat and the Makefile.
"""
import os
import re

import pytest

# Every .c file the README Components table names (user-mode + kernel).
EXPECTED_SOURCES = [
    "main.c",
    "hgs_framework.c",
    "hgs_rpc_observer.c",
    "hgs_attestation_fuzzer.c",
    "hgs_key_protector_model.c",
    "hgs_vm_policy_sampler.c",
    "hgs_utils.c",
    "getopt_compat.c",
    "hgs_kernel_driver.c",
    "hgs_kernel_framework.c",
    "hgs_kernel_rpc_observer.c",
    "hgs_kernel_attestation_fuzzer.c",
    "hgs_kernel_key_protector_model.c",
    "hgs_kernel_vm_policy_sampler.c",
    "hgs_kernel_utils.c",
]

EXPECTED_HEADERS = [
    "hgs_manipulator.h",
    "hgs_kernel_driver.h",
    "getopt.h",
]

EXPECTED_BUILD_FILES = [
    "build.bat",
    "Makefile",
    "build_kernel_final.bat",
    "makefile.kernel",
    "HgsManipulationFramework.sln",
    "config.json",
]

# The 8 user-mode sources that must be shared between build.bat and Makefile.
USER_MODE_SOURCES = [
    "main.c",
    "hgs_framework.c",
    "hgs_rpc_observer.c",
    "hgs_attestation_fuzzer.c",
    "hgs_key_protector_model.c",
    "hgs_vm_policy_sampler.c",
    "hgs_utils.c",
    "getopt_compat.c",
]


@pytest.mark.parametrize("name", EXPECTED_SOURCES)
def test_source_present(repo_root, name):
    assert os.path.isfile(os.path.join(repo_root, "src", name)), f"missing src/{name}"


@pytest.mark.parametrize("name", EXPECTED_HEADERS)
def test_header_present(repo_root, name):
    assert os.path.isfile(os.path.join(repo_root, "include", name)), f"missing include/{name}"


@pytest.mark.parametrize("name", EXPECTED_BUILD_FILES)
def test_build_file_present(repo_root, name):
    assert os.path.isfile(os.path.join(repo_root, name)), f"missing {name}"


def _read(repo_root, name):
    with open(os.path.join(repo_root, name), "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def test_user_mode_source_list_is_consistent(repo_root):
    """build.bat and Makefile must reference the same 8 user-mode sources
    and must NOT pull in any kernel source (which would break a user-mode
    link)."""
    build_bat = _read(repo_root, "build.bat")
    makefile = _read(repo_root, "Makefile")
    for src in USER_MODE_SOURCES:
        assert src in build_bat, f"build.bat does not reference {src}"
        assert src in makefile, f"Makefile does not reference {src}"
    # Neither user-mode build script should *compile* a kernel source. A
    # source is compiled when referenced by its src/ path; a bare mention in
    # an explanatory comment (e.g. "kernel sources are built separately") is
    # fine, so match the path-prefixed form only.
    assert not re.search(r"src[\\/]hgs_kernel_", build_bat), "build.bat compiles a kernel source"
    assert not re.search(r"src[\\/]hgs_kernel_", makefile), "Makefile compiles a kernel source"
