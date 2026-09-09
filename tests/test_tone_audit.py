"""Tone audit — automates the claim the README makes:

    "The codebase has been audited (src/ and include/) for legacy
     offensive-tone strings ('attack', 'bypass', 'exploit', 'inject',
     'hijack'); none remain."

Previously that claim was enforced by a one-off manual grep and could
regress unnoticed (BUILD_AND_VERIFY §3.1.9). This test makes it a CI
gate: any source/header that reintroduces one of the banned words as a
whole word fails the build.

Note 'hook' is deliberately NOT in the banned set: it is a legitimate
technical term for the RPC-observer modelling components and appears in
neutral, defensive contexts.
"""
import os
import re

import pytest

BANNED_WORDS = ["attack", "bypass", "exploit", "inject", "hijack"]
# Whole-word, case-insensitive. 'inject' as a whole word is banned but
# 'injector'/'injection' would also match the stem — none are present and
# none should be reintroduced.
_PATTERN = re.compile(r"\b(" + "|".join(BANNED_WORDS) + r")\b", re.IGNORECASE)

_AUDITED_DIRS = ["src", "include"]
_AUDITED_EXTS = {".c", ".h"}


def _audited_files(repo_root):
    for d in _AUDITED_DIRS:
        base = os.path.join(repo_root, d)
        for name in sorted(os.listdir(base)):
            if os.path.splitext(name)[1] in _AUDITED_EXTS:
                yield os.path.join(base, name)


def test_audited_dirs_exist(repo_root):
    for d in _AUDITED_DIRS:
        assert os.path.isdir(os.path.join(repo_root, d)), f"missing dir: {d}"


def test_no_offensive_tone_strings(repo_root):
    offenders = []
    for path in _audited_files(repo_root):
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for lineno, line in enumerate(fh, 1):
                m = _PATTERN.search(line)
                if m:
                    rel = os.path.relpath(path, repo_root)
                    offenders.append(f"{rel}:{lineno}: {m.group(0)!r} -> {line.strip()}")
    assert not offenders, (
        "Offensive-tone strings reintroduced (README claims none remain):\n"
        + "\n".join(offenders)
    )
