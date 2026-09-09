"""Shared fixtures. Exposes the repository root so tests can locate
sources, headers, build scripts, and the built CLI binary without
depending on the working directory pytest was launched from."""
import os

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_HERE)


@pytest.fixture(scope="session")
def repo_root():
    return _REPO_ROOT
