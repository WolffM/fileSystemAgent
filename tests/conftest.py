"""Shared test fixtures for the fileSystemAgent test suite."""

import pytest
from pathlib import Path


@pytest.fixture
def tmp_tools_dir(tmp_path):
    """Temporary directory for tool binaries."""
    d = tmp_path / "tools"
    d.mkdir()
    return d


@pytest.fixture
def tmp_output_dir(tmp_path):
    """Temporary directory for scan output."""
    d = tmp_path / "output"
    d.mkdir()
    return d


@pytest.fixture
def fixtures_dir():
    """Path to the test fixtures directory."""
    return Path(__file__).parent / "security" / "fixtures"
