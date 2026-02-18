"""Tests for the ScannerBase abstract class using a mock scanner."""

import asyncio
import sys
import pytest
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import patch

from src.security.models import (
    Finding,
    ScanConfig,
    ScanResult,
    ScanStatus,
    ScanTarget,
    SeverityLevel,
)
from src.security.scanner_base import ScannerBase
from src.security.tool_manager import ToolManager


class MockScanner(ScannerBase):
    """Concrete test scanner that returns a configurable finding."""

    @property
    def tool_name(self) -> str:
        return "mock_tool"

    def build_command(self, scan_config: ScanConfig, output_dir: Path) -> List[str]:
        return [sys.executable, "-c", "print('mock scan output')"]

    def parse_output(self, scan_result: ScanResult) -> List[Finding]:
        if "mock scan output" in scan_result.stdout:
            return [
                Finding(
                    tool_name="mock_tool",
                    severity=SeverityLevel.INFO,
                    category="test",
                    title="Mock finding",
                    description="Found during mock scan",
                    target="test_target",
                )
            ]
        return []


class ErrorScanner(ScannerBase):
    """Scanner that generates an error exit code."""

    @property
    def tool_name(self) -> str:
        return "mock_tool"

    def build_command(self, scan_config: ScanConfig, output_dir: Path) -> List[str]:
        return [sys.executable, "-c", "import sys; sys.exit(1)"]

    def parse_output(self, scan_result: ScanResult) -> List[Finding]:
        return []


class ParseErrorScanner(ScannerBase):
    """Scanner whose parse_output raises an exception."""

    @property
    def tool_name(self) -> str:
        return "mock_tool"

    def build_command(self, scan_config: ScanConfig, output_dir: Path) -> List[str]:
        return [sys.executable, "-c", "print('ok')"]

    def parse_output(self, scan_result: ScanResult) -> List[Finding]:
        raise ValueError("Intentional parse error")


class SlowScanner(ScannerBase):
    """Scanner that takes too long (for timeout testing)."""

    @property
    def tool_name(self) -> str:
        return "mock_tool"

    def build_command(self, scan_config: ScanConfig, output_dir: Path) -> List[str]:
        return [sys.executable, "-c", "import time; time.sleep(30)"]

    def parse_output(self, scan_result: ScanResult) -> List[Finding]:
        return []


class SuccessOnOneScanner(ScannerBase):
    """Scanner where return code 1 means 'findings found' (like ClamAV)."""

    @property
    def tool_name(self) -> str:
        return "mock_tool"

    def build_command(self, scan_config: ScanConfig, output_dir: Path) -> List[str]:
        return [sys.executable, "-c", "import sys; print('FOUND'); sys.exit(1)"]

    def parse_output(self, scan_result: ScanResult) -> List[Finding]:
        return [
            Finding(
                tool_name="mock_tool",
                severity=SeverityLevel.HIGH,
                category="test",
                title="Found something",
                description="desc",
                target="target",
            )
        ]

    def _is_success_return_code(self, return_code: Optional[int]) -> bool:
        return return_code == 1


def _make_tool_manager(tmp_path: Path) -> ToolManager:
    """Create a ToolManager with a mock_tool installed."""
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir(exist_ok=True)
    mock_dir = tools_dir / "mock_tool"
    mock_dir.mkdir(exist_ok=True)
    # Create a fake exe (won't actually be run — the scanner overrides the command)
    (mock_dir / "mock_tool.exe").write_text("fake")
    return ToolManager(tools_dir=str(tools_dir))


@pytest.fixture
def mock_tool_manager(tmp_path):
    """ToolManager with mock_tool registered and 'installed'."""
    tm = _make_tool_manager(tmp_path)
    # Register our mock tool
    from src.security.models import ToolInfo

    tm._tools["mock_tool"] = ToolInfo(
        name="mock_tool",
        display_name="Mock Tool",
        exe_name="mock_tool.exe",
    )
    # Make it "installed"
    mock_dir = tmp_path / "tools" / "mock_tool"
    mock_dir.mkdir(exist_ok=True)
    (mock_dir / "mock_tool.exe").write_text("fake")
    tm.check_tool("mock_tool")
    return tm


@pytest.fixture
def scan_config(tmp_path):
    return ScanConfig(
        tool_name="mock_tool",
        target=ScanTarget(target_type="path", target_value=str(tmp_path)),
        output_dir=str(tmp_path / "output"),
    )


class TestScannerBaseRun:
    @pytest.mark.asyncio
    async def test_successful_scan(self, mock_tool_manager, scan_config):
        scanner = MockScanner(mock_tool_manager)
        result = await scanner.run(scan_config)

        assert result.status == ScanStatus.COMPLETED
        assert result.return_code == 0
        assert "mock scan output" in result.stdout
        assert result.findings_count == 1
        assert result.findings[0].title == "Mock finding"
        assert result.started_at is not None
        assert result.completed_at is not None
        assert result.duration_seconds is not None
        assert result.duration_seconds >= 0

    @pytest.mark.asyncio
    async def test_tool_not_available(self, tmp_path, scan_config):
        # ToolManager with no tools installed
        tm = ToolManager(tools_dir=str(tmp_path / "empty_tools"))
        from src.security.models import ToolInfo

        tm._tools["mock_tool"] = ToolInfo(
            name="mock_tool", display_name="Mock", exe_name="mock_tool.exe"
        )
        scanner = MockScanner(tm)
        result = await scanner.run(scan_config)

        assert result.status == ScanStatus.SKIPPED
        assert "not installed" in result.error_message

    @pytest.mark.asyncio
    async def test_dry_run(self, mock_tool_manager, scan_config):
        scan_config.dry_run = True
        scanner = MockScanner(mock_tool_manager)
        result = await scanner.run(scan_config)

        assert result.status == ScanStatus.COMPLETED
        assert "[DRY RUN]" in result.stdout
        assert result.findings_count == 0

    @pytest.mark.asyncio
    async def test_nonzero_exit_code(self, mock_tool_manager, scan_config):
        scanner = ErrorScanner(mock_tool_manager)
        result = await scanner.run(scan_config)

        assert result.status == ScanStatus.FAILED
        assert result.return_code == 1
        assert "exited with code 1" in result.error_message

    @pytest.mark.asyncio
    async def test_parse_error_doesnt_crash(self, mock_tool_manager, scan_config):
        scanner = ParseErrorScanner(mock_tool_manager)
        result = await scanner.run(scan_config)

        # Should still complete — parse errors are caught
        assert result.status == ScanStatus.COMPLETED
        assert result.findings_count == 0

    @pytest.mark.asyncio
    async def test_timeout(self, mock_tool_manager, scan_config):
        scan_config.timeout = 1  # 1 second timeout
        scanner = SlowScanner(mock_tool_manager)
        result = await scanner.run(scan_config)

        assert result.status == ScanStatus.TIMED_OUT
        assert "timed out" in result.error_message

    @pytest.mark.asyncio
    async def test_custom_success_return_code(self, mock_tool_manager, scan_config):
        scanner = SuccessOnOneScanner(mock_tool_manager)
        result = await scanner.run(scan_config)

        assert result.status == ScanStatus.COMPLETED
        assert result.return_code == 1
        assert result.findings_count == 1


class TestScannerBaseHelpers:
    def test_is_available_true(self, mock_tool_manager):
        scanner = MockScanner(mock_tool_manager)
        assert scanner.is_available() is True

    def test_is_available_false(self, tmp_path):
        tm = ToolManager(tools_dir=str(tmp_path / "empty"))
        from src.security.models import ToolInfo

        tm._tools["mock_tool"] = ToolInfo(
            name="mock_tool", display_name="Mock", exe_name="mock_tool.exe"
        )
        scanner = MockScanner(tm)
        assert scanner.is_available() is False

    def test_create_output_dir(self, mock_tool_manager, scan_config):
        scanner = MockScanner(mock_tool_manager)
        output_dir = scanner._create_output_dir(scan_config)
        assert output_dir.exists()
        assert "mock_tool" in str(output_dir)
