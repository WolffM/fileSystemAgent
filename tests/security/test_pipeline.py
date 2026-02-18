"""Tests for ScanPipeline orchestration."""

import pytest
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.security.models import (
    Finding,
    PipelineConfig,
    ScanConfig,
    ScanResult,
    ScanStatus,
    ScanTarget,
    SeverityLevel,
    ToolInfo,
)
from src.security.pipeline import ScanPipeline
from src.security.scanner_base import ScannerBase
from src.security.tool_manager import ToolManager


class AlwaysFindsScanner(ScannerBase):
    """Mock scanner that always produces a finding."""

    _tool = "mock_finds"

    @property
    def tool_name(self) -> str:
        return self._tool

    def build_command(self, scan_config, output_dir):
        import sys
        return [sys.executable, "-c", "print('found something')"]

    def parse_output(self, scan_result):
        return [
            Finding(
                tool_name=self._tool,
                severity=SeverityLevel.HIGH,
                category="test",
                title="Mock finding",
                description="desc",
                target="target",
            )
        ]


class AlwaysFailsScanner(ScannerBase):
    """Mock scanner that always fails."""

    _tool = "mock_fails"

    @property
    def tool_name(self) -> str:
        return self._tool

    def build_command(self, scan_config, output_dir):
        import sys
        return [sys.executable, "-c", "import sys; sys.exit(2)"]

    def parse_output(self, scan_result):
        return []


def _make_pipeline(tmp_path) -> ScanPipeline:
    """Create a ScanPipeline with mock scanners."""
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir(exist_ok=True)
    tm = ToolManager(tools_dir=str(tools_dir))

    # Register mock tools
    for name in ("mock_finds", "mock_fails"):
        tm._tools[name] = ToolInfo(
            name=name, display_name=name, exe_name=f"{name}.exe"
        )
        d = tools_dir / name
        d.mkdir(exist_ok=True)
        (d / f"{name}.exe").write_text("fake")

    pipeline = ScanPipeline(tool_manager=tm)
    pipeline._scanners["mock_finds"] = AlwaysFindsScanner(tm)
    pipeline._scanners["mock_fails"] = AlwaysFailsScanner(tm)
    return pipeline


class TestPipelineExecution:
    @pytest.mark.asyncio
    async def test_run_single_step(self, tmp_path):
        pipeline = _make_pipeline(tmp_path)
        config = PipelineConfig(
            name="test",
            steps=[
                ScanConfig(
                    tool_name="mock_finds",
                    output_dir=str(tmp_path / "output"),
                ),
            ],
        )
        result = await pipeline.run_pipeline(config)

        assert result.status == ScanStatus.COMPLETED
        assert len(result.scan_results) == 1
        assert result.total_findings == 1
        assert result.high_findings == 1
        assert result.started_at is not None
        assert result.completed_at is not None

    @pytest.mark.asyncio
    async def test_run_multi_step(self, tmp_path):
        pipeline = _make_pipeline(tmp_path)
        config = PipelineConfig(
            name="multi",
            steps=[
                ScanConfig(tool_name="mock_finds", output_dir=str(tmp_path / "out1")),
                ScanConfig(tool_name="mock_finds", output_dir=str(tmp_path / "out2")),
            ],
        )
        result = await pipeline.run_pipeline(config)

        assert result.status == ScanStatus.COMPLETED
        assert len(result.scan_results) == 2
        assert result.total_findings == 2

    @pytest.mark.asyncio
    async def test_stop_on_failure(self, tmp_path):
        pipeline = _make_pipeline(tmp_path)
        config = PipelineConfig(
            name="stop_test",
            stop_on_failure=True,
            steps=[
                ScanConfig(tool_name="mock_fails", output_dir=str(tmp_path / "out1")),
                ScanConfig(tool_name="mock_finds", output_dir=str(tmp_path / "out2")),
            ],
        )
        result = await pipeline.run_pipeline(config)

        assert result.status == ScanStatus.FAILED
        # Second step should never run
        assert len(result.scan_results) == 1

    @pytest.mark.asyncio
    async def test_continue_on_failure(self, tmp_path):
        pipeline = _make_pipeline(tmp_path)
        config = PipelineConfig(
            name="continue_test",
            stop_on_failure=False,
            steps=[
                ScanConfig(tool_name="mock_fails", output_dir=str(tmp_path / "out1")),
                ScanConfig(tool_name="mock_finds", output_dir=str(tmp_path / "out2")),
            ],
        )
        result = await pipeline.run_pipeline(config)

        assert result.status == ScanStatus.COMPLETED
        assert len(result.scan_results) == 2
        assert result.scan_results[0].status == ScanStatus.FAILED
        assert result.scan_results[1].status == ScanStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_unknown_scanner_skipped(self, tmp_path):
        pipeline = _make_pipeline(tmp_path)
        config = PipelineConfig(
            name="skip_test",
            steps=[
                ScanConfig(
                    tool_name="nonexistent_tool",
                    output_dir=str(tmp_path / "out"),
                ),
            ],
        )
        result = await pipeline.run_pipeline(config)

        assert result.status == ScanStatus.COMPLETED
        assert len(result.scan_results) == 1
        assert result.scan_results[0].status == ScanStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_results_stored(self, tmp_path):
        pipeline = _make_pipeline(tmp_path)
        config = PipelineConfig(
            name="stored",
            steps=[
                ScanConfig(tool_name="mock_finds", output_dir=str(tmp_path / "out")),
            ],
        )

        await pipeline.run_pipeline(config)
        await pipeline.run_pipeline(config)

        recent = pipeline.get_recent_results()
        assert len(recent) == 2

    @pytest.mark.asyncio
    async def test_get_all_findings(self, tmp_path):
        pipeline = _make_pipeline(tmp_path)
        config = PipelineConfig(
            name="findings",
            steps=[
                ScanConfig(tool_name="mock_finds", output_dir=str(tmp_path / "out1")),
                ScanConfig(tool_name="mock_finds", output_dir=str(tmp_path / "out2")),
            ],
        )
        await pipeline.run_pipeline(config)
        findings = pipeline.get_all_findings()
        assert len(findings) == 2


class TestPipelineFactories:
    def test_daily_pipeline(self):
        config = ScanPipeline.create_daily_pipeline()
        assert config.name == "daily_security_scan"
        assert len(config.steps) == 7
        tool_names = [s.tool_name for s in config.steps]
        assert "clamav" in tool_names
        assert "yara_x" in tool_names
        assert "hollows_hunter" in tool_names
        assert "hayabusa" in tool_names
        assert "autorunsc" in tool_names
        assert "sigcheck" in tool_names
        assert "listdlls" in tool_names

    def test_forensic_pipeline(self):
        config = ScanPipeline.create_forensic_pipeline()
        assert config.name == "forensic_triage"
        assert len(config.steps) == 2
        tool_names = [s.tool_name for s in config.steps]
        assert "chainsaw" in tool_names
        assert "hayabusa" in tool_names

    def test_custom_target(self):
        config = ScanPipeline.create_daily_pipeline(
            scan_target="D:\\Data",
            output_dir="./custom/output",
        )
        assert config.steps[0].target.target_value == "D:\\Data"
        assert config.steps[0].output_dir == "./custom/output"
