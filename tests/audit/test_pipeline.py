"""Tests for ScanPipeline orchestration."""

import asyncio
import pytest
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.audit.analyzer_base import AnalyzerBase
from src.audit.collector_base import CollectorBase
from src.audit.models import (
    AnalyzerConfig,
    AnalyzerResult,
    CollectorConfig,
    CollectorResult,
    Finding,
    PipelineConfig,
    ScanConfig,
    ScanResult,
    ScanStatus,
    ScanTarget,
    SeverityLevel,
    ToolInfo,
)
from src.audit.pipeline import ScanPipeline
from src.audit.scanner_base import ScannerBase
from src.audit.tool_manager import ToolManager


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


class OrderTrackingCollector(CollectorBase):
    """Mock collector that records execution order."""

    def __init__(self, name: str, order_log: List[str]):
        super().__init__()
        self._name = name
        self._order_log = order_log

    @property
    def collector_name(self) -> str:
        return self._name

    async def collect(
        self, config: CollectorConfig, context: Dict[str, Any]
    ) -> CollectorResult:
        self._order_log.append(f"collector:{self._name}")
        return CollectorResult(
            collector_name=self._name,
            status=ScanStatus.COMPLETED,
            data={f"{self._name}_data": True},
            started_at=datetime.now(),
            completed_at=datetime.now(),
        )


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

    output_dir = tmp_path / "scan_output"
    output_dir.mkdir(exist_ok=True)

    pipeline = ScanPipeline(
        tool_manager=tm,
        config={"output_dir": str(output_dir)},
    )
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
        assert config.name == "daily_scan"
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

    def test_daily_pipeline_has_empty_collectors(self):
        config = ScanPipeline.create_daily_pipeline()
        assert config.collectors == []
        assert config.analyzers == []

    def test_forensic_pipeline_has_empty_collectors(self):
        config = ScanPipeline.create_forensic_pipeline()
        assert config.collectors == []
        assert config.analyzers == []


class TestPipelineStageOrdering:
    """Tests for the multi-stage pipeline execution order."""

    @pytest.mark.asyncio
    async def test_collectors_run_before_scanners(self, tmp_path):
        """Collectors execute before scanners in the pipeline."""
        order_log = []
        pipeline = _make_pipeline(tmp_path)

        # Wrap scanner to track order
        original_scanner = pipeline._scanners["mock_finds"]
        class OrderTrackingScanner(ScannerBase):
            @property
            def tool_name(self):
                return "mock_finds"
            def build_command(self, *args):
                return original_scanner.build_command(*args)
            def parse_output(self, *args):
                return original_scanner.parse_output(*args)
            async def run(self, config):
                order_log.append("scanner:mock_finds")
                return await original_scanner.run(config)

        pipeline._scanners["mock_finds"] = OrderTrackingScanner(pipeline.tool_manager)

        # Register a collector
        collector = OrderTrackingCollector("test_collector", order_log)
        pipeline._collectors["test_collector"] = collector

        config = PipelineConfig(
            name="order_test",
            collectors=[CollectorConfig(collector_name="test_collector")],
            steps=[ScanConfig(tool_name="mock_finds", output_dir=str(tmp_path / "out"))],
        )
        await pipeline.run_pipeline(config)

        assert order_log[0] == "collector:test_collector"
        assert order_log[1] == "scanner:mock_finds"

    @pytest.mark.asyncio
    async def test_collector_data_in_context(self, tmp_path):
        """Collector data is written to the pipeline context dict."""
        pipeline = _make_pipeline(tmp_path)

        # We'll verify by checking the collector result data
        class ContextCheckCollector(CollectorBase):
            @property
            def collector_name(self):
                return "ctx_collector"
            async def collect(self, config, context):
                return CollectorResult(
                    collector_name="ctx_collector",
                    status=ScanStatus.COMPLETED,
                    data={"key": "value", "count": 42},
                    started_at=datetime.now(),
                    completed_at=datetime.now(),
                )

        pipeline._collectors["ctx_collector"] = ContextCheckCollector()

        config = PipelineConfig(
            name="context_test",
            collectors=[CollectorConfig(collector_name="ctx_collector")],
        )
        result = await pipeline.run_pipeline(config)

        assert result.status == ScanStatus.COMPLETED
        assert len(result.collector_results) == 1
        assert result.collector_results[0].data["key"] == "value"

    @pytest.mark.asyncio
    async def test_unknown_collector_skipped(self, tmp_path):
        """Unknown collectors are skipped gracefully."""
        pipeline = _make_pipeline(tmp_path)

        config = PipelineConfig(
            name="skip_collector_test",
            collectors=[CollectorConfig(collector_name="nonexistent")],
        )
        result = await pipeline.run_pipeline(config)

        assert result.status == ScanStatus.COMPLETED
        assert len(result.collector_results) == 1
        assert result.collector_results[0].status == ScanStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_pipeline_persists_to_disk(self, tmp_path):
        """Pipeline results are saved to disk after completion."""
        pipeline = _make_pipeline(tmp_path)
        config = PipelineConfig(
            name="persist_test",
            steps=[ScanConfig(tool_name="mock_finds", output_dir=str(tmp_path / "out"))],
        )
        await pipeline.run_pipeline(config)

        # Check that a JSON file was written to the output dir
        output_dir = Path(pipeline.output_dir)
        json_files = list(output_dir.glob("*.json"))
        assert len(json_files) >= 1
        assert "persist_test" in json_files[0].name

    @pytest.mark.asyncio
    async def test_collector_findings_in_total(self, tmp_path):
        """Collector findings are included in PipelineResult.total_findings."""
        pipeline = _make_pipeline(tmp_path)

        class FindingCollector(CollectorBase):
            @property
            def collector_name(self):
                return "finding_collector"
            async def collect(self, config, context):
                return CollectorResult(
                    collector_name="finding_collector",
                    status=ScanStatus.COMPLETED,
                    findings=[
                        Finding(
                            tool_name="finding_collector",
                            severity=SeverityLevel.CRITICAL,
                            category="test",
                            title="Collector Finding",
                            description="Found by collector",
                            target="test",
                        )
                    ],
                    started_at=datetime.now(),
                    completed_at=datetime.now(),
                )

        pipeline._collectors["finding_collector"] = FindingCollector()

        config = PipelineConfig(
            name="collector_findings_test",
            collectors=[CollectorConfig(collector_name="finding_collector")],
            steps=[ScanConfig(tool_name="mock_finds", output_dir=str(tmp_path / "out"))],
        )
        result = await pipeline.run_pipeline(config)

        # 1 from collector + 1 from scanner = 2 total
        assert result.total_findings == 2
        assert result.critical_findings == 1  # from collector
        assert result.high_findings == 1  # from scanner


class TestPipelineAnalyzerDispatch:
    """Tests for analyzer stage dispatch in the pipeline."""

    @pytest.mark.asyncio
    async def test_analyzer_runs_after_collectors_and_scanners(self, tmp_path):
        """Analyzers execute after collectors and scanners."""
        order_log = []
        pipeline = _make_pipeline(tmp_path)

        # Collector that logs order
        collector = OrderTrackingCollector("order_collector", order_log)
        pipeline._collectors["order_collector"] = collector

        # Analyzer that logs order
        class OrderTrackingAnalyzer(AnalyzerBase):
            @property
            def analyzer_name(self):
                return "order_analyzer"
            async def analyze(self, config, context):
                order_log.append("analyzer:order_analyzer")
                return AnalyzerResult(
                    analyzer_name="order_analyzer",
                    status=ScanStatus.COMPLETED,
                    started_at=datetime.now(),
                    completed_at=datetime.now(),
                )

        pipeline._analyzers["order_analyzer"] = OrderTrackingAnalyzer()

        # Wrap scanner to track order
        original_scanner = pipeline._scanners["mock_finds"]
        class OrderScanner(ScannerBase):
            @property
            def tool_name(self):
                return "mock_finds"
            def build_command(self, *args):
                return original_scanner.build_command(*args)
            def parse_output(self, *args):
                return original_scanner.parse_output(*args)
            async def run(self, config):
                order_log.append("scanner:mock_finds")
                return await original_scanner.run(config)

        pipeline._scanners["mock_finds"] = OrderScanner(pipeline.tool_manager)

        config = PipelineConfig(
            name="order_test",
            collectors=[CollectorConfig(collector_name="order_collector")],
            steps=[ScanConfig(tool_name="mock_finds", output_dir=str(tmp_path / "out"))],
            analyzers=[AnalyzerConfig(analyzer_name="order_analyzer")],
        )
        await pipeline.run_pipeline(config)

        assert order_log[0] == "collector:order_collector"
        assert order_log[1] == "scanner:mock_finds"
        assert order_log[2] == "analyzer:order_analyzer"

    @pytest.mark.asyncio
    async def test_analyzer_receives_context(self, tmp_path):
        """Analyzers receive context populated by collectors."""
        pipeline = _make_pipeline(tmp_path)

        # Collector that writes data to context
        class DataCollector(CollectorBase):
            @property
            def collector_name(self):
                return "data_collector"
            async def collect(self, config, context):
                return CollectorResult(
                    collector_name="data_collector",
                    status=ScanStatus.COMPLETED,
                    data={"key": "from_collector"},
                    started_at=datetime.now(),
                    completed_at=datetime.now(),
                )

        pipeline._collectors["data_collector"] = DataCollector()

        # Analyzer that checks context
        received_context = {}
        class ContextCheckAnalyzer(AnalyzerBase):
            @property
            def analyzer_name(self):
                return "ctx_analyzer"
            async def analyze(self, config, context):
                received_context.update(context)
                return AnalyzerResult(
                    analyzer_name="ctx_analyzer",
                    status=ScanStatus.COMPLETED,
                    started_at=datetime.now(),
                    completed_at=datetime.now(),
                )

        pipeline._analyzers["ctx_analyzer"] = ContextCheckAnalyzer()

        config = PipelineConfig(
            name="ctx_test",
            collectors=[CollectorConfig(collector_name="data_collector")],
            analyzers=[AnalyzerConfig(analyzer_name="ctx_analyzer")],
        )
        await pipeline.run_pipeline(config)

        assert "data_collector" in received_context
        assert received_context["data_collector"]["key"] == "from_collector"

    @pytest.mark.asyncio
    async def test_unknown_analyzer_skipped(self, tmp_path):
        """Unknown analyzers are skipped gracefully."""
        pipeline = _make_pipeline(tmp_path)

        config = PipelineConfig(
            name="skip_analyzer_test",
            analyzers=[AnalyzerConfig(analyzer_name="nonexistent")],
        )
        result = await pipeline.run_pipeline(config)

        assert result.status == ScanStatus.COMPLETED
        assert len(result.analyzer_results) == 1
        assert result.analyzer_results[0].status == ScanStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_analyzer_findings_in_total(self, tmp_path):
        """Analyzer findings are included in PipelineResult.total_findings."""
        pipeline = _make_pipeline(tmp_path)

        class FindingAnalyzer(AnalyzerBase):
            @property
            def analyzer_name(self):
                return "finding_analyzer"
            async def analyze(self, config, context):
                return AnalyzerResult(
                    analyzer_name="finding_analyzer",
                    status=ScanStatus.COMPLETED,
                    findings=[
                        Finding(
                            tool_name="finding_analyzer",
                            severity=SeverityLevel.LOW,
                            category="test",
                            title="Analyzer Finding",
                            description="Found by analyzer",
                            target="test",
                        )
                    ],
                    started_at=datetime.now(),
                    completed_at=datetime.now(),
                )

        pipeline._analyzers["finding_analyzer"] = FindingAnalyzer()

        config = PipelineConfig(
            name="analyzer_findings_test",
            steps=[ScanConfig(tool_name="mock_finds", output_dir=str(tmp_path / "out"))],
            analyzers=[AnalyzerConfig(analyzer_name="finding_analyzer")],
        )
        result = await pipeline.run_pipeline(config)

        # 1 from scanner + 1 from analyzer = 2 total
        assert result.total_findings == 2
        assert result.high_findings == 1  # from scanner
        # Analyzer finding is LOW, not counted in high_findings

    @pytest.mark.asyncio
    async def test_analyzers_skipped_on_failure(self, tmp_path):
        """If stop_on_failure and a scanner fails, analyzers don't run."""
        pipeline = _make_pipeline(tmp_path)

        analyzer_ran = False
        class TrackAnalyzer(AnalyzerBase):
            @property
            def analyzer_name(self):
                return "track_analyzer"
            async def analyze(self, config, context):
                nonlocal analyzer_ran
                analyzer_ran = True
                return AnalyzerResult(
                    analyzer_name="track_analyzer",
                    status=ScanStatus.COMPLETED,
                    started_at=datetime.now(),
                    completed_at=datetime.now(),
                )

        pipeline._analyzers["track_analyzer"] = TrackAnalyzer()

        config = PipelineConfig(
            name="skip_on_failure",
            stop_on_failure=True,
            steps=[ScanConfig(tool_name="mock_fails", output_dir=str(tmp_path / "out"))],
            analyzers=[AnalyzerConfig(analyzer_name="track_analyzer")],
        )
        result = await pipeline.run_pipeline(config)

        assert result.status == ScanStatus.FAILED
        assert analyzer_ran is False
