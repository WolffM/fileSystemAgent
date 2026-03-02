"""Tests for HtmlReportGenerator — HTML output structure and content."""

import pytest
from datetime import datetime, timedelta

from src.audit.models import (
    AnalyzerResult,
    CollectorResult,
    Finding,
    PipelineResult,
    ScanConfig,
    ScanResult,
    ScanStatus,
    ScanTarget,
    SeverityLevel,
)
from src.audit.reporting.html_report import HtmlReportGenerator


@pytest.fixture
def generator():
    return HtmlReportGenerator()


@pytest.fixture
def empty_result():
    """Pipeline result with no findings."""
    return PipelineResult(
        pipeline_name="test_pipeline",
        status=ScanStatus.COMPLETED,
        started_at=datetime(2026, 2, 18, 12, 0, 0),
        completed_at=datetime(2026, 2, 18, 12, 1, 30),
    )


@pytest.fixture
def full_result():
    """Pipeline result with findings across all stage types."""
    started = datetime(2026, 2, 18, 12, 0, 0)
    completed = datetime(2026, 2, 18, 12, 5, 0)

    return PipelineResult(
        pipeline_name="process_scan",
        status=ScanStatus.COMPLETED,
        started_at=started,
        completed_at=completed,
        collector_results=[
            CollectorResult(
                collector_name="process_snapshot",
                status=ScanStatus.COMPLETED,
                data={"processes": [], "count": 336},
                findings=[
                    Finding(
                        tool_name="process_snapshot",
                        severity=SeverityLevel.MEDIUM,
                        category="unsigned_process",
                        title="Unsigned process: suspicious.exe",
                        description="Process running without valid signature",
                        target="C:\\Temp\\suspicious.exe",
                    ),
                ],
                started_at=started,
                completed_at=started + timedelta(seconds=10),
                duration_seconds=10.0,
            ),
            CollectorResult(
                collector_name="service_auditor",
                status=ScanStatus.COMPLETED,
                data={"services": [], "count": 309},
                started_at=started + timedelta(seconds=10),
                completed_at=started + timedelta(seconds=15),
                duration_seconds=5.0,
            ),
            CollectorResult(
                collector_name="network_mapper",
                status=ScanStatus.COMPLETED,
                data={
                    "connections": [], "count": 143,
                    "listening": 45, "established": 47,
                },
                started_at=started + timedelta(seconds=15),
                completed_at=started + timedelta(seconds=20),
                duration_seconds=5.0,
            ),
            CollectorResult(
                collector_name="persistence_auditor",
                status=ScanStatus.COMPLETED,
                data={
                    "scheduled_tasks": [], "run_keys": [],
                    "task_count": 186, "run_key_count": 17, "errors": [],
                },
                started_at=started + timedelta(seconds=20),
                completed_at=started + timedelta(seconds=25),
                duration_seconds=5.0,
            ),
        ],
        scan_results=[
            ScanResult(
                tool_name="hollows_hunter",
                status=ScanStatus.SKIPPED,
                config=ScanConfig(
                    tool_name="hollows_hunter",
                    target=ScanTarget(target_type="system", target_value=""),
                ),
                error_message="Not installed",
            ),
        ],
        analyzer_results=[
            AnalyzerResult(
                analyzer_name="resource_analyzer",
                status=ScanStatus.COMPLETED,
                findings=[
                    Finding(
                        tool_name="resource_analyzer",
                        severity=SeverityLevel.HIGH,
                        category="system_writable_binary",
                        title="SYSTEM service with writable binary: EvilSvc",
                        description="Service running as SYSTEM with writable binary",
                        target="C:\\Temp\\evil.exe",
                        mitre_attack="T1574.010",
                    ),
                    Finding(
                        tool_name="resource_analyzer",
                        severity=SeverityLevel.LOW,
                        category="high_thread_count",
                        title="High thread count: leaky.exe",
                        description="500 threads",
                        target="leaky.exe",
                    ),
                ],
                started_at=started + timedelta(seconds=30),
                completed_at=started + timedelta(seconds=31),
                duration_seconds=1.0,
            ),
            AnalyzerResult(
                analyzer_name="baseline_differ",
                status=ScanStatus.COMPLETED,
                data={
                    "first_run": False,
                    "total_changes": 3,
                    "diff_summary": {
                        "processes": {"added": 1, "removed": 0},
                        "services": {"added": 1, "removed": 1},
                    },
                },
                findings=[
                    Finding(
                        tool_name="baseline_differ",
                        severity=SeverityLevel.MEDIUM,
                        category="new_service",
                        title="New service: EvilSvc",
                        description="New SYSTEM service detected",
                        target="C:\\Temp\\evil.exe",
                    ),
                ],
                started_at=started + timedelta(seconds=31),
                completed_at=started + timedelta(seconds=32),
                duration_seconds=1.0,
            ),
        ],
    )


class TestHtmlStructure:
    def test_generates_valid_html(self, generator, full_result):
        html = generator.generate(full_result)
        assert html.startswith("<!DOCTYPE html>")
        assert "<html lang=\"en\">" in html
        assert "</html>" in html
        assert "<head>" in html
        assert "</head>" in html
        assert "<body>" in html
        assert "</body>" in html

    def test_has_title(self, generator, full_result):
        html = generator.generate(full_result)
        assert "<title>System Health Report" in html
        assert "process_scan" in html

    def test_has_css(self, generator, full_result):
        html = generator.generate(full_result)
        assert "<style>" in html
        assert "</style>" in html

    def test_has_all_sections(self, generator, full_result):
        html = generator.generate(full_result)
        assert 'id="summary"' in html
        assert 'id="findings"' in html
        assert 'id="steps"' in html
        assert 'id="inventory"' in html
        assert 'id="baseline"' in html


class TestExecutiveSummary:
    def test_shows_status(self, generator, full_result):
        html = generator.generate(full_result)
        assert "COMPLETED" in html

    def test_shows_finding_count(self, generator, full_result):
        html = generator.generate(full_result)
        # 1 collector + 2 analyzer + 1 baseline = 4 total
        assert ">4<" in html  # total findings card value

    def test_shows_duration(self, generator, full_result):
        html = generator.generate(full_result)
        assert "300.0s" in html  # 5 minutes

    def test_severity_breakdown(self, generator, full_result):
        html = generator.generate(full_result)
        assert "CRITICAL" in html
        assert "HIGH" in html
        assert "MEDIUM" in html
        assert "LOW" in html
        assert "INFO" in html


class TestFindingsTable:
    def test_all_findings_present(self, generator, full_result):
        html = generator.generate(full_result)
        assert "suspicious.exe" in html
        assert "EvilSvc" in html
        assert "leaky.exe" in html

    def test_findings_sorted_by_severity(self, generator, full_result):
        html = generator.generate(full_result)
        # HIGH should appear before MEDIUM, which should appear before LOW
        high_pos = html.index("system_writable_binary")
        medium_pos = html.index("unsigned_process")
        low_pos = html.index("high_thread_count")
        assert high_pos < medium_pos < low_pos

    def test_mitre_attack_shown(self, generator, full_result):
        html = generator.generate(full_result)
        assert "T1574.010" in html

    def test_empty_findings(self, generator, empty_result):
        html = generator.generate(empty_result)
        assert "No findings" in html

    def test_severity_badges(self, generator, full_result):
        html = generator.generate(full_result)
        assert "severity-badge" in html


class TestPipelineSteps:
    def test_all_steps_listed(self, generator, full_result):
        html = generator.generate(full_result)
        assert "process_snapshot" in html
        assert "service_auditor" in html
        assert "network_mapper" in html
        assert "persistence_auditor" in html
        assert "hollows_hunter" in html
        assert "resource_analyzer" in html
        assert "baseline_differ" in html

    def test_step_types_shown(self, generator, full_result):
        html = generator.generate(full_result)
        assert "Collector" in html
        assert "Scanner" in html
        assert "Analyzer" in html

    def test_skipped_step_shown(self, generator, full_result):
        html = generator.generate(full_result)
        assert "skipped" in html
        assert "Not installed" in html


class TestInventorySummary:
    def test_process_count(self, generator, full_result):
        html = generator.generate(full_result)
        assert "336" in html
        assert "Processes" in html

    def test_service_count(self, generator, full_result):
        html = generator.generate(full_result)
        assert "309" in html
        assert "Services" in html

    def test_network_counts(self, generator, full_result):
        html = generator.generate(full_result)
        assert "143" in html
        assert "45L" in html
        assert "47E" in html

    def test_persistence_counts(self, generator, full_result):
        html = generator.generate(full_result)
        assert "186T" in html
        assert "17K" in html

    def test_no_inventory_without_data(self, generator, empty_result):
        html = generator.generate(empty_result)
        assert 'id="inventory"' not in html


class TestBaselineDiff:
    def test_diff_summary_shown(self, generator, full_result):
        html = generator.generate(full_result)
        assert "3 change(s) detected" in html

    def test_diff_categories(self, generator, full_result):
        html = generator.generate(full_result)
        assert "Processes" in html
        assert "Services" in html

    def test_added_removed_counts(self, generator, full_result):
        html = generator.generate(full_result)
        assert "+1" in html
        assert "-1" in html

    def test_first_run_message(self, generator, empty_result):
        empty_result.analyzer_results = [
            AnalyzerResult(
                analyzer_name="baseline_differ",
                status=ScanStatus.COMPLETED,
                data={"first_run": True},
            )
        ]
        html = generator.generate(empty_result)
        assert "First run" in html
        assert "saved as baseline" in html

    def test_no_changes_message(self, generator, empty_result):
        empty_result.analyzer_results = [
            AnalyzerResult(
                analyzer_name="baseline_differ",
                status=ScanStatus.COMPLETED,
                data={"first_run": False, "total_changes": 0, "diff_summary": {}},
            )
        ]
        html = generator.generate(empty_result)
        assert "No changes detected" in html

    def test_no_baseline_section_without_differ(self, generator, empty_result):
        html = generator.generate(empty_result)
        assert 'id="baseline"' not in html


class TestFileOutput:
    def test_write_to_file(self, generator, full_result, tmp_path):
        output_path = str(tmp_path / "report.html")
        html = generator.generate(full_result, output_path=output_path)

        from pathlib import Path
        report_file = Path(output_path)
        assert report_file.exists()
        assert report_file.read_text(encoding="utf-8") == html

    def test_creates_parent_dirs(self, generator, full_result, tmp_path):
        output_path = str(tmp_path / "sub" / "dir" / "report.html")
        generator.generate(full_result, output_path=output_path)

        from pathlib import Path
        assert Path(output_path).exists()

    def test_returns_html_without_file(self, generator, full_result):
        html = generator.generate(full_result)
        assert isinstance(html, str)
        assert len(html) > 0


class TestHtmlEscaping:
    def test_xss_in_title(self, generator, empty_result):
        empty_result.pipeline_name = '<script>alert("xss")</script>'
        html = generator.generate(empty_result)
        assert '<script>alert("xss")</script>' not in html
        assert "&lt;script&gt;" in html

    def test_xss_in_finding(self, generator, empty_result):
        empty_result.scan_results = [
            ScanResult(
                tool_name="test",
                status=ScanStatus.COMPLETED,
                config=ScanConfig(tool_name="test"),
                findings=[
                    Finding(
                        tool_name="test",
                        severity=SeverityLevel.LOW,
                        category="test",
                        title='<img src=x onerror="alert(1)">',
                        description="safe",
                        target="safe",
                    ),
                ],
            ),
        ]
        html = generator.generate(empty_result)
        assert '<img src=x onerror="alert(1)">' not in html
        assert "&lt;img" in html


class TestProcessScanPipelineFactory:
    def test_has_all_collectors(self):
        from src.audit.pipeline import ScanPipeline
        config = ScanPipeline.create_process_scan_pipeline()
        collector_names = [c.collector_name for c in config.collectors]
        assert "process_snapshot" in collector_names
        assert "service_auditor" in collector_names
        assert "network_mapper" in collector_names
        assert "persistence_auditor" in collector_names

    def test_has_hollows_hunter_scanner(self):
        from src.audit.pipeline import ScanPipeline
        config = ScanPipeline.create_process_scan_pipeline()
        scanner_names = [s.tool_name for s in config.steps]
        assert "hollows_hunter" in scanner_names

    def test_has_analyzers(self):
        from src.audit.pipeline import ScanPipeline
        config = ScanPipeline.create_process_scan_pipeline()
        analyzer_names = [a.analyzer_name for a in config.analyzers]
        assert "resource_analyzer" in analyzer_names
        assert "baseline_differ" in analyzer_names

    def test_pipeline_name(self):
        from src.audit.pipeline import ScanPipeline
        config = ScanPipeline.create_process_scan_pipeline()
        assert config.name == "process_scan"

    def test_custom_dirs(self):
        from src.audit.pipeline import ScanPipeline
        config = ScanPipeline.create_process_scan_pipeline(
            output_dir="./custom/scans",
            baseline_dir="./custom/baselines",
        )
        assert config.steps[0].output_dir == "./custom/scans"
        # baseline_dir is in analyzer extra_args
        baseline_analyzer = next(
            a for a in config.analyzers if a.analyzer_name == "baseline_differ"
        )
        assert baseline_analyzer.extra_args["baseline_dir"] == "./custom/baselines"

    def test_existing_factories_unchanged(self):
        """Regression: existing factory methods still work."""
        from src.audit.pipeline import ScanPipeline
        daily = ScanPipeline.create_daily_pipeline()
        assert daily.name == "daily_scan"
        assert len(daily.steps) == 6
        assert daily.collectors == []

        forensic = ScanPipeline.create_forensic_pipeline()
        assert forensic.name == "forensic_triage"
        assert len(forensic.steps) == 2
        assert forensic.collectors == []
