"""Tests for security scanning Pydantic models."""

import pytest
from datetime import datetime

from src.security.models import (
    Finding,
    PipelineConfig,
    PipelineResult,
    ScanConfig,
    ScanResult,
    ScanStatus,
    ScanTarget,
    SeverityLevel,
    ToolInfo,
)


class TestToolInfo:
    def test_minimal_creation(self):
        tool = ToolInfo(name="test", display_name="Test Tool", exe_name="test.exe")
        assert tool.name == "test"
        assert tool.installed is False
        assert tool.requires_admin is False
        assert tool.install_method == "github_release"

    def test_full_creation(self):
        tool = ToolInfo(
            name="hollows_hunter",
            display_name="HollowsHunter",
            exe_name="hollows_hunter.exe",
            version="0.4.1.1",
            github_repo="hasherezade/hollows_hunter",
            github_asset_pattern="hollows_hunter64.zip",
            requires_admin=True,
            license="BSD-2-Clause",
            expected_hash="abc123",
        )
        assert tool.github_repo == "hasherezade/hollows_hunter"
        assert tool.requires_admin is True

    def test_serialization_roundtrip(self):
        tool = ToolInfo(name="t", display_name="T", exe_name="t.exe")
        data = tool.model_dump()
        restored = ToolInfo(**data)
        assert restored.name == tool.name


class TestScanTarget:
    def test_defaults(self):
        target = ScanTarget()
        assert target.target_type == "path"
        assert target.target_value == ""
        assert target.recursive is True

    def test_process_target(self):
        target = ScanTarget(target_type="process", target_value="1234")
        assert target.target_type == "process"


class TestScanConfig:
    def test_defaults(self):
        cfg = ScanConfig(tool_name="clamav")
        assert cfg.timeout == 600
        assert cfg.dry_run is False
        assert cfg.extra_args == {}

    def test_custom(self):
        cfg = ScanConfig(
            tool_name="hayabusa",
            target=ScanTarget(target_type="eventlog", target_value="live"),
            timeout=300,
            extra_args={"min_level": "high"},
        )
        assert cfg.target.target_type == "eventlog"
        assert cfg.extra_args["min_level"] == "high"


class TestSeverityLevel:
    def test_ordering(self):
        levels = [SeverityLevel.CRITICAL, SeverityLevel.INFO, SeverityLevel.HIGH]
        assert SeverityLevel.CRITICAL in levels
        assert SeverityLevel.LOW not in levels

    def test_string_value(self):
        assert SeverityLevel.CRITICAL.value == "critical"
        assert str(SeverityLevel.HIGH) == "SeverityLevel.HIGH"


class TestFinding:
    def test_auto_id(self):
        f1 = Finding(
            tool_name="clamav",
            severity=SeverityLevel.HIGH,
            category="malware_signature",
            title="EICAR detected",
            description="EICAR test file found",
            target="/tmp/eicar.txt",
        )
        f2 = Finding(
            tool_name="clamav",
            severity=SeverityLevel.HIGH,
            category="malware_signature",
            title="EICAR detected",
            description="EICAR test file found",
            target="/tmp/eicar.txt",
        )
        assert f1.finding_id != f2.finding_id

    def test_with_mitre(self):
        f = Finding(
            tool_name="hollows_hunter",
            severity=SeverityLevel.CRITICAL,
            category="memory_anomaly",
            title="Process hollowing detected",
            description="PID 4567 has hollowed modules",
            target="4567",
            mitre_attack="T1055.012",
        )
        assert f.mitre_attack == "T1055.012"

    def test_timestamp_auto(self):
        f = Finding(
            tool_name="t",
            severity=SeverityLevel.INFO,
            category="test",
            title="t",
            description="t",
            target="t",
        )
        assert isinstance(f.timestamp, datetime)


class TestScanResult:
    def test_defaults(self):
        cfg = ScanConfig(tool_name="test")
        r = ScanResult(tool_name="test", config=cfg)
        assert r.status == ScanStatus.PENDING
        assert r.findings_count == 0
        assert r.has_critical is False

    def test_findings_count(self):
        cfg = ScanConfig(tool_name="test")
        r = ScanResult(
            tool_name="test",
            config=cfg,
            findings=[
                Finding(
                    tool_name="test",
                    severity=SeverityLevel.HIGH,
                    category="test",
                    title="t",
                    description="d",
                    target="x",
                ),
                Finding(
                    tool_name="test",
                    severity=SeverityLevel.CRITICAL,
                    category="test",
                    title="t",
                    description="d",
                    target="x",
                ),
            ],
        )
        assert r.findings_count == 2
        assert r.has_critical is True
        assert r.has_high is True

    def test_serialization(self):
        cfg = ScanConfig(tool_name="test")
        r = ScanResult(tool_name="test", config=cfg, status=ScanStatus.COMPLETED)
        data = r.model_dump()
        assert data["status"] == "completed"
        assert data["tool_name"] == "test"


class TestScanStatus:
    def test_all_values(self):
        expected = {"pending", "running", "completed", "failed", "timed_out", "skipped"}
        actual = {s.value for s in ScanStatus}
        assert actual == expected


class TestPipelineConfig:
    def test_defaults(self):
        pc = PipelineConfig()
        assert pc.name == "security_scan"
        assert pc.steps == []
        assert pc.stop_on_failure is False

    def test_with_steps(self):
        steps = [
            ScanConfig(tool_name="clamav"),
            ScanConfig(tool_name="yara_x"),
        ]
        pc = PipelineConfig(name="daily", steps=steps)
        assert len(pc.steps) == 2


class TestPipelineResult:
    def test_finding_aggregation(self):
        cfg = ScanConfig(tool_name="test")
        findings_a = [
            Finding(
                tool_name="a",
                severity=SeverityLevel.CRITICAL,
                category="t",
                title="t",
                description="d",
                target="x",
            ),
            Finding(
                tool_name="a",
                severity=SeverityLevel.HIGH,
                category="t",
                title="t",
                description="d",
                target="x",
            ),
        ]
        findings_b = [
            Finding(
                tool_name="b",
                severity=SeverityLevel.HIGH,
                category="t",
                title="t",
                description="d",
                target="x",
            ),
        ]
        pr = PipelineResult(
            pipeline_name="test",
            scan_results=[
                ScanResult(tool_name="a", config=cfg, findings=findings_a),
                ScanResult(tool_name="b", config=cfg, findings=findings_b),
            ],
        )
        assert pr.total_findings == 3
        assert pr.critical_findings == 1
        assert pr.high_findings == 2

    def test_duration(self):
        pr = PipelineResult(
            pipeline_name="test",
            started_at=datetime(2025, 1, 1, 0, 0, 0),
            completed_at=datetime(2025, 1, 1, 0, 5, 0),
        )
        assert pr.duration_seconds == 300.0

    def test_duration_none_when_incomplete(self):
        pr = PipelineResult(pipeline_name="test")
        assert pr.duration_seconds is None
