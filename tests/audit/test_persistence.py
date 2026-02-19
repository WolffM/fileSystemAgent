"""Tests for pipeline result persistence — save to disk and load back."""

import json
import time
import pytest
from datetime import datetime
from pathlib import Path

from src.audit.models import (
    Finding,
    PipelineResult,
    ScanConfig,
    ScanResult,
    ScanStatus,
    SeverityLevel,
)
from src.audit.pipeline import ScanPipeline


def _make_pipeline_result(name: str = "test_pipeline", num_findings: int = 0) -> PipelineResult:
    """Create a PipelineResult with optional findings for testing."""
    findings = [
        Finding(
            tool_name="test_tool",
            severity=SeverityLevel.HIGH,
            category="test",
            title=f"Test Finding {i}",
            description=f"Description {i}",
            target=f"target_{i}",
        )
        for i in range(num_findings)
    ]
    scan_result = ScanResult(
        tool_name="test_tool",
        config=ScanConfig(tool_name="test_tool"),
        status=ScanStatus.COMPLETED,
        findings=findings,
    )
    return PipelineResult(
        pipeline_name=name,
        status=ScanStatus.COMPLETED,
        started_at=datetime(2024, 1, 1, 12, 0, 0),
        completed_at=datetime(2024, 1, 1, 12, 5, 0),
        scan_results=[scan_result],
    )


class TestResultPersistence:
    def test_save_and_load_pipeline_result(self, tmp_path):
        """Save a result, load it back, compare key fields."""
        result = _make_pipeline_result("roundtrip_test", num_findings=3)
        sp = ScanPipeline.__new__(ScanPipeline)
        sp.output_dir = str(tmp_path)
        sp._results = []

        saved_path = sp._save_result(result)
        assert saved_path is not None
        assert saved_path.exists()

        loaded = ScanPipeline.load_results(str(tmp_path), limit=10)
        assert len(loaded) == 1

        loaded_result = loaded[0]
        assert loaded_result.pipeline_name == "roundtrip_test"
        assert loaded_result.status == ScanStatus.COMPLETED
        assert loaded_result.total_findings == 3
        assert len(loaded_result.scan_results) == 1
        assert loaded_result.scan_results[0].findings_count == 3

    def test_load_results_ordering(self, tmp_path):
        """Multiple saves should load in newest-first order."""
        sp = ScanPipeline.__new__(ScanPipeline)
        sp.output_dir = str(tmp_path)
        sp._results = []

        for i in range(3):
            result = _make_pipeline_result(f"pipeline_{i}")
            sp._save_result(result)
            time.sleep(0.05)  # ensure different mtimes

        loaded = ScanPipeline.load_results(str(tmp_path), limit=10)
        assert len(loaded) == 3
        # Newest first
        assert loaded[0].pipeline_name == "pipeline_2"
        assert loaded[2].pipeline_name == "pipeline_0"

    def test_load_results_limit(self, tmp_path):
        """Respects limit parameter."""
        sp = ScanPipeline.__new__(ScanPipeline)
        sp.output_dir = str(tmp_path)
        sp._results = []

        for i in range(5):
            sp._save_result(_make_pipeline_result(f"pipeline_{i}"))
            time.sleep(0.05)

        loaded = ScanPipeline.load_results(str(tmp_path), limit=2)
        assert len(loaded) == 2

    def test_load_empty_dir(self, tmp_path):
        """Returns empty list when no results exist."""
        loaded = ScanPipeline.load_results(str(tmp_path), limit=10)
        assert loaded == []

    def test_load_nonexistent_dir(self):
        """Returns empty list when directory doesn't exist."""
        loaded = ScanPipeline.load_results("/nonexistent/path", limit=10)
        assert loaded == []

    def test_save_creates_directory(self, tmp_path):
        """Output directory is created if missing."""
        nested_dir = tmp_path / "deep" / "nested" / "dir"
        sp = ScanPipeline.__new__(ScanPipeline)
        sp.output_dir = str(nested_dir)
        sp._results = []

        result = _make_pipeline_result("test")
        saved = sp._save_result(result)

        assert saved is not None
        assert nested_dir.is_dir()
        assert saved.exists()

    def test_saved_json_is_valid(self, tmp_path):
        """Saved file is valid JSON with expected structure."""
        sp = ScanPipeline.__new__(ScanPipeline)
        sp.output_dir = str(tmp_path)
        sp._results = []

        result = _make_pipeline_result("json_test", num_findings=2)
        saved = sp._save_result(result)

        data = json.loads(saved.read_text())
        assert data["pipeline_name"] == "json_test"
        assert data["status"] == "completed"
        assert len(data["scan_results"]) == 1
        assert len(data["scan_results"][0]["findings"]) == 2

    def test_get_recent_results_falls_back_to_disk(self, tmp_path):
        """get_recent_results loads from disk when in-memory results are empty."""
        sp = ScanPipeline.__new__(ScanPipeline)
        sp.output_dir = str(tmp_path)
        sp._results = []

        # Save directly to disk (bypassing in-memory)
        result = _make_pipeline_result("disk_fallback", num_findings=1)
        sp._save_result(result)

        # In-memory is empty, should load from disk
        recent = sp.get_recent_results(limit=10)
        assert len(recent) == 1
        assert recent[0].pipeline_name == "disk_fallback"

    def test_get_recent_results_prefers_memory(self, tmp_path):
        """get_recent_results uses in-memory results when available."""
        sp = ScanPipeline.__new__(ScanPipeline)
        sp.output_dir = str(tmp_path)

        memory_result = _make_pipeline_result("in_memory")
        sp._results = [memory_result]

        # Also save a different result to disk
        disk_result = _make_pipeline_result("on_disk")
        sp._save_result(disk_result)

        recent = sp.get_recent_results(limit=10)
        assert len(recent) == 1
        assert recent[0].pipeline_name == "in_memory"

    def test_corrupted_json_skipped(self, tmp_path):
        """Corrupted JSON files are skipped during load."""
        # Write valid result
        sp = ScanPipeline.__new__(ScanPipeline)
        sp.output_dir = str(tmp_path)
        sp._results = []
        sp._save_result(_make_pipeline_result("valid"))

        # Write corrupted file
        (tmp_path / "corrupted.json").write_text("{invalid json")

        loaded = ScanPipeline.load_results(str(tmp_path), limit=10)
        assert len(loaded) == 1
        assert loaded[0].pipeline_name == "valid"
