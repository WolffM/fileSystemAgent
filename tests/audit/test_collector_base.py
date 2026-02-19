"""Tests for CollectorBase — the abstract base class for native data collectors."""

import asyncio
import pytest
from datetime import datetime
from typing import Any, Dict, List

from src.audit.collector_base import CollectorBase
from src.audit.models import (
    CollectorConfig,
    CollectorResult,
    Finding,
    ScanStatus,
    SeverityLevel,
)


class MockCollector(CollectorBase):
    """A concrete collector for testing."""

    @property
    def collector_name(self) -> str:
        return "mock_collector"

    async def collect(
        self, config: CollectorConfig, context: Dict[str, Any]
    ) -> CollectorResult:
        return CollectorResult(
            collector_name=self.collector_name,
            status=ScanStatus.COMPLETED,
            data={"processes": [{"pid": 1, "name": "test"}]},
            findings=[
                Finding(
                    tool_name=self.collector_name,
                    severity=SeverityLevel.MEDIUM,
                    category="test",
                    title="Test Finding",
                    description="A test finding",
                    target="test_target",
                )
            ],
            started_at=datetime.now(),
            completed_at=datetime.now(),
        )


class SlowCollector(CollectorBase):
    """A collector that sleeps longer than the timeout."""

    @property
    def collector_name(self) -> str:
        return "slow_collector"

    async def collect(
        self, config: CollectorConfig, context: Dict[str, Any]
    ) -> CollectorResult:
        await asyncio.sleep(10)  # Will timeout
        return CollectorResult(
            collector_name=self.collector_name,
            status=ScanStatus.COMPLETED,
        )


class FailingCollector(CollectorBase):
    """A collector that raises an exception."""

    @property
    def collector_name(self) -> str:
        return "failing_collector"

    async def collect(
        self, config: CollectorConfig, context: Dict[str, Any]
    ) -> CollectorResult:
        raise RuntimeError("Collection failed")


class TestCollectorBaseRun:
    async def test_collect_returns_collector_result(self):
        """Mock collector returns correct type with expected data."""
        collector = MockCollector()
        config = CollectorConfig(collector_name="mock_collector")
        context = {}

        result = await collector.run(config, context)

        assert isinstance(result, CollectorResult)
        assert result.collector_name == "mock_collector"
        assert result.status == ScanStatus.COMPLETED
        assert result.data == {"processes": [{"pid": 1, "name": "test"}]}

    async def test_collect_with_findings(self):
        """Collector generates findings."""
        collector = MockCollector()
        config = CollectorConfig(collector_name="mock_collector")
        context = {}

        result = await collector.run(config, context)

        assert result.findings_count == 1
        assert result.findings[0].title == "Test Finding"
        assert result.findings[0].severity == SeverityLevel.MEDIUM

    async def test_collect_populates_context(self):
        """Successful collection writes data into shared context dict."""
        collector = MockCollector()
        config = CollectorConfig(collector_name="mock_collector")
        context = {}

        await collector.run(config, context)

        assert "mock_collector" in context
        assert context["mock_collector"]["processes"][0]["name"] == "test"

    async def test_collect_timeout(self):
        """Handles timeout gracefully."""
        collector = SlowCollector()
        config = CollectorConfig(collector_name="slow_collector", timeout=1)
        context = {}

        result = await collector.run(config, context)

        assert result.status == ScanStatus.TIMED_OUT
        assert "timed out" in result.error_message
        assert "slow_collector" not in context

    async def test_collect_failure(self):
        """Handles exceptions gracefully."""
        collector = FailingCollector()
        config = CollectorConfig(collector_name="failing_collector")
        context = {}

        result = await collector.run(config, context)

        assert result.status == ScanStatus.FAILED
        assert "Collection failed" in result.error_message
        assert "failing_collector" not in context

    async def test_duration_tracked(self):
        """Duration is computed after collection."""
        collector = MockCollector()
        config = CollectorConfig(collector_name="mock_collector")
        context = {}

        result = await collector.run(config, context)

        assert result.completed_at is not None
        assert result.duration_seconds is not None
        assert result.duration_seconds >= 0


class TestCollectorBaseHelpers:
    def test_is_admin_returns_bool(self):
        """Admin check returns a boolean without crashing."""
        collector = MockCollector()
        result = collector._is_admin()
        assert isinstance(result, bool)

    def test_is_admin_cached(self):
        """Admin check result is cached."""
        collector = MockCollector()
        first = collector._is_admin()
        second = collector._is_admin()
        assert first == second
        assert collector._admin_cached is not None

    async def test_run_powershell_simple(self):
        """PowerShell helper executes simple command."""
        collector = MockCollector()
        # Write-Output is the simplest PS command
        result = await collector._run_powershell("Write-Output 'hello'")
        assert "hello" in result

    async def test_run_powershell_error(self):
        """PowerShell helper raises on non-zero exit."""
        collector = MockCollector()
        with pytest.raises(RuntimeError, match="exited with code"):
            await collector._run_powershell("exit 1")
