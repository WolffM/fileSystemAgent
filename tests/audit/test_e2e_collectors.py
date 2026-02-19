"""End-to-end tests that run native collectors on the local Windows machine.

These tests execute real PowerShell commands to collect system data.
They verify that collectors can run without crashing and produce valid output.

Run with: pytest tests/audit/test_e2e_collectors.py -v -m e2e
"""

import platform
import pytest

from src.audit.collectors.process_snapshot import ProcessSnapshotCollector
from src.audit.collectors.service_auditor import ServiceAuditorCollector
from src.audit.collectors.network_mapper import NetworkMapperCollector
from src.audit.collectors.persistence_auditor import PersistenceAuditorCollector
from src.audit.models import CollectorConfig, ScanStatus

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.skipif(
        platform.system() != "Windows",
        reason="Collectors require Windows PowerShell",
    ),
]


class TestProcessSnapshotE2E:
    @pytest.mark.asyncio
    async def test_collect_returns_processes(self):
        """Process snapshot runs and returns a non-empty process list."""
        collector = ProcessSnapshotCollector()
        config = CollectorConfig(collector_name="process_snapshot", timeout=30)
        context = {}

        result = await collector.collect(config, context)

        assert result.status == ScanStatus.COMPLETED
        assert result.error_message is None
        assert result.data["count"] > 0
        assert len(result.data["processes"]) > 0

    @pytest.mark.asyncio
    async def test_process_has_expected_fields(self):
        """Each process entry has pid, name, and ram_mb."""
        collector = ProcessSnapshotCollector()
        config = CollectorConfig(collector_name="process_snapshot", timeout=30)

        result = await collector.collect(config, {})

        assert result.status == ScanStatus.COMPLETED
        first_proc = result.data["processes"][0]
        assert "pid" in first_proc
        assert "name" in first_proc
        assert "ram_mb" in first_proc

    @pytest.mark.asyncio
    async def test_known_process_visible(self):
        """The current Python process should be visible in the snapshot."""
        collector = ProcessSnapshotCollector()
        config = CollectorConfig(collector_name="process_snapshot", timeout=30)

        result = await collector.collect(config, {})

        assert result.status == ScanStatus.COMPLETED
        names = [p["name"] for p in result.data["processes"]]
        assert any("python" in n.lower() for n in names)

    @pytest.mark.asyncio
    async def test_duration_tracked(self):
        """Collection records timing information."""
        collector = ProcessSnapshotCollector()
        config = CollectorConfig(collector_name="process_snapshot", timeout=30)

        result = await collector.collect(config, {})

        assert result.duration_seconds is not None
        assert result.duration_seconds > 0


class TestServiceAuditorE2E:
    @pytest.mark.asyncio
    async def test_collect_returns_services(self):
        """Service auditor runs and returns a non-empty service list."""
        collector = ServiceAuditorCollector()
        config = CollectorConfig(collector_name="service_auditor", timeout=30)

        result = await collector.collect(config, {})

        assert result.status == ScanStatus.COMPLETED
        assert result.data["count"] > 0
        assert len(result.data["services"]) > 0

    @pytest.mark.asyncio
    async def test_service_has_expected_fields(self):
        """Each service entry has name, state, and start_mode."""
        collector = ServiceAuditorCollector()
        config = CollectorConfig(collector_name="service_auditor", timeout=30)

        result = await collector.collect(config, {})

        assert result.status == ScanStatus.COMPLETED
        first_svc = result.data["services"][0]
        assert "name" in first_svc
        assert "state" in first_svc
        assert "start_mode" in first_svc

    @pytest.mark.asyncio
    async def test_known_service_visible(self):
        """Well-known Windows services should be present."""
        collector = ServiceAuditorCollector()
        config = CollectorConfig(collector_name="service_auditor", timeout=30)

        result = await collector.collect(config, {})

        assert result.status == ScanStatus.COMPLETED
        names = [s["name"] for s in result.data["services"]]
        # Spooler or wuauserv should exist on any Windows box
        assert any(n in names for n in ("Spooler", "wuauserv", "Winmgmt"))


class TestNetworkMapperE2E:
    @pytest.mark.asyncio
    async def test_collect_returns_connections(self):
        """Network mapper runs and returns connection data."""
        collector = NetworkMapperCollector()
        config = CollectorConfig(collector_name="network_mapper", timeout=30)

        result = await collector.collect(config, {})

        assert result.status == ScanStatus.COMPLETED
        assert result.data["count"] > 0
        assert len(result.data["connections"]) > 0

    @pytest.mark.asyncio
    async def test_connection_has_expected_fields(self):
        """Each connection entry has required fields."""
        collector = NetworkMapperCollector()
        config = CollectorConfig(collector_name="network_mapper", timeout=30)

        result = await collector.collect(config, {})

        assert result.status == ScanStatus.COMPLETED
        first_conn = result.data["connections"][0]
        assert "local_address" in first_conn
        assert "local_port" in first_conn
        assert "state" in first_conn
        assert "pid" in first_conn

    @pytest.mark.asyncio
    async def test_summary_counts(self):
        """Summary counts (listening, established) are populated."""
        collector = NetworkMapperCollector()
        config = CollectorConfig(collector_name="network_mapper", timeout=30)

        result = await collector.collect(config, {})

        assert result.status == ScanStatus.COMPLETED
        assert "listening" in result.data
        assert "established" in result.data
        # On any running system, at least some connections exist
        assert result.data["listening"] + result.data["established"] > 0

    @pytest.mark.asyncio
    async def test_state_is_string(self):
        """Connection states are resolved to strings, not raw integers."""
        collector = NetworkMapperCollector()
        config = CollectorConfig(collector_name="network_mapper", timeout=30)

        result = await collector.collect(config, {})

        assert result.status == ScanStatus.COMPLETED
        for conn in result.data["connections"]:
            assert isinstance(conn["state"], str)
            assert not conn["state"].isdigit()  # should not be raw number


class TestPersistenceAuditorE2E:
    @pytest.mark.asyncio
    async def test_collect_returns_data(self):
        """Persistence auditor runs and returns scheduled tasks and run keys."""
        collector = PersistenceAuditorCollector()
        config = CollectorConfig(collector_name="persistence_auditor", timeout=30)

        result = await collector.collect(config, {})

        assert result.status == ScanStatus.COMPLETED
        assert result.error_message is None
        assert result.data["task_count"] > 0
        assert result.data["run_key_count"] > 0

    @pytest.mark.asyncio
    async def test_scheduled_tasks_have_fields(self):
        """Scheduled task entries have expected fields."""
        collector = PersistenceAuditorCollector()
        config = CollectorConfig(collector_name="persistence_auditor", timeout=30)

        result = await collector.collect(config, {})

        assert result.status == ScanStatus.COMPLETED
        first_task = result.data["scheduled_tasks"][0]
        assert "task_name" in first_task
        assert "state" in first_task
        assert isinstance(first_task["state"], str)

    @pytest.mark.asyncio
    async def test_run_keys_have_fields(self):
        """Run key entries have expected fields."""
        collector = PersistenceAuditorCollector()
        config = CollectorConfig(collector_name="persistence_auditor", timeout=30)

        result = await collector.collect(config, {})

        assert result.status == ScanStatus.COMPLETED
        first_key = result.data["run_keys"][0]
        assert "registry_path" in first_key
        assert "name" in first_key
        assert "value" in first_key

    @pytest.mark.asyncio
    async def test_duration_tracked(self):
        """Collection records timing information."""
        collector = PersistenceAuditorCollector()
        config = CollectorConfig(collector_name="persistence_auditor", timeout=30)

        result = await collector.collect(config, {})

        assert result.duration_seconds is not None
        assert result.duration_seconds > 0
