"""Tests for ResourceAnalyzer — ranking, anomaly detection, and context consumption."""

import pytest
from datetime import datetime, timedelta, timezone

from src.audit.analyzers.resource_analyzer import ResourceAnalyzer, _STALE_HOURS
from src.audit.models import (
    AnalyzerConfig,
    FindingDomain,
    ProcessInfo,
    ScanStatus,
    ServiceInfo,
    SeverityLevel,
)


@pytest.fixture
def analyzer():
    return ResourceAnalyzer()


@pytest.fixture
def sample_processes():
    return [
        ProcessInfo(pid=0, name="System Idle Process", ram_mb=0),
        ProcessInfo(pid=4, name="System", ram_mb=1, thread_count=200),
        ProcessInfo(
            pid=100, name="chrome.exe",
            path="C:\\Program Files\\Chrome\\chrome.exe",
            ram_mb=500, thread_count=30, handle_count=800,
        ),
        ProcessInfo(
            pid=200, name="bigtool.exe",
            path="C:\\Program Files\\Big\\bigtool.exe",
            ram_mb=2048, thread_count=250, handle_count=6000,
        ),
        ProcessInfo(
            pid=300, name="notepad.exe",
            path="C:\\Windows\\System32\\notepad.exe",
            ram_mb=10, thread_count=4, handle_count=80,
        ),
        ProcessInfo(
            pid=400, name="leaky.exe",
            path="C:\\Temp\\leaky.exe",
            ram_mb=100, thread_count=500, handle_count=10000,
        ),
    ]


@pytest.fixture
def sample_services():
    return [
        ServiceInfo(
            name="SafeSvc", display_name="Safe Service",
            state="Running", start_mode="Auto",
            binary_path="C:\\Program Files\\Safe\\safe.exe",
            account="LocalSystem",
        ),
        ServiceInfo(
            name="WritableSvc", display_name="Writable Service",
            state="Running", start_mode="Auto",
            binary_path="C:\\Temp\\writable.exe",
            account="NT AUTHORITY\\SYSTEM",
            system_with_writable_binary=True,
        ),
        ServiceInfo(
            name="StoppedSvc", display_name="Stopped Service",
            state="Stopped", start_mode="Manual",
            binary_path="C:\\Temp\\stopped.exe",
            account="LocalSystem",
            system_with_writable_binary=True,
        ),
        ServiceInfo(
            name="UserSvc", display_name="User Service",
            state="Running", start_mode="Auto",
            binary_path="C:\\Temp\\user.exe",
            account="DOMAIN\\user",
            system_with_writable_binary=True,
        ),
    ]


@pytest.fixture
def context_with_data(sample_processes, sample_services):
    return {
        "process_snapshot": {
            "processes": [p.model_dump() for p in sample_processes],
            "count": len(sample_processes),
        },
        "service_auditor": {
            "services": [s.model_dump() for s in sample_services],
            "count": len(sample_services),
        },
    }


class TestLoadFromContext:
    def test_load_processes(self, analyzer, context_with_data):
        procs = analyzer._load_processes(context_with_data)
        assert len(procs) == 6
        assert all(isinstance(p, ProcessInfo) for p in procs)

    def test_load_services(self, analyzer, context_with_data):
        svcs = analyzer._load_services(context_with_data)
        assert len(svcs) == 4
        assert all(isinstance(s, ServiceInfo) for s in svcs)

    def test_load_empty_context(self, analyzer):
        assert analyzer._load_processes({}) == []
        assert analyzer._load_services({}) == []


class TestRanking:
    def test_top_by_ram(self, analyzer, sample_processes):
        top = analyzer._top_by_ram(sample_processes, 3)
        assert len(top) == 3
        assert top[0].name == "bigtool.exe"  # 2048 MB
        assert top[1].name == "chrome.exe"   # 500 MB

    def test_top_by_threads(self, analyzer, sample_processes):
        top = analyzer._top_by_threads(sample_processes, 3)
        assert len(top) == 3
        assert top[0].name == "leaky.exe"    # 500 threads
        assert top[1].name == "bigtool.exe"  # 250 threads

    def test_top_by_handles(self, analyzer, sample_processes):
        top = analyzer._top_by_handles(sample_processes, 3)
        assert len(top) == 3
        assert top[0].name == "leaky.exe"    # 10000 handles
        assert top[1].name == "bigtool.exe"  # 6000 handles

    def test_top_n_exceeds_list_size(self, analyzer, sample_processes):
        """Requesting more than available returns all."""
        top = analyzer._top_by_ram(sample_processes, 100)
        assert len(top) == 6

    def test_empty_list(self, analyzer):
        assert analyzer._top_by_ram([], 5) == []
        assert analyzer._top_by_threads([], 5) == []
        assert analyzer._top_by_handles([], 5) == []

    def test_single_process(self, analyzer):
        procs = [ProcessInfo(pid=1, name="solo.exe", ram_mb=100)]
        top = analyzer._top_by_ram(procs, 5)
        assert len(top) == 1


class TestFindResourceHogs:
    def test_high_thread_count(self, analyzer, sample_processes):
        findings = analyzer._find_resource_hogs(sample_processes)
        thread_findings = [f for f in findings if f.category == "high_thread_count"]
        # leaky.exe (500 threads) and bigtool.exe (250 threads) > 200
        assert len(thread_findings) == 2

    def test_high_handle_count(self, analyzer, sample_processes):
        findings = analyzer._find_resource_hogs(sample_processes)
        handle_findings = [f for f in findings if f.category == "high_handle_count"]
        # leaky.exe (10000 handles) and bigtool.exe (6000 handles) > 5000
        assert len(handle_findings) == 2

    def test_system_processes_skipped(self, analyzer, sample_processes):
        findings = analyzer._find_resource_hogs(sample_processes)
        pids = []
        for f in findings:
            if f.raw_data and "pid" in f.raw_data:
                pids.append(f.raw_data["pid"])
        assert 0 not in pids
        assert 4 not in pids

    def test_normal_process_not_flagged(self, analyzer):
        procs = [ProcessInfo(
            pid=100, name="normal.exe",
            thread_count=50, handle_count=200,
        )]
        findings = analyzer._find_resource_hogs(procs)
        assert len(findings) == 0

    def test_empty_list(self, analyzer):
        assert analyzer._find_resource_hogs([]) == []


class TestFindUnsignedSystemServices:
    def test_writable_system_service(self, analyzer, sample_services):
        findings = analyzer._find_unsigned_system_services(sample_services)
        writable = [f for f in findings if f.category == "system_writable_binary"]
        assert len(writable) == 1
        assert "WritableSvc" in writable[0].title
        assert writable[0].severity == SeverityLevel.HIGH
        assert writable[0].mitre_attack == "T1574.010"

    def test_stopped_service_not_flagged(self, analyzer, sample_services):
        findings = analyzer._find_unsigned_system_services(sample_services)
        stopped = [f for f in findings if "StoppedSvc" in f.title]
        assert len(stopped) == 0

    def test_non_system_not_flagged(self, analyzer, sample_services):
        findings = analyzer._find_unsigned_system_services(sample_services)
        user = [f for f in findings if "UserSvc" in f.title]
        assert len(user) == 0

    def test_empty_list(self, analyzer):
        assert analyzer._find_unsigned_system_services([]) == []


class TestAnalyzeE2E:
    @pytest.mark.asyncio
    async def test_full_analysis(self, analyzer, context_with_data):
        config = AnalyzerConfig(analyzer_name="resource_analyzer")
        result = await analyzer.analyze(config, context_with_data)

        assert result.status == ScanStatus.COMPLETED
        assert result.data["process_count"] == 6
        assert result.data["service_count"] == 4
        assert len(result.data["top_ram"]) <= 10
        assert len(result.findings) > 0

    @pytest.mark.asyncio
    async def test_empty_context(self, analyzer):
        config = AnalyzerConfig(analyzer_name="resource_analyzer")
        result = await analyzer.analyze(config, {})

        assert result.status == ScanStatus.COMPLETED
        assert result.data.get("skipped") is True

    @pytest.mark.asyncio
    async def test_custom_top_n(self, analyzer, context_with_data):
        config = AnalyzerConfig(
            analyzer_name="resource_analyzer",
            extra_args={"top_n": 2},
        )
        result = await analyzer.analyze(config, context_with_data)

        assert len(result.data["top_ram"]) == 2
        assert len(result.data["top_threads"]) == 2

    @pytest.mark.asyncio
    async def test_run_wraps_analyze(self, analyzer, context_with_data):
        """AnalyzerBase.run() wraps analyze() with timing."""
        config = AnalyzerConfig(analyzer_name="resource_analyzer")
        result = await analyzer.run(config, context_with_data)

        assert result.started_at is not None
        assert result.completed_at is not None
        assert result.duration_seconds is not None
        assert result.duration_seconds >= 0


class TestRamHogDetection:
    def test_high_ram_flagged(self, analyzer):
        procs = [ProcessInfo(
            pid=100, name="hog.exe", path="C:\\hog.exe", ram_mb=2048,
        )]
        findings = analyzer._find_resource_hogs(procs)
        ram = [f for f in findings if f.category == "high_ram_usage"]
        assert len(ram) == 1
        assert ram[0].domain == FindingDomain.PERFORMANCE

    def test_normal_ram_not_flagged(self, analyzer):
        procs = [ProcessInfo(pid=100, name="ok.exe", ram_mb=512)]
        findings = analyzer._find_resource_hogs(procs)
        ram = [f for f in findings if f.category == "high_ram_usage"]
        assert len(ram) == 0


class TestCpuHogDetection:
    def test_high_cpu_flagged(self, analyzer):
        procs = [ProcessInfo(
            pid=100, name="burner.exe", path="C:\\burner.exe", cpu_percent=5000.0,
        )]
        findings = analyzer._find_resource_hogs(procs)
        cpu = [f for f in findings if f.category == "high_cpu_usage"]
        assert len(cpu) == 1
        assert cpu[0].domain == FindingDomain.PERFORMANCE

    def test_normal_cpu_not_flagged(self, analyzer):
        procs = [ProcessInfo(pid=100, name="idle.exe", cpu_percent=100.0)]
        findings = analyzer._find_resource_hogs(procs)
        cpu = [f for f in findings if f.category == "high_cpu_usage"]
        assert len(cpu) == 0


class TestFindingDomainTags:
    def test_resource_hog_findings_are_performance(self, analyzer, sample_processes):
        findings = analyzer._find_resource_hogs(sample_processes)
        for f in findings:
            assert f.domain == FindingDomain.PERFORMANCE

    def test_system_service_finding_is_security(self, analyzer, sample_services):
        findings = analyzer._find_unsigned_system_services(sample_services)
        for f in findings:
            assert f.domain == FindingDomain.SECURITY  # default


def _wmi_date(dt: datetime) -> str:
    """Create a WMI /Date(millis)/ string from a datetime."""
    millis = int(dt.timestamp() * 1000)
    return f"/Date({millis})/"


class TestStaleProcessDetection:
    def test_stale_process_flagged(self, analyzer):
        old_time = datetime.now(tz=timezone.utc) - timedelta(days=10)
        procs = [ProcessInfo(
            pid=100, name="oldapp.exe", path="C:\\oldapp.exe",
            created_at=_wmi_date(old_time),
        )]
        findings, stale = analyzer._find_stale_processes(procs)
        assert len(findings) == 1
        assert findings[0].category == "stale_process"
        assert findings[0].domain == FindingDomain.HYGIENE
        assert len(stale) == 1

    def test_fresh_process_not_flagged(self, analyzer):
        now = datetime.now(tz=timezone.utc) - timedelta(hours=1)
        procs = [ProcessInfo(
            pid=100, name="fresh.exe", created_at=_wmi_date(now),
        )]
        findings, stale = analyzer._find_stale_processes(procs)
        assert len(findings) == 0
        assert len(stale) == 0

    def test_known_long_running_skipped(self, analyzer):
        old_time = datetime.now(tz=timezone.utc) - timedelta(days=30)
        procs = [ProcessInfo(
            pid=100, name="svchost.exe", created_at=_wmi_date(old_time),
        )]
        findings, _ = analyzer._find_stale_processes(procs)
        assert len(findings) == 0

    def test_system_processes_skipped(self, analyzer):
        old_time = datetime.now(tz=timezone.utc) - timedelta(days=30)
        procs = [ProcessInfo(
            pid=4, name="System", created_at=_wmi_date(old_time),
        )]
        findings, _ = analyzer._find_stale_processes(procs)
        assert len(findings) == 0

    def test_no_created_at_skipped(self, analyzer):
        procs = [ProcessInfo(pid=100, name="nodate.exe")]
        findings, _ = analyzer._find_stale_processes(procs)
        assert len(findings) == 0


class TestOrphanProcessDetection:
    def test_orphan_stale_flagged(self, analyzer):
        old_time = datetime.now(tz=timezone.utc) - timedelta(days=2)
        procs = [
            ProcessInfo(pid=100, name="orphan.exe", parent_pid=9999,
                        path="C:\\orphan.exe", created_at=_wmi_date(old_time)),
        ]
        findings, orphans = analyzer._find_orphan_processes(procs)
        assert len(findings) == 1
        assert findings[0].category == "orphan_process"
        assert findings[0].domain == FindingDomain.HYGIENE

    def test_orphan_unsigned_flagged(self, analyzer):
        now = datetime.now(tz=timezone.utc) - timedelta(minutes=5)
        procs = [
            ProcessInfo(pid=100, name="unsigned_orphan.exe", parent_pid=9999,
                        path="C:\\bad.exe", is_signed=False, created_at=_wmi_date(now)),
        ]
        findings, _ = analyzer._find_orphan_processes(procs)
        assert len(findings) == 1

    def test_orphan_fresh_signed_not_flagged(self, analyzer):
        """Fresh, signed orphan should NOT be flagged (noise reduction)."""
        now = datetime.now(tz=timezone.utc) - timedelta(minutes=5)
        procs = [
            ProcessInfo(pid=100, name="ok_orphan.exe", parent_pid=9999,
                        is_signed=True, created_at=_wmi_date(now)),
        ]
        findings, _ = analyzer._find_orphan_processes(procs)
        assert len(findings) == 0

    def test_parent_alive_not_flagged(self, analyzer):
        old_time = datetime.now(tz=timezone.utc) - timedelta(days=2)
        procs = [
            ProcessInfo(pid=50, name="parent.exe"),
            ProcessInfo(pid=100, name="child.exe", parent_pid=50,
                        created_at=_wmi_date(old_time)),
        ]
        findings, _ = analyzer._find_orphan_processes(procs)
        assert len(findings) == 0

    def test_known_long_running_skipped(self, analyzer):
        old_time = datetime.now(tz=timezone.utc) - timedelta(days=10)
        procs = [
            ProcessInfo(pid=100, name="explorer.exe", parent_pid=9999,
                        created_at=_wmi_date(old_time)),
        ]
        findings, _ = analyzer._find_orphan_processes(procs)
        assert len(findings) == 0

    def test_system_parent_not_orphan(self, analyzer):
        """Processes with parent PID 0 or 4 are not orphans."""
        old_time = datetime.now(tz=timezone.utc) - timedelta(days=10)
        procs = [
            ProcessInfo(pid=100, name="child.exe", parent_pid=4,
                        created_at=_wmi_date(old_time)),
        ]
        findings, _ = analyzer._find_orphan_processes(procs)
        assert len(findings) == 0


class TestParseWmiDate:
    def test_valid_date(self):
        dt = ResourceAnalyzer._parse_wmi_date("/Date(1708200000000)/")
        assert dt is not None
        assert dt.year == 2024

    def test_none_returns_none(self):
        assert ResourceAnalyzer._parse_wmi_date(None) is None

    def test_empty_string_returns_none(self):
        assert ResourceAnalyzer._parse_wmi_date("") is None

    def test_invalid_format_returns_none(self):
        assert ResourceAnalyzer._parse_wmi_date("not a date") is None
