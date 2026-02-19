"""Tests for ProcessSnapshotCollector — parsing and analysis logic."""

import json
import pytest
from pathlib import Path

from src.audit.collectors.process_snapshot import ProcessSnapshotCollector
from src.audit.models import SeverityLevel

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def collector():
    return ProcessSnapshotCollector()


@pytest.fixture
def raw_processes():
    return json.loads((FIXTURES / "win32_process_output.json").read_text())


class TestParseProcesses:
    def test_parse_all_entries(self, collector, raw_processes):
        """All valid entries are parsed into ProcessInfo objects."""
        procs = collector._parse_processes(raw_processes)
        assert len(procs) == 7

    def test_pid_and_name(self, collector, raw_processes):
        procs = collector._parse_processes(raw_processes)
        chrome = next(p for p in procs if p.name == "chrome.exe")
        assert chrome.pid == 5678
        assert chrome.parent_pid == 5600

    def test_ram_bytes_to_mb(self, collector, raw_processes):
        """WorkingSetSize (bytes) is converted to MB."""
        procs = collector._parse_processes(raw_processes)
        chrome = next(p for p in procs if p.name == "chrome.exe")
        assert chrome.ram_mb == pytest.approx(500.0, abs=1)

    def test_large_ram(self, collector, raw_processes):
        """A 3 GB process is parsed correctly."""
        procs = collector._parse_processes(raw_processes)
        big = next(p for p in procs if p.name == "bigtool.exe")
        assert big.ram_mb == pytest.approx(3072.0, abs=1)

    def test_null_path_handled(self, collector, raw_processes):
        """Processes with null ExecutablePath parse without error."""
        procs = collector._parse_processes(raw_processes)
        system = next(p for p in procs if p.pid == 0)
        assert system.path is None

    def test_thread_and_handle_counts(self, collector, raw_processes):
        procs = collector._parse_processes(raw_processes)
        svchost = next(p for p in procs if p.name == "svchost.exe")
        assert svchost.thread_count == 12
        assert svchost.handle_count == 450

    def test_null_working_set_treated_as_zero(self, collector):
        """WorkingSetSize of None becomes 0 MB."""
        raw = [{"ProcessId": 1, "Name": "test.exe", "WorkingSetSize": None}]
        procs = collector._parse_processes(raw)
        assert procs[0].ram_mb == 0.0

    def test_single_process_dict(self, collector):
        """A single dict (not list) still parses."""
        raw = [{"ProcessId": 42, "Name": "solo.exe", "WorkingSetSize": 1048576}]
        procs = collector._parse_processes(raw)
        assert len(procs) == 1
        assert procs[0].pid == 42
        assert procs[0].ram_mb == pytest.approx(1.0, abs=0.1)


class TestApplySignatures:
    def test_apply_valid_signature(self, collector):
        from src.audit.models import ProcessInfo
        procs = [ProcessInfo(
            pid=100, name="app.exe",
            path="C:\\Program Files\\App\\app.exe",
        )]
        sigs = {"C:\\Program Files\\App\\app.exe": {"Status": "Valid", "Signer": "CN=Microsoft"}}
        collector._apply_signatures(procs, sigs)
        assert procs[0].is_signed is True
        assert procs[0].signer == "CN=Microsoft"

    def test_apply_unsigned(self, collector):
        from src.audit.models import ProcessInfo
        procs = [ProcessInfo(
            pid=100, name="app.exe",
            path="C:\\Temp\\app.exe",
        )]
        sigs = {"C:\\Temp\\app.exe": {"Status": "NotSigned", "Signer": None}}
        collector._apply_signatures(procs, sigs)
        assert procs[0].is_signed is False
        assert procs[0].signer is None

    def test_no_matching_sig(self, collector):
        from src.audit.models import ProcessInfo
        procs = [ProcessInfo(pid=100, name="app.exe", path="C:\\missing.exe")]
        collector._apply_signatures(procs, {})
        assert procs[0].is_signed is None  # unchanged


class TestAnalyze:
    def test_unsigned_finding(self, collector):
        from src.audit.models import ProcessInfo
        procs = [ProcessInfo(
            pid=100, name="bad.exe",
            path="C:\\Temp\\bad.exe",
            is_signed=False,
        )]
        findings = collector._analyze(procs)
        unsigned = [f for f in findings if f.category == "unsigned_process"]
        assert len(unsigned) == 1
        assert unsigned[0].severity == SeverityLevel.MEDIUM

    def test_no_ram_finding_in_collector(self, collector, raw_processes):
        """RAM hog detection is handled by resource_analyzer, not the collector."""
        procs = collector._parse_processes(raw_processes)
        findings = collector._analyze(procs)
        high_ram = [f for f in findings if "ram" in f.category or "memory" in f.category or "resource" in f.category]
        assert len(high_ram) == 0

    def test_non_standard_path_finding(self, collector, raw_processes):
        procs = collector._parse_processes(raw_processes)
        findings = collector._analyze(procs)
        nsp = [f for f in findings if f.category == "non_standard_path"]
        # suspicious.exe is in AppData\Local\Temp
        names = [f.title for f in nsp]
        assert any("suspicious.exe" in t for t in names)

    def test_system_processes_skipped(self, collector, raw_processes):
        procs = collector._parse_processes(raw_processes)
        findings = collector._analyze(procs)
        # PIDs 0 and 4 should be skipped
        pids_in_findings = []
        for f in findings:
            if f.raw_data and "pid" in f.raw_data:
                pids_in_findings.append(f.raw_data["pid"])
        assert 0 not in pids_in_findings
        assert 4 not in pids_in_findings

    def test_no_path_skipped(self, collector):
        from src.audit.models import ProcessInfo
        procs = [ProcessInfo(pid=100, name="no_path.exe")]
        findings = collector._analyze(procs)
        assert len(findings) == 0


class TestIsStandardPath:
    @pytest.mark.parametrize("path,expected", [
        ("C:\\Windows\\System32\\cmd.exe", True),
        ("C:\\Program Files\\App\\app.exe", True),
        ("C:\\Program Files (x86)\\App\\app.exe", True),
        ("C:\\ProgramData\\App\\app.exe", True),
        ("c:\\windows\\system32\\cmd.exe", True),  # case-insensitive
        ("D:\\Tools\\tool.exe", False),
        ("C:\\Users\\Admin\\Desktop\\app.exe", False),
        ("C:\\Temp\\virus.exe", False),
    ])
    def test_standard_path_detection(self, path, expected):
        assert ProcessSnapshotCollector._is_standard_path(path) == expected


class TestOwnerParsing:
    def test_owner_domain_and_user(self, collector):
        raw = [{"ProcessId": 100, "Name": "test.exe",
                "OwnerDomain": "MYPC", "OwnerUser": "admin"}]
        procs = collector._parse_processes(raw)
        assert procs[0].user == "MYPC\\admin"

    def test_owner_user_only(self, collector):
        raw = [{"ProcessId": 100, "Name": "test.exe",
                "OwnerUser": "admin", "OwnerDomain": None}]
        procs = collector._parse_processes(raw)
        assert procs[0].user == "admin"

    def test_no_owner_fields(self, collector):
        raw = [{"ProcessId": 100, "Name": "test.exe"}]
        procs = collector._parse_processes(raw)
        assert procs[0].user is None

    def test_empty_owner_user(self, collector):
        raw = [{"ProcessId": 100, "Name": "test.exe",
                "OwnerUser": "", "OwnerDomain": "MYPC"}]
        procs = collector._parse_processes(raw)
        assert procs[0].user is None


class TestCpuSampling:
    @pytest.mark.asyncio
    async def test_sample_cpu_merges_by_pid(self, collector):
        from src.audit.models import ProcessInfo
        procs = [
            ProcessInfo(pid=100, name="a.exe"),
            ProcessInfo(pid=200, name="b.exe"),
        ]
        # Mock _run_powershell to return CPU data
        import json
        cpu_data = [{"Id": 100, "CpuSeconds": 42.5}, {"Id": 200, "CpuSeconds": 0.0}]

        async def mock_ps(script, timeout=60):
            return json.dumps(cpu_data)

        collector._run_powershell = mock_ps
        await collector._sample_cpu(procs, 30)

        assert procs[0].cpu_percent == 42.5
        assert procs[1].cpu_percent == 0.0

    @pytest.mark.asyncio
    async def test_sample_cpu_graceful_failure(self, collector):
        from src.audit.models import ProcessInfo
        procs = [ProcessInfo(pid=100, name="a.exe")]

        async def mock_ps_fail(script, timeout=60):
            raise RuntimeError("PS failed")

        collector._run_powershell = mock_ps_fail
        await collector._sample_cpu(procs, 30)
        # Should not raise, CPU stays at default
        assert procs[0].cpu_percent == 0.0
