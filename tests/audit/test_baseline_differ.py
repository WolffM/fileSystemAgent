"""Tests for BaselineDiffer — diff engine, severity classification, persistence."""

import json
import pytest
from datetime import datetime
from pathlib import Path

from src.audit.analyzers.baseline_differ import BaselineDiffer
from src.audit.models import AnalyzerConfig, ScanStatus, SeverityLevel


@pytest.fixture
def differ():
    return BaselineDiffer()


@pytest.fixture
def baseline_context():
    """Simulated baseline scan data (previous run)."""
    return {
        "process_snapshot": {
            "processes": [
                {"name": "chrome.exe", "path": "C:\\Program Files\\Chrome\\chrome.exe"},
                {"name": "svchost.exe", "path": "C:\\Windows\\System32\\svchost.exe"},
                {"name": "notepad.exe", "path": "C:\\Windows\\System32\\notepad.exe"},
            ],
        },
        "service_auditor": {
            "services": [
                {"name": "Spooler", "display_name": "Print Spooler",
                 "state": "Running", "account": "LocalSystem",
                 "binary_path": "C:\\Windows\\System32\\spoolsv.exe"},
                {"name": "wuauserv", "display_name": "Windows Update",
                 "state": "Running", "account": "LocalSystem",
                 "binary_path": "C:\\Windows\\System32\\svchost.exe"},
            ],
        },
        "network_mapper": {
            "connections": [
                {"local_address": "0.0.0.0", "local_port": 80,
                 "state": "Listen", "process_name": "httpd.exe"},
                {"local_address": "0.0.0.0", "local_port": 443,
                 "state": "Listen", "process_name": "httpd.exe"},
                {"local_address": "192.168.1.10", "local_port": 50000,
                 "state": "Established", "process_name": "chrome.exe"},
            ],
        },
        "persistence_auditor": {
            "scheduled_tasks": [
                {"task_name": "WindowsUpdate", "execute": "C:\\Windows\\System32\\usoclient.exe"},
                {"task_name": "MyBackup", "execute": "D:\\Scripts\\backup.bat"},
            ],
            "run_keys": [
                {"registry_path": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                 "name": "SecurityHealth",
                 "value": "C:\\Windows\\system32\\SecurityHealthSystray.exe"},
            ],
        },
    }


@pytest.fixture
def current_context():
    """Simulated current scan data with some changes."""
    return {
        "process_snapshot": {
            "processes": [
                {"name": "chrome.exe", "path": "C:\\Program Files\\Chrome\\chrome.exe"},
                {"name": "svchost.exe", "path": "C:\\Windows\\System32\\svchost.exe"},
                # notepad removed, malware added
                {"name": "malware.exe", "path": "C:\\Temp\\malware.exe"},
            ],
        },
        "service_auditor": {
            "services": [
                {"name": "Spooler", "display_name": "Print Spooler",
                 "state": "Running", "account": "LocalSystem",
                 "binary_path": "C:\\Windows\\System32\\spoolsv.exe"},
                # wuauserv removed, EvilSvc added as SYSTEM
                {"name": "EvilSvc", "display_name": "Evil Service",
                 "state": "Running", "account": "LocalSystem",
                 "binary_path": "C:\\Temp\\evil.exe"},
            ],
        },
        "network_mapper": {
            "connections": [
                {"local_address": "0.0.0.0", "local_port": 80,
                 "state": "Listen", "process_name": "httpd.exe"},
                # port 443 removed, port 4444 added
                {"local_address": "0.0.0.0", "local_port": 4444,
                 "state": "Listen", "process_name": "nc.exe"},
                {"local_address": "192.168.1.10", "local_port": 50000,
                 "state": "Established", "process_name": "chrome.exe"},
            ],
        },
        "persistence_auditor": {
            "scheduled_tasks": [
                {"task_name": "WindowsUpdate", "execute": "C:\\Windows\\System32\\usoclient.exe"},
                # MyBackup removed, SuspiciousTask added
                {"task_name": "SuspiciousTask", "execute": "C:\\Temp\\payload.exe"},
            ],
            "run_keys": [
                {"registry_path": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                 "name": "SecurityHealth",
                 "value": "C:\\Windows\\system32\\SecurityHealthSystray.exe"},
                # new run key
                {"registry_path": "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                 "name": "Backdoor",
                 "value": "C:\\Temp\\backdoor.exe"},
            ],
        },
    }


# ---- Process diff tests ----

class TestDiffProcesses:
    def test_added_process(self, differ, baseline_context, current_context):
        result = differ._diff_processes(
            baseline_context["process_snapshot"],
            current_context["process_snapshot"],
        )
        added = [f for f in result["findings"] if f.category == "new_process"]
        assert len(added) == 1
        assert "malware.exe" in added[0].title
        assert added[0].severity == SeverityLevel.LOW

    def test_removed_process(self, differ, baseline_context, current_context):
        result = differ._diff_processes(
            baseline_context["process_snapshot"],
            current_context["process_snapshot"],
        )
        removed = [f for f in result["findings"] if f.category == "removed_process"]
        assert len(removed) == 1
        assert "notepad.exe" in removed[0].title
        assert removed[0].severity == SeverityLevel.INFO

    def test_unchanged_processes_not_reported(self, differ, baseline_context, current_context):
        result = differ._diff_processes(
            baseline_context["process_snapshot"],
            current_context["process_snapshot"],
        )
        titles = [f.title for f in result["findings"]]
        assert not any("chrome.exe" in t for t in titles)
        assert not any("svchost.exe" in t for t in titles)

    def test_summary_counts(self, differ, baseline_context, current_context):
        result = differ._diff_processes(
            baseline_context["process_snapshot"],
            current_context["process_snapshot"],
        )
        assert result["summary"]["added"] == 1
        assert result["summary"]["removed"] == 1

    def test_identical_processes(self, differ, baseline_context):
        result = differ._diff_processes(
            baseline_context["process_snapshot"],
            baseline_context["process_snapshot"],
        )
        assert len(result["findings"]) == 0
        assert result["summary"]["added"] == 0
        assert result["summary"]["removed"] == 0

    def test_empty_baseline(self, differ, current_context):
        result = differ._diff_processes({}, current_context["process_snapshot"])
        added = [f for f in result["findings"] if f.category == "new_process"]
        assert len(added) == 3  # all current processes are "new"

    def test_empty_current(self, differ, baseline_context):
        result = differ._diff_processes(baseline_context["process_snapshot"], {})
        removed = [f for f in result["findings"] if f.category == "removed_process"]
        assert len(removed) == 3  # all baseline processes are "removed"

    def test_both_empty(self, differ):
        result = differ._diff_processes({}, {})
        assert len(result["findings"]) == 0


# ---- Service diff tests ----

class TestDiffServices:
    def test_new_system_service_is_high(self, differ, baseline_context, current_context):
        result = differ._diff_services(
            baseline_context["service_auditor"],
            current_context["service_auditor"],
        )
        added = [f for f in result["findings"] if f.category == "new_service"]
        assert len(added) == 1
        assert "EvilSvc" in added[0].title
        assert added[0].severity == SeverityLevel.HIGH  # LocalSystem account

    def test_removed_service(self, differ, baseline_context, current_context):
        result = differ._diff_services(
            baseline_context["service_auditor"],
            current_context["service_auditor"],
        )
        removed = [f for f in result["findings"] if f.category == "removed_service"]
        assert len(removed) == 1
        assert "wuauserv" in removed[0].title
        assert removed[0].severity == SeverityLevel.INFO

    def test_non_system_service_is_medium(self, differ):
        baseline = {"services": []}
        current = {"services": [
            {"name": "UserSvc", "display_name": "User Service",
             "state": "Running", "account": "DOMAIN\\user",
             "binary_path": "C:\\app.exe"},
        ]}
        result = differ._diff_services(baseline, current)
        added = [f for f in result["findings"] if f.category == "new_service"]
        assert len(added) == 1
        assert added[0].severity == SeverityLevel.MEDIUM

    def test_nt_authority_system_is_high(self, differ):
        baseline = {"services": []}
        current = {"services": [
            {"name": "NtSvc", "display_name": "NT Svc",
             "state": "Running", "account": "NT AUTHORITY\\SYSTEM",
             "binary_path": "C:\\app.exe"},
        ]}
        result = differ._diff_services(baseline, current)
        added = [f for f in result["findings"] if f.category == "new_service"]
        assert added[0].severity == SeverityLevel.HIGH

    def test_identical_services(self, differ, baseline_context):
        result = differ._diff_services(
            baseline_context["service_auditor"],
            baseline_context["service_auditor"],
        )
        assert len(result["findings"]) == 0


# ---- Network diff tests ----

class TestDiffNetwork:
    def test_new_listener(self, differ, baseline_context, current_context):
        result = differ._diff_network(
            baseline_context["network_mapper"],
            current_context["network_mapper"],
        )
        added = [f for f in result["findings"] if f.category == "new_listener"]
        assert len(added) == 1
        assert "4444" in added[0].title
        assert added[0].severity == SeverityLevel.MEDIUM

    def test_removed_listener(self, differ, baseline_context, current_context):
        result = differ._diff_network(
            baseline_context["network_mapper"],
            current_context["network_mapper"],
        )
        removed = [f for f in result["findings"] if f.category == "removed_listener"]
        assert len(removed) == 1
        assert "443" in removed[0].title

    def test_established_connections_ignored(self, differ, baseline_context, current_context):
        """Only Listen-state connections are diffed."""
        result = differ._diff_network(
            baseline_context["network_mapper"],
            current_context["network_mapper"],
        )
        # Established connections should not appear in findings
        all_targets = [f.target for f in result["findings"]]
        assert not any("50000" in t for t in all_targets)

    def test_identical_listeners(self, differ, baseline_context):
        result = differ._diff_network(
            baseline_context["network_mapper"],
            baseline_context["network_mapper"],
        )
        assert len(result["findings"]) == 0


# ---- Persistence diff tests ----

class TestDiffPersistence:
    def test_new_scheduled_task(self, differ, baseline_context, current_context):
        result = differ._diff_persistence(
            baseline_context["persistence_auditor"],
            current_context["persistence_auditor"],
        )
        added_tasks = [f for f in result["findings"]
                       if f.category == "new_scheduled_task"]
        assert len(added_tasks) == 1
        assert "SuspiciousTask" in added_tasks[0].title
        assert added_tasks[0].severity == SeverityLevel.MEDIUM

    def test_removed_scheduled_task(self, differ, baseline_context, current_context):
        result = differ._diff_persistence(
            baseline_context["persistence_auditor"],
            current_context["persistence_auditor"],
        )
        removed_tasks = [f for f in result["findings"]
                         if f.category == "removed_scheduled_task"]
        assert len(removed_tasks) == 1
        assert "MyBackup" in removed_tasks[0].title
        assert removed_tasks[0].severity == SeverityLevel.INFO

    def test_new_run_key(self, differ, baseline_context, current_context):
        result = differ._diff_persistence(
            baseline_context["persistence_auditor"],
            current_context["persistence_auditor"],
        )
        added_keys = [f for f in result["findings"]
                      if f.category == "new_run_key"]
        assert len(added_keys) == 1
        assert "Backdoor" in added_keys[0].title
        assert added_keys[0].severity == SeverityLevel.MEDIUM

    def test_removed_run_key(self, differ):
        baseline = {
            "scheduled_tasks": [],
            "run_keys": [
                {"registry_path": "HKLM:\\...\\Run", "name": "OldKey",
                 "value": "C:\\old.exe"},
            ],
        }
        current = {"scheduled_tasks": [], "run_keys": []}
        result = differ._diff_persistence(baseline, current)
        removed = [f for f in result["findings"]
                   if f.category == "removed_run_key"]
        assert len(removed) == 1
        assert "OldKey" in removed[0].title
        assert removed[0].severity == SeverityLevel.INFO

    def test_summary_combines_tasks_and_keys(self, differ, baseline_context, current_context):
        result = differ._diff_persistence(
            baseline_context["persistence_auditor"],
            current_context["persistence_auditor"],
        )
        # 1 new task + 1 new run key = 2 added; 1 removed task = 1 removed
        assert result["summary"]["added"] == 2
        assert result["summary"]["removed"] == 1

    def test_identical_persistence(self, differ, baseline_context):
        result = differ._diff_persistence(
            baseline_context["persistence_auditor"],
            baseline_context["persistence_auditor"],
        )
        assert len(result["findings"]) == 0
        assert result["summary"]["added"] == 0
        assert result["summary"]["removed"] == 0


# ---- Extract listeners helper ----

class TestExtractListeners:
    def test_only_listen_state(self, differ):
        data = {
            "connections": [
                {"local_address": "0.0.0.0", "local_port": 80, "state": "Listen"},
                {"local_address": "1.2.3.4", "local_port": 443, "state": "Established"},
                {"local_address": "0.0.0.0", "local_port": 22, "state": "Listen"},
            ]
        }
        listeners = differ._extract_listeners(data)
        assert len(listeners) == 2
        assert "0.0.0.0:80" in listeners
        assert "0.0.0.0:22" in listeners

    def test_empty_connections(self, differ):
        assert differ._extract_listeners({}) == {}
        assert differ._extract_listeners({"connections": []}) == {}


# ---- Full analyze E2E ----

class TestAnalyzeE2E:
    @pytest.mark.asyncio
    async def test_first_run_saves_baseline(self, differ, tmp_path, baseline_context):
        config = AnalyzerConfig(
            analyzer_name="baseline_differ",
            extra_args={"baseline_dir": str(tmp_path)},
        )
        result = await differ.analyze(config, baseline_context)

        assert result.status == ScanStatus.COMPLETED
        assert result.data["first_run"] is True
        assert result.data["baseline_saved"] is True
        # Baseline file should exist
        baselines = list(tmp_path.glob("baseline_*.json"))
        assert len(baselines) == 1

    @pytest.mark.asyncio
    async def test_second_run_diffs(self, differ, tmp_path,
                                     baseline_context, current_context):
        config = AnalyzerConfig(
            analyzer_name="baseline_differ",
            extra_args={"baseline_dir": str(tmp_path)},
        )
        # First run — saves baseline
        await differ.analyze(config, baseline_context)
        # Second run — produces diff
        result = await differ.analyze(config, current_context)

        assert result.status == ScanStatus.COMPLETED
        assert result.data["first_run"] is False
        assert result.data["total_changes"] > 0
        assert len(result.findings) > 0

    @pytest.mark.asyncio
    async def test_second_run_finds_all_categories(self, differ, tmp_path,
                                                     baseline_context, current_context):
        config = AnalyzerConfig(
            analyzer_name="baseline_differ",
            extra_args={"baseline_dir": str(tmp_path)},
        )
        await differ.analyze(config, baseline_context)
        result = await differ.analyze(config, current_context)

        categories = {f.category for f in result.findings}
        assert "new_process" in categories
        assert "removed_process" in categories
        assert "new_service" in categories
        assert "removed_service" in categories
        assert "new_listener" in categories
        assert "removed_listener" in categories
        assert "new_scheduled_task" in categories
        assert "removed_scheduled_task" in categories
        assert "new_run_key" in categories

    @pytest.mark.asyncio
    async def test_identical_scans_no_findings(self, differ, tmp_path, baseline_context):
        config = AnalyzerConfig(
            analyzer_name="baseline_differ",
            extra_args={"baseline_dir": str(tmp_path)},
        )
        await differ.analyze(config, baseline_context)
        result = await differ.analyze(config, baseline_context)

        assert result.data["total_changes"] == 0
        assert len(result.findings) == 0

    @pytest.mark.asyncio
    async def test_partial_context_only_diffs_available(self, differ, tmp_path):
        """If only process data exists, only process diff runs."""
        baseline = {
            "process_snapshot": {
                "processes": [{"name": "a.exe", "path": "C:\\a.exe"}],
            },
        }
        current = {
            "process_snapshot": {
                "processes": [
                    {"name": "a.exe", "path": "C:\\a.exe"},
                    {"name": "b.exe", "path": "C:\\b.exe"},
                ],
            },
        }
        config = AnalyzerConfig(
            analyzer_name="baseline_differ",
            extra_args={"baseline_dir": str(tmp_path)},
        )
        await differ.analyze(config, baseline)
        result = await differ.analyze(config, current)

        assert result.data["total_changes"] == 1
        assert len(result.findings) == 1
        assert result.findings[0].category == "new_process"
        # No service/network/persistence diffs
        assert "services" not in result.data["diff_summary"]
        assert "network" not in result.data["diff_summary"]
        assert "persistence" not in result.data["diff_summary"]


# ---- Baseline persistence helpers ----

class TestBaselinePersistence:
    def test_save_and_load(self, tmp_path):
        context = {"test": "data", "count": 42}
        BaselineDiffer._save_baseline(tmp_path, context)

        loaded = BaselineDiffer._load_baseline(tmp_path)
        assert loaded is not None
        assert loaded["test"] == "data"
        assert loaded["count"] == 42

    def test_load_nonexistent_dir(self, tmp_path):
        assert BaselineDiffer._load_baseline(tmp_path / "nonexistent") is None

    def test_load_empty_dir(self, tmp_path):
        assert BaselineDiffer._load_baseline(tmp_path) is None

    def test_load_most_recent(self, tmp_path):
        import time
        BaselineDiffer._save_baseline(tmp_path, {"version": 1})
        time.sleep(0.05)
        BaselineDiffer._save_baseline(tmp_path, {"version": 2})

        loaded = BaselineDiffer._load_baseline(tmp_path)
        assert loaded["version"] == 2

    def test_get_baseline_info(self, tmp_path):
        BaselineDiffer._save_baseline(tmp_path, {"process_snapshot": {}, "service_auditor": {}})

        info = BaselineDiffer.get_baseline_info(str(tmp_path))
        assert info is not None
        assert info["file_count"] == 1
        assert "process_snapshot" in info["collectors"]
        assert "service_auditor" in info["collectors"]

    def test_get_baseline_info_none(self, tmp_path):
        assert BaselineDiffer.get_baseline_info(str(tmp_path / "nope")) is None

    def test_clear_baselines(self, tmp_path):
        import time
        BaselineDiffer._save_baseline(tmp_path, {"a": 1})
        time.sleep(1.1)  # ensure different timestamp in filename
        BaselineDiffer._save_baseline(tmp_path, {"b": 2})

        removed = BaselineDiffer.clear_baselines(str(tmp_path))
        assert removed == 2
        assert list(tmp_path.glob("baseline_*.json")) == []

    def test_clear_empty_dir(self, tmp_path):
        assert BaselineDiffer.clear_baselines(str(tmp_path)) == 0

    def test_clear_nonexistent_dir(self, tmp_path):
        assert BaselineDiffer.clear_baselines(str(tmp_path / "nope")) == 0

    def test_save_baseline_from_context(self, tmp_path):
        context = {"data": [1, 2, 3]}
        filepath = BaselineDiffer.save_baseline_from_context(context, str(tmp_path))
        assert filepath is not None
        assert filepath.exists()
        data = json.loads(filepath.read_text())
        assert data["data"] == [1, 2, 3]


# ---- Analyzer name ----

class TestAnalyzerName:
    def test_name(self, differ):
        assert differ.analyzer_name == "baseline_differ"
