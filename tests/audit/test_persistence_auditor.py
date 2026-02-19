"""Tests for PersistenceAuditorCollector — parsing and analysis logic."""

import json
import pytest
from pathlib import Path

from src.audit.collectors.persistence_auditor import PersistenceAuditorCollector
from src.audit.models import SeverityLevel

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def collector():
    return PersistenceAuditorCollector()


@pytest.fixture
def raw_tasks():
    return json.loads((FIXTURES / "scheduled_tasks_output.json").read_text())


@pytest.fixture
def raw_run_keys():
    return json.loads((FIXTURES / "run_keys_output.json").read_text())


class TestParseTasks:
    def test_parse_all_entries(self, collector, raw_tasks):
        tasks = collector._parse_tasks(raw_tasks)
        assert len(tasks) == 6

    def test_state_enum_to_string(self, collector, raw_tasks):
        tasks = collector._parse_tasks(raw_tasks)
        ready = [t for t in tasks if t.state == "Ready"]
        assert len(ready) == 4  # WindowsUpdate, MyBackup, ChromeUpdate, SuspiciousTask

    def test_disabled_state(self, collector, raw_tasks):
        tasks = collector._parse_tasks(raw_tasks)
        disabled = next(t for t in tasks if t.task_name == "DisabledTask")
        assert disabled.state == "Disabled"

    def test_running_state(self, collector, raw_tasks):
        tasks = collector._parse_tasks(raw_tasks)
        running = next(t for t in tasks if t.task_name == "PowerShellTask")
        assert running.state == "Running"

    def test_run_level_highest(self, collector, raw_tasks):
        tasks = collector._parse_tasks(raw_tasks)
        wu = next(t for t in tasks if t.task_name == "WindowsUpdate")
        assert wu.run_level == "Highest"

    def test_run_level_limited(self, collector, raw_tasks):
        tasks = collector._parse_tasks(raw_tasks)
        chrome = next(t for t in tasks if t.task_name == "ChromeUpdate")
        assert chrome.run_level == "Limited"

    def test_task_fields(self, collector, raw_tasks):
        tasks = collector._parse_tasks(raw_tasks)
        backup = next(t for t in tasks if t.task_name == "MyBackup")
        assert backup.task_path == "\\"
        assert backup.execute == "D:\\Scripts\\backup.bat"
        assert backup.user_id == "Admin"

    def test_string_state_passthrough(self, collector):
        raw = [{"TaskName": "test", "State": "Ready"}]
        tasks = collector._parse_tasks(raw)
        assert tasks[0].state == "Ready"

    def test_null_execute(self, collector):
        raw = [{"TaskName": "empty", "Execute": None}]
        tasks = collector._parse_tasks(raw)
        assert tasks[0].execute is None


class TestParseRunKeys:
    def test_parse_all_entries(self, collector, raw_run_keys):
        keys = collector._parse_run_keys(raw_run_keys)
        assert len(keys) == 5

    def test_basic_fields(self, collector, raw_run_keys):
        keys = collector._parse_run_keys(raw_run_keys)
        security = next(k for k in keys if k.name == "SecurityHealth")
        assert security.registry_path == "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
        assert security.value == "C:\\Windows\\system32\\SecurityHealthSystray.exe"

    def test_hkcu_keys(self, collector, raw_run_keys):
        keys = collector._parse_run_keys(raw_run_keys)
        hkcu = [k for k in keys if "HKCU" in k.registry_path]
        assert len(hkcu) == 3  # Discord, RiotClient, Steam


class TestExtractExePath:
    @pytest.mark.parametrize("value,expected", [
        # Quoted path
        ('"C:\\Program Files\\App\\app.exe" --flag', "C:\\Program Files\\App\\app.exe"),
        # Unquoted path
        ("C:\\Windows\\system32\\cmd.exe /c run", "C:\\Windows\\system32\\cmd.exe"),
        # Simple path
        ("C:\\app.exe", "C:\\app.exe"),
        # Empty
        ("", ""),
    ])
    def test_extract_exe_path(self, value, expected):
        assert PersistenceAuditorCollector._extract_exe_path(value) == expected


class TestIsSuspiciousTaskPath:
    @pytest.mark.parametrize("path,expected", [
        # Standard Windows paths — not suspicious
        ("C:\\Windows\\System32\\usoclient.exe", False),
        ("C:\\Program Files\\Google\\Update\\GoogleUpdate.exe", False),
        ("C:\\Program Files (x86)\\App\\app.exe", False),
        ("C:\\ProgramData\\App\\app.exe", False),
        ("powershell.exe", False),
        ("cmd.exe", False),
        ("%SystemRoot%\\system32\\cmd.exe", False),
        # Non-standard — suspicious
        ("D:\\Scripts\\backup.bat", True),
        ("C:\\Users\\Admin\\AppData\\Local\\Temp\\payload.exe", True),
        ("C:\\Temp\\script.exe", True),
    ])
    def test_suspicious_task_path(self, path, expected):
        assert PersistenceAuditorCollector._is_suspicious_task_path(path) == expected


class TestIsSuspiciousRunKeyPath:
    @pytest.mark.parametrize("path,expected", [
        # Standard paths — not suspicious
        ("C:\\Windows\\system32\\SecurityHealthSystray.exe", False),
        ("C:\\Program Files\\App\\app.exe", False),
        # User profile paths — accepted
        ("C:\\Users\\Admin\\AppData\\Local\\Discord\\Update.exe", False),
        # Non-standard drives — suspicious
        ("G:\\Riot Games\\Riot Client\\RiotClientServices.exe", True),
        ("M:\\Steam\\steam.exe", True),
        ("D:\\Tools\\tool.exe", True),
    ])
    def test_suspicious_run_key_path(self, path, expected):
        assert PersistenceAuditorCollector._is_suspicious_run_key_path(path) == expected


class TestAnalyzeTasks:
    def test_elevated_task_finding(self, collector, raw_tasks):
        """Elevated tasks generate MEDIUM findings."""
        tasks = collector._parse_tasks(raw_tasks)
        findings = collector._analyze_tasks(tasks)
        elevated = [f for f in findings if f.category == "elevated_scheduled_task"]
        # WindowsUpdate (Highest, not disabled) + MyBackup (Highest, not disabled) = 2
        # DisabledTask is Highest but disabled — skipped
        names = [f.title for f in elevated]
        assert any("WindowsUpdate" in t for t in names)
        assert any("MyBackup" in t for t in names)
        assert not any("DisabledTask" in t for t in names)

    def test_suspicious_path_finding(self, collector, raw_tasks):
        """Tasks with non-standard executables generate findings."""
        tasks = collector._parse_tasks(raw_tasks)
        findings = collector._analyze_tasks(tasks)
        suspicious = [f for f in findings if f.category == "suspicious_task_path"]
        names = [f.title for f in suspicious]
        # MyBackup (D:\Scripts), SuspiciousTask (C:\Users\...\Temp\)
        assert any("MyBackup" in t for t in names)
        assert any("SuspiciousTask" in t for t in names)

    def test_disabled_task_skipped(self, collector, raw_tasks):
        tasks = collector._parse_tasks(raw_tasks)
        findings = collector._analyze_tasks(tasks)
        disabled = [f for f in findings if "DisabledTask" in f.title]
        assert len(disabled) == 0

    def test_standard_path_task_not_flagged(self, collector, raw_tasks):
        """ChromeUpdate uses C:\\Program Files — not suspicious."""
        tasks = collector._parse_tasks(raw_tasks)
        findings = collector._analyze_tasks(tasks)
        chrome = [f for f in findings if "ChromeUpdate" in f.title]
        assert len(chrome) == 0

    def test_powershell_task_not_flagged_as_suspicious(self, collector, raw_tasks):
        """PowerShellTask uses powershell.exe — standard."""
        tasks = collector._parse_tasks(raw_tasks)
        findings = collector._analyze_tasks(tasks)
        ps_suspicious = [
            f for f in findings
            if "PowerShellTask" in f.title and f.category == "suspicious_task_path"
        ]
        assert len(ps_suspicious) == 0


class TestAnalyzeRunKeys:
    def test_suspicious_run_key_finding(self, collector, raw_run_keys):
        keys = collector._parse_run_keys(raw_run_keys)
        findings = collector._analyze_run_keys(keys)
        suspicious = [f for f in findings if f.category == "suspicious_run_key"]
        # RiotClient (G:\) and Steam (M:\) are non-standard drives
        names = [f.title for f in suspicious]
        assert any("RiotClient" in t for t in names)
        assert any("Steam" in t for t in names)

    def test_standard_path_not_flagged(self, collector, raw_run_keys):
        keys = collector._parse_run_keys(raw_run_keys)
        findings = collector._analyze_run_keys(keys)
        standard = [f for f in findings if "SecurityHealth" in f.title]
        assert len(standard) == 0

    def test_user_profile_not_flagged(self, collector, raw_run_keys):
        """Discord in AppData is a common pattern, not flagged."""
        keys = collector._parse_run_keys(raw_run_keys)
        findings = collector._analyze_run_keys(keys)
        discord = [f for f in findings if "Discord" in f.title]
        assert len(discord) == 0
