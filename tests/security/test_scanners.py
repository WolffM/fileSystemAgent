"""Tests for individual scanner implementations — output parsing and command building.

These tests verify that each scanner correctly:
1. Parses its tool's output format into normalized Finding objects
2. Builds the right CLI command from ScanConfig
"""

import json
import pytest
from pathlib import Path

from src.security.models import (
    Finding,
    ScanConfig,
    ScanResult,
    ScanStatus,
    ScanTarget,
    SeverityLevel,
    ToolInfo,
)
from src.security.tool_manager import ToolManager
from src.security.scanners.clamav import ClamAVScanner
from src.security.scanners.hollows_hunter import HollowsHunterScanner
from src.security.scanners.yara_scanner import YaraScanner
from src.security.scanners.hayabusa import HayabusaScanner
from src.security.scanners.chainsaw import ChainsawScanner
from src.security.scanners.sysinternals import (
    AutorunscScanner,
    SigcheckScanner,
    ListDllsScanner,
)


@pytest.fixture
def mock_tm(tmp_path):
    """ToolManager with all tools 'installed' as fakes."""
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir()
    tm = ToolManager(tools_dir=str(tools_dir))
    # Create fake executables for all tools
    for tool_name, tool_info in tm._tools.items():
        tool_dir = tools_dir / tool_name
        tool_dir.mkdir(exist_ok=True)
        (tool_dir / tool_info.exe_name).write_text("fake")
    return tm


@pytest.fixture
def fixtures_dir():
    return Path(__file__).parent / "fixtures"


def _make_scan_result(tool_name: str, stdout: str = "", output_files: list = None) -> ScanResult:
    """Helper to create a ScanResult with pre-populated output."""
    return ScanResult(
        tool_name=tool_name,
        config=ScanConfig(tool_name=tool_name),
        status=ScanStatus.COMPLETED,
        stdout=stdout,
        output_files=output_files or [],
    )


# ---- ClamAV ----

class TestClamAVScanner:
    def test_parse_output(self, mock_tm, fixtures_dir):
        scanner = ClamAVScanner(mock_tm, config={"update_before_scan": False})
        stdout = (fixtures_dir / "clamscan_output.log").read_text()
        result = _make_scan_result("clamav", stdout=stdout)
        findings = scanner.parse_output(result)

        assert len(findings) == 3
        assert findings[0].title == "ClamAV: Eicar-Signature"
        assert findings[0].severity == SeverityLevel.HIGH
        assert findings[0].category == "malware_signature"
        assert "eicar.txt" in findings[0].target
        assert findings[1].title == "ClamAV: Win.Trojan.Generic-12345"
        assert findings[2].title == "ClamAV: Win.Malware.Agent-67890"

    def test_parse_no_findings(self, mock_tm):
        scanner = ClamAVScanner(mock_tm, config={"update_before_scan": False})
        result = _make_scan_result("clamav", stdout="C:\\clean.txt: OK\n")
        findings = scanner.parse_output(result)
        assert findings == []

    def test_success_return_code(self, mock_tm):
        scanner = ClamAVScanner(mock_tm, config={"update_before_scan": False})
        # ClamAV returns 1 when malware is found (success, not error)
        assert scanner._is_success_return_code(1) is True
        assert scanner._is_success_return_code(0) is False

    def test_build_command(self, mock_tm, tmp_path):
        scanner = ClamAVScanner(mock_tm, config={"update_before_scan": False})
        config = ScanConfig(
            tool_name="clamav",
            target=ScanTarget(target_type="path", target_value="C:\\Users"),
        )
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        cmd = scanner.build_command(config, output_dir)

        assert cmd[0].endswith("clamscan.exe")
        assert "-r" in cmd
        assert "C:\\Users" in cmd
        assert any("--log=" in arg for arg in cmd)


# ---- HollowsHunter ----

class TestHollowsHunterScanner:
    def test_parse_output(self, mock_tm, fixtures_dir, tmp_path):
        scanner = HollowsHunterScanner(mock_tm)

        # Set up output directory mimicking HollowsHunter's output
        output_dir = tmp_path / "hh_output"
        output_dir.mkdir()
        fixture_data = json.loads(
            (fixtures_dir / "hollows_hunter_output.json").read_text()
        )
        (output_dir / "scan_report.json").write_text(json.dumps(fixture_data))

        result = _make_scan_result(
            "hollows_hunter",
            output_files=[str(output_dir / "scan_report.json")],
        )
        findings = scanner.parse_output(result)

        # PID 4567: 2 replaced + 1 implanted = 2 finding types
        # PID 8901: 1 hdr_modified + 3 patched + 2 iat_hooked = 3 finding types
        assert len(findings) == 5

        critical = [f for f in findings if f.severity == SeverityLevel.CRITICAL]
        assert len(critical) == 2  # replaced + implanted

        replaced = [f for f in findings if "replaced" in f.title]
        assert len(replaced) == 1
        assert replaced[0].mitre_attack == "T1055.012"

    def test_build_command_all_processes(self, mock_tm, tmp_path):
        scanner = HollowsHunterScanner(mock_tm)
        config = ScanConfig(
            tool_name="hollows_hunter",
            target=ScanTarget(target_type="system", target_value=""),
        )
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        cmd = scanner.build_command(config, output_dir)

        assert cmd[0].endswith("hollows_hunter.exe")
        assert "/json" in cmd
        assert "/dir" in cmd
        assert "/pid" not in cmd

    def test_build_command_specific_pid(self, mock_tm, tmp_path):
        scanner = HollowsHunterScanner(mock_tm)
        config = ScanConfig(
            tool_name="hollows_hunter",
            target=ScanTarget(target_type="process", target_value="1234"),
        )
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        cmd = scanner.build_command(config, output_dir)

        assert "/pid" in cmd
        assert "1234" in cmd


# ---- YARA-X ----

class TestYaraScanner:
    def test_parse_output(self, mock_tm, fixtures_dir):
        scanner = YaraScanner(mock_tm)
        stdout = (fixtures_dir / "yara_output.json").read_text()
        result = _make_scan_result("yara_x", stdout=stdout)
        findings = scanner.parse_output(result)

        assert len(findings) == 2
        assert findings[0].title == "YARA: APT_Backdoor_Win32"
        assert findings[0].severity == SeverityLevel.CRITICAL
        assert findings[0].mitre_attack == "T1059"
        assert "malware.exe" in findings[0].target

        assert findings[1].title == "YARA: HKTL_Mimikatz"
        assert findings[1].severity == SeverityLevel.HIGH

    def test_parse_empty_output(self, mock_tm):
        scanner = YaraScanner(mock_tm)
        result = _make_scan_result("yara_x", stdout="")
        findings = scanner.parse_output(result)
        assert findings == []

    def test_build_command(self, mock_tm, tmp_path):
        scanner = YaraScanner(mock_tm, config={"rules_dir": str(tmp_path / "rules")})
        config = ScanConfig(
            tool_name="yara_x",
            target=ScanTarget(target_type="path", target_value="C:\\Users"),
        )
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        cmd = scanner.build_command(config, output_dir)

        assert cmd[0].endswith("yr.exe")
        assert "scan" in cmd
        assert "C:\\Users" in cmd
        assert "--output-format" in cmd


# ---- Hayabusa ----

class TestHayabusaScanner:
    def test_parse_output(self, mock_tm, fixtures_dir, tmp_path):
        scanner = HayabusaScanner(mock_tm)

        # Write fixture to a file that looks like Hayabusa output
        csv_text = (fixtures_dir / "hayabusa_output.csv").read_text()
        output_dir = tmp_path / "hayabusa_out"
        output_dir.mkdir()
        csv_file = output_dir / "timeline.csv"
        csv_file.write_text(csv_text)

        result = _make_scan_result(
            "hayabusa",
            output_files=[str(csv_file)],
        )
        findings = scanner.parse_output(result)

        # 5 rows, but info-level is skipped, so 4 findings
        assert len(findings) == 4

        critical = [f for f in findings if f.severity == SeverityLevel.CRITICAL]
        assert len(critical) == 1
        assert "Encoded PowerShell" in critical[0].title

        high = [f for f in findings if f.severity == SeverityLevel.HIGH]
        assert len(high) == 2

    def test_build_command_live(self, mock_tm, tmp_path):
        scanner = HayabusaScanner(mock_tm)
        config = ScanConfig(
            tool_name="hayabusa",
            target=ScanTarget(target_type="eventlog", target_value="live"),
        )
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        cmd = scanner.build_command(config, output_dir)

        assert cmd[0].endswith("hayabusa.exe")
        assert "csv-timeline" in cmd
        assert "--no-wizard" in cmd
        assert "-l" in cmd
        assert "-q" in cmd

    def test_build_command_offline(self, mock_tm, tmp_path):
        scanner = HayabusaScanner(mock_tm)
        config = ScanConfig(
            tool_name="hayabusa",
            target=ScanTarget(
                target_type="eventlog",
                target_value="C:\\evtx_files",
            ),
        )
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        cmd = scanner.build_command(config, output_dir)

        assert "-d" in cmd
        assert "C:\\evtx_files" in cmd
        assert "-l" not in cmd


# ---- Chainsaw ----

class TestChainsawScanner:
    def test_parse_output(self, mock_tm, fixtures_dir, tmp_path):
        scanner = ChainsawScanner(mock_tm)

        output_dir = tmp_path / "chainsaw_out"
        output_dir.mkdir()
        json_file = output_dir / "results.json"
        json_file.write_text((fixtures_dir / "chainsaw_output.json").read_text())

        result = _make_scan_result(
            "chainsaw",
            output_files=[str(json_file)],
        )
        findings = scanner.parse_output(result)

        # 3 detections in fixture, but informational is skipped
        assert len(findings) == 2

        critical = [f for f in findings if f.severity == SeverityLevel.CRITICAL]
        assert len(critical) == 1
        assert "Event Log Clearing" in critical[0].title

        high = [f for f in findings if f.severity == SeverityLevel.HIGH]
        assert len(high) == 1
        assert "PowerShell" in high[0].title

    def test_build_command(self, mock_tm, tmp_path):
        scanner = ChainsawScanner(mock_tm)
        config = ScanConfig(
            tool_name="chainsaw",
            target=ScanTarget(
                target_type="path",
                target_value="C:\\Windows\\System32\\winevt\\Logs",
            ),
        )
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        cmd = scanner.build_command(config, output_dir)

        assert cmd[0].endswith("chainsaw.exe")
        assert "hunt" in cmd
        assert "--json" in cmd


# ---- Autorunsc ----

class TestAutorunscScanner:
    def test_parse_output(self, mock_tm, fixtures_dir):
        scanner = AutorunscScanner(mock_tm)
        stdout = (fixtures_dir / "autorunsc_output.csv").read_text()
        result = _make_scan_result("autorunsc", stdout=stdout)
        findings = scanner.parse_output(result)

        # SuspiciousService: not verified + VT hit = 2 findings
        # MicrosoftUpdate: verified, 0|0 VT = 0 findings
        # ShadyHelper: not verified, no VT = 1 finding
        assert len(findings) == 3

        critical = [f for f in findings if f.severity == SeverityLevel.CRITICAL]
        assert len(critical) == 1
        assert "VT hit" in critical[0].title

        unsigned = [f for f in findings if "unsigned" in f.title.lower()]
        assert len(unsigned) == 2

    def test_build_command(self, mock_tm, tmp_path):
        scanner = AutorunscScanner(mock_tm)
        config = ScanConfig(tool_name="autorunsc")
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        cmd = scanner.build_command(config, output_dir)

        assert cmd[0].endswith("autorunsc64.exe")
        assert "-a" in cmd
        assert "-c" in cmd
        assert "-accepteula" in cmd


# ---- Sigcheck ----

class TestSigcheckScanner:
    def test_parse_output(self, mock_tm, fixtures_dir):
        scanner = SigcheckScanner(mock_tm)
        stdout = (fixtures_dir / "sigcheck_output.csv").read_text()
        result = _make_scan_result("sigcheck", stdout=stdout)
        findings = scanner.parse_output(result)

        # 2 unsigned files in fixture
        assert len(findings) == 2
        assert all(f.severity == SeverityLevel.MEDIUM for f in findings)
        assert all(f.category == "unsigned_binary" for f in findings)

        targets = [f.target for f in findings]
        assert "C:\\Windows\\System32\\evil.dll" in targets
        assert "C:\\Windows\\System32\\suspicious.sys" in targets

    def test_build_command(self, mock_tm, tmp_path):
        scanner = SigcheckScanner(mock_tm)
        config = ScanConfig(
            tool_name="sigcheck",
            target=ScanTarget(target_type="path", target_value="C:\\Windows"),
        )
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        cmd = scanner.build_command(config, output_dir)

        assert cmd[0].endswith("sigcheck64.exe")
        assert "-u" in cmd
        assert "-e" in cmd
        assert "-c" in cmd
        assert "C:\\Windows" in cmd


# ---- ListDLLs ----

class TestListDllsScanner:
    def test_parse_output(self, mock_tm, fixtures_dir):
        scanner = ListDllsScanner(mock_tm)
        stdout = (fixtures_dir / "listdlls_output.txt").read_text()
        result = _make_scan_result("listdlls", stdout=stdout)
        findings = scanner.parse_output(result)

        # 3 unsigned DLLs in fixture
        assert len(findings) == 3
        assert all(f.severity == SeverityLevel.MEDIUM for f in findings)
        assert all(f.category == "unsigned_dll" for f in findings)

        # Check process attribution
        explorer_findings = [
            f for f in findings if f.raw_data.get("process") == "explorer.exe"
        ]
        assert len(explorer_findings) == 2

        svchost_findings = [
            f for f in findings if f.raw_data.get("process") == "svchost.exe"
        ]
        assert len(svchost_findings) == 1

    def test_parse_empty_output(self, mock_tm):
        scanner = ListDllsScanner(mock_tm)
        result = _make_scan_result("listdlls", stdout="")
        findings = scanner.parse_output(result)
        assert findings == []

    def test_build_command(self, mock_tm, tmp_path):
        scanner = ListDllsScanner(mock_tm)
        config = ScanConfig(tool_name="listdlls")
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        cmd = scanner.build_command(config, output_dir)

        assert cmd[0].endswith("listdlls64.exe")
        assert "-u" in cmd
        assert "-accepteula" in cmd
