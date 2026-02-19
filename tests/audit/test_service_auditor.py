"""Tests for ServiceAuditorCollector — parsing and vulnerability analysis."""

import json
import pytest
from pathlib import Path

from src.audit.collectors.service_auditor import ServiceAuditorCollector
from src.audit.models import SeverityLevel

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def collector():
    return ServiceAuditorCollector()


@pytest.fixture
def raw_services():
    return json.loads((FIXTURES / "win32_service_output.json").read_text())


class TestParseServices:
    def test_parse_all_entries(self, collector, raw_services):
        services = collector._parse_services(raw_services)
        assert len(services) == 7

    def test_basic_fields(self, collector, raw_services):
        services = collector._parse_services(raw_services)
        wuauserv = next(s for s in services if s.name == "wuauserv")
        assert wuauserv.display_name == "Windows Update"
        assert wuauserv.state == "Running"
        assert wuauserv.start_mode == "Manual"
        assert wuauserv.account == "LocalSystem"

    def test_null_path_handled(self, collector, raw_services):
        """Services with null PathName have binary_path = None."""
        services = collector._parse_services(raw_services)
        null_svc = next(s for s in services if s.name == "NullPathSvc")
        assert null_svc.binary_path is None

    def test_unquoted_path_detected(self, collector, raw_services):
        """VulnSvc has unquoted path with spaces."""
        services = collector._parse_services(raw_services)
        vuln = next(s for s in services if s.name == "VulnSvc")
        assert vuln.unquoted_path is True

    def test_quoted_path_not_flagged(self, collector, raw_services):
        """WeirdSvc has a quoted path."""
        services = collector._parse_services(raw_services)
        weird = next(s for s in services if s.name == "WeirdSvc")
        assert weird.unquoted_path is False

    def test_non_standard_location_detected(self, collector, raw_services):
        """WeirdSvc is in D:\\CustomTools — non-standard."""
        services = collector._parse_services(raw_services)
        weird = next(s for s in services if s.name == "WeirdSvc")
        assert weird.non_standard_binary_location is True

    def test_standard_location_not_flagged(self, collector, raw_services):
        services = collector._parse_services(raw_services)
        spooler = next(s for s in services if s.name == "Spooler")
        assert spooler.non_standard_binary_location is False


class TestHasUnquotedPath:
    @pytest.mark.parametrize("path,expected", [
        # Unquoted with spaces
        ("C:\\Program Files\\My App\\service.exe", True),
        ("C:\\Program Files\\Vulnerable App\\My Service\\service.exe -run", True),
        # Quoted — safe
        ('"C:\\Program Files\\My App\\service.exe"', False),
        ('"C:\\Program Files\\App\\svc.exe" -arg', False),
        # No spaces — safe
        ("C:\\Windows\\System32\\svchost.exe", False),
        ("C:\\svchost.exe -k netsvcs", False),
        # Empty/null
        ("", False),
        ("   ", False),
    ])
    def test_unquoted_detection(self, path, expected):
        assert ServiceAuditorCollector._has_unquoted_path(path) == expected


class TestIsNonStandard:
    @pytest.mark.parametrize("path,expected", [
        ("C:\\Windows\\System32\\svchost.exe", False),
        ("C:\\Program Files\\App\\app.exe", False),
        ("C:\\Program Files (x86)\\App\\app.exe", False),
        ("C:\\ProgramData\\service\\svc.exe", False),
        ("D:\\Tools\\service.exe", True),
        ("C:\\Users\\Admin\\service.exe", True),
        ('"D:\\Tools\\service.exe"', True),  # quoted but still non-standard
        ("", False),  # empty returns False
    ])
    def test_non_standard_detection(self, path, expected):
        assert ServiceAuditorCollector._is_non_standard(path) == expected


class TestIsSystemAccount:
    @pytest.mark.parametrize("account,expected", [
        ("LocalSystem", True),
        ("Local System", True),
        ("NT AUTHORITY\\SYSTEM", True),
        ("nt authority\\system", True),
        ("NT SERVICE\\SafeSvc", False),
        ("DOMAIN\\serviceaccount", False),
        ("NetworkService", False),
    ])
    def test_system_account_detection(self, account, expected):
        assert ServiceAuditorCollector._is_system_account(account) == expected


class TestAnalyze:
    def test_unquoted_path_finding(self, collector, raw_services):
        """Unquoted path with spaces generates HIGH finding."""
        services = collector._parse_services(raw_services)
        findings = collector._analyze(services)
        unquoted = [f for f in findings if f.category == "unquoted_service_path"]
        assert len(unquoted) == 1
        assert unquoted[0].severity == SeverityLevel.HIGH
        assert "VulnSvc" in unquoted[0].title
        assert unquoted[0].mitre_attack == "T1574.009"

    def test_system_non_standard_finding(self, collector, raw_services):
        """SYSTEM service in non-standard location generates MEDIUM finding."""
        services = collector._parse_services(raw_services)
        findings = collector._analyze(services)
        non_std = [f for f in findings if f.category == "system_service_non_standard"]
        assert len(non_std) == 1
        assert non_std[0].severity == SeverityLevel.MEDIUM
        assert "WeirdSvc" in non_std[0].title

    def test_non_system_non_standard_not_flagged(self, collector, raw_services):
        """Non-SYSTEM service in non-standard location is not flagged."""
        services = collector._parse_services(raw_services)
        findings = collector._analyze(services)
        # UserSvc runs as DOMAIN\serviceaccount, non-standard path, but not SYSTEM
        user_findings = [f for f in findings if "UserSvc" in f.title]
        assert len(user_findings) == 0

    def test_stopped_system_service_not_flagged(self, collector):
        """Stopped service is not flagged for non-standard path."""
        from src.audit.models import ServiceInfo
        services = [ServiceInfo(
            name="StoppedSvc", display_name="Stopped",
            state="Stopped", start_mode="Manual",
            binary_path="D:\\Tools\\svc.exe",
            account="LocalSystem",
            non_standard_binary_location=True,
        )]
        findings = collector._analyze(services)
        non_std = [f for f in findings if f.category == "system_service_non_standard"]
        assert len(non_std) == 0

    def test_null_path_skipped(self, collector, raw_services):
        """Services with no binary path produce no findings."""
        services = collector._parse_services(raw_services)
        findings = collector._analyze(services)
        null_findings = [f for f in findings if "NullPathSvc" in f.title]
        assert len(null_findings) == 0

    def test_total_finding_count(self, collector, raw_services):
        """Total findings from fixture data."""
        services = collector._parse_services(raw_services)
        findings = collector._analyze(services)
        # 1 unquoted path (VulnSvc) + 1 SYSTEM non-standard (WeirdSvc) = 2
        assert len(findings) == 2
