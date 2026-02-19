"""Tests for NetworkMapperCollector — parsing, RFC1918 classification, and analysis."""

import json
import pytest
from pathlib import Path

from src.audit.collectors.network_mapper import NetworkMapperCollector
from src.audit.models import SeverityLevel

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def collector():
    return NetworkMapperCollector()


@pytest.fixture
def raw_connections():
    return json.loads((FIXTURES / "tcp_connection_output.json").read_text())


class TestParseConnections:
    def test_parse_all_entries(self, collector, raw_connections):
        conns = collector._parse_connections(raw_connections)
        assert len(conns) == 11

    def test_state_enum_to_string(self, collector, raw_connections):
        """Integer state values are mapped to human-readable strings."""
        conns = collector._parse_connections(raw_connections)
        listen = [c for c in conns if c.state == "Listen"]
        established = [c for c in conns if c.state == "Established"]
        assert len(listen) == 3  # ports 80, 49152, 9999
        assert len(established) == 8

    def test_process_name_preserved(self, collector, raw_connections):
        conns = collector._parse_connections(raw_connections)
        chrome = [c for c in conns if c.process_name == "chrome.exe"]
        assert len(chrome) == 2

    def test_external_flag_set(self, collector, raw_connections):
        """External connections are flagged correctly."""
        conns = collector._parse_connections(raw_connections)
        external = [c for c in conns if c.is_outbound_external]
        # 93.184.216.34 (x2) + 203.0.113.50 (x1) = 3 external
        assert len(external) == 3

    def test_loopback_not_external(self, collector, raw_connections):
        conns = collector._parse_connections(raw_connections)
        loopback = [c for c in conns if c.local_address == "127.0.0.1"]
        for c in loopback:
            assert c.is_outbound_external is False

    def test_rfc1918_not_external(self, collector, raw_connections):
        """192.168.x.x and 10.x.x.x connections are not external."""
        conns = collector._parse_connections(raw_connections)
        internal = next(c for c in conns if c.remote_address == "192.168.1.1")
        assert internal.is_outbound_external is False
        internal10 = next(c for c in conns if c.remote_address == "10.0.0.1")
        assert internal10.is_outbound_external is False

    def test_string_state_passthrough(self, collector):
        """If state is already a string, pass it through."""
        raw = [{"LocalAddress": "0.0.0.0", "LocalPort": 80,
                "RemoteAddress": "0.0.0.0", "RemotePort": 0,
                "State": "Listen", "OwningProcess": 4}]
        conns = collector._parse_connections(raw)
        assert conns[0].state == "Listen"

    def test_unknown_state_number(self, collector):
        """Unknown state number gets formatted."""
        raw = [{"LocalAddress": "0.0.0.0", "LocalPort": 80,
                "RemoteAddress": "0.0.0.0", "RemotePort": 0,
                "State": 99, "OwningProcess": 4}]
        conns = collector._parse_connections(raw)
        assert conns[0].state == "Unknown(99)"


class TestIsExternal:
    @pytest.mark.parametrize("addr,expected", [
        # External IPv4
        ("8.8.8.8", True),
        ("93.184.216.34", True),
        ("203.0.113.50", True),
        ("1.1.1.1", True),
        # RFC1918
        ("10.0.0.1", False),
        ("10.255.255.255", False),
        ("172.16.0.1", False),
        ("172.31.255.255", False),
        ("192.168.0.1", False),
        ("192.168.255.255", False),
        # Not RFC1918 (172 outside /12)
        ("172.15.0.1", True),
        ("172.32.0.1", True),
        # Loopback
        ("127.0.0.1", False),
        ("127.255.255.255", False),
        # Zero
        ("0.0.0.0", False),
        # Link-local
        ("169.254.1.1", False),
        # IPv6
        ("::1", False),
        ("::", False),
        ("fe80::1", False),
        ("fd00::1", False),
        ("fc00::1", False),
        ("2001:db8::1", True),  # documentation range, but treated as external
        # Empty/invalid
        ("", False),
        ("not-an-ip", False),
    ])
    def test_is_external(self, addr, expected):
        assert NetworkMapperCollector._is_external(addr) == expected


class TestIsSuspiciousListener:
    def test_wildcard_high_port_suspicious(self, collector):
        from src.audit.models import NetworkConnection
        conn = NetworkConnection(
            local_address="0.0.0.0", local_port=9999,
            state="Listen", pid=100,
        )
        assert collector._is_suspicious_listener(conn) is True

    def test_wildcard_ipv6_suspicious(self, collector):
        from src.audit.models import NetworkConnection
        conn = NetworkConnection(
            local_address="::", local_port=4444,
            state="Listen", pid=100,
        )
        assert collector._is_suspicious_listener(conn) is True

    def test_wildcard_common_port_not_suspicious(self, collector):
        from src.audit.models import NetworkConnection
        conn = NetworkConnection(
            local_address="0.0.0.0", local_port=80,
            state="Listen", pid=100,
        )
        assert collector._is_suspicious_listener(conn) is False

    def test_localhost_listener_not_suspicious(self, collector):
        from src.audit.models import NetworkConnection
        conn = NetworkConnection(
            local_address="127.0.0.1", local_port=9999,
            state="Listen", pid=100,
        )
        assert collector._is_suspicious_listener(conn) is False

    def test_specific_ip_listener_not_suspicious(self, collector):
        from src.audit.models import NetworkConnection
        conn = NetworkConnection(
            local_address="192.168.1.100", local_port=9999,
            state="Listen", pid=100,
        )
        assert collector._is_suspicious_listener(conn) is False


class TestAnalyze:
    def test_suspicious_listener_finding(self, collector, raw_connections):
        """Wildcard listener on high port generates finding."""
        conns = collector._parse_connections(raw_connections)
        findings = collector._analyze(conns)
        listeners = [f for f in findings if f.category == "suspicious_listener"]
        # Port 49152 on 0.0.0.0 and port 9999 on :: should be flagged
        assert len(listeners) == 2
        ports = [f.target for f in listeners]
        assert "0.0.0.0:49152" in ports
        assert ":::9999" in ports

    def test_common_port_listener_not_flagged(self, collector, raw_connections):
        """Port 80 on 0.0.0.0 should NOT be flagged."""
        conns = collector._parse_connections(raw_connections)
        findings = collector._analyze(conns)
        port80 = [f for f in findings if "port 80" in f.title]
        assert len(port80) == 0

    def test_many_external_not_triggered_below_threshold(self, collector, raw_connections):
        """Chrome has 2 external connections — below threshold of 10."""
        conns = collector._parse_connections(raw_connections)
        findings = collector._analyze(conns)
        many = [f for f in findings if f.category == "many_external_connections"]
        assert len(many) == 0

    def test_many_external_triggered_above_threshold(self, collector):
        """Process with 10+ external connections triggers finding."""
        from src.audit.models import NetworkConnection
        conns = [
            NetworkConnection(
                local_address="192.168.1.100", local_port=55000 + i,
                remote_address=f"93.184.216.{i}", remote_port=443,
                state="Established", pid=9000,
                process_name="chatty.exe",
                is_outbound_external=True,
            )
            for i in range(12)
        ]
        findings = collector._analyze(conns)
        many = [f for f in findings if f.category == "many_external_connections"]
        assert len(many) == 1
        assert many[0].severity == SeverityLevel.MEDIUM
        assert "chatty.exe" in many[0].title

    def test_total_finding_count(self, collector, raw_connections):
        """Total findings from fixture data."""
        conns = collector._parse_connections(raw_connections)
        findings = collector._analyze(conns)
        # 2 suspicious listeners (49152, 9999) + 0 many_external = 2
        assert len(findings) == 2
