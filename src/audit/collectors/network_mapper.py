"""Network mapper collector — TCP connection inventory with RFC1918 classification."""

import json
import logging
from datetime import datetime
from typing import Any, Dict, List

from ..collector_base import CollectorBase
from ..models import (
    CollectorConfig,
    CollectorResult,
    Finding,
    NetworkConnection,
    ScanStatus,
    SeverityLevel,
)

logger = logging.getLogger(__name__)

_PS_NETWORK_SCRIPT = r"""
$conns = Get-NetTCPConnection -ErrorAction SilentlyContinue |
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort,
                  State, OwningProcess
$procs = @{}
Get-CimInstance Win32_Process | ForEach-Object {
    $procs[$_.ProcessId] = $_.Name
}
$conns | ForEach-Object {
    $_ | Add-Member -NotePropertyName ProcessName `
         -NotePropertyValue $procs[$_.OwningProcess] -PassThru
} | ConvertTo-Json -Depth 3 -Compress
"""

# TCP State enum values from Windows MIB_TCP_STATE
# (Get-NetTCPConnection returns integers when serialized via Select-Object + ConvertTo-Json)
_TCP_STATE_MAP = {
    1: "Closed",
    2: "Listen",
    3: "SynSent",
    4: "SynReceived",
    5: "Established",
    6: "FinWait1",
    7: "FinWait2",
    8: "CloseWait",
    9: "Closing",
    10: "LastAck",
    11: "TimeWait",
    12: "DeleteTCB",
    100: "Bound",
}


class NetworkMapperCollector(CollectorBase):
    """Collects TCP connection inventory and classifies external connections."""

    @property
    def collector_name(self) -> str:
        return "network_mapper"

    async def collect(
        self, config: CollectorConfig, context: Dict[str, Any]
    ) -> CollectorResult:
        result = CollectorResult(
            collector_name=self.collector_name,
            started_at=datetime.now(),
        )

        try:
            stdout = await self._run_powershell(
                _PS_NETWORK_SCRIPT, timeout=config.timeout
            )
            raw_conns = json.loads(stdout)
            if isinstance(raw_conns, dict):
                raw_conns = [raw_conns]

            connections = self._parse_connections(raw_conns)
            findings = self._analyze(connections)

            result.status = ScanStatus.COMPLETED
            result.data = {
                "connections": [c.model_dump() for c in connections],
                "count": len(connections),
                "listening": sum(1 for c in connections if c.state == "Listen"),
                "established": sum(
                    1 for c in connections if c.state == "Established"
                ),
            }
            result.findings = findings

        except Exception as e:
            result.status = ScanStatus.FAILED
            result.error_message = str(e)
            logger.error(f"Network mapping failed: {e}", exc_info=True)

        result.completed_at = datetime.now()
        if result.started_at:
            result.duration_seconds = (
                result.completed_at - result.started_at
            ).total_seconds()
        return result

    def _parse_connections(self, raw: List[dict]) -> List[NetworkConnection]:
        """Parse PowerShell Get-NetTCPConnection JSON into NetworkConnection models."""
        connections = []
        for entry in raw:
            try:
                state_raw = entry.get("State", 0)
                if isinstance(state_raw, int):
                    state = _TCP_STATE_MAP.get(state_raw, f"Unknown({state_raw})")
                else:
                    state = str(state_raw)

                remote_addr = entry.get("RemoteAddress") or ""
                local_addr = entry.get("LocalAddress") or ""

                conn = NetworkConnection(
                    local_address=local_addr,
                    local_port=entry.get("LocalPort", 0),
                    remote_address=remote_addr or None,
                    remote_port=entry.get("RemotePort") or None,
                    state=state,
                    pid=entry.get("OwningProcess", 0),
                    process_name=entry.get("ProcessName"),
                    is_outbound_external=self._is_external(remote_addr),
                )
                connections.append(conn)
            except Exception as e:
                logger.debug(f"Skipping connection entry: {e}")
        return connections

    def _analyze(self, connections: List[NetworkConnection]) -> List[Finding]:
        """Generate findings from connection data."""
        findings = []

        # Group external connections by process
        external_by_proc: Dict[int, List[NetworkConnection]] = {}
        for conn in connections:
            if conn.is_outbound_external and conn.state == "Established":
                external_by_proc.setdefault(conn.pid, []).append(conn)

        for pid, conns in external_by_proc.items():
            proc_name = conns[0].process_name or f"PID {pid}"
            remote_addrs = list({c.remote_address for c in conns if c.remote_address})

            # Flag processes with many external connections
            if len(conns) >= 10:
                findings.append(Finding(
                    tool_name=self.collector_name,
                    severity=SeverityLevel.MEDIUM,
                    category="many_external_connections",
                    title=f"Many external connections: {proc_name}",
                    description=(
                        f"Process {proc_name} (PID {pid}) has "
                        f"{len(conns)} established external connections "
                        f"to {len(remote_addrs)} unique addresses."
                    ),
                    target=proc_name,
                    raw_data={
                        "pid": pid,
                        "process_name": proc_name,
                        "connection_count": len(conns),
                        "remote_addresses": remote_addrs[:20],
                    },
                ))

        # Listening on non-standard ports
        listening = [c for c in connections if c.state == "Listen"]
        for conn in listening:
            if self._is_suspicious_listener(conn):
                proc_name = conn.process_name or f"PID {conn.pid}"
                findings.append(Finding(
                    tool_name=self.collector_name,
                    severity=SeverityLevel.LOW,
                    category="suspicious_listener",
                    title=f"Unusual listener: {proc_name} on port {conn.local_port}",
                    description=(
                        f"Process {proc_name} (PID {conn.pid}) is listening "
                        f"on {conn.local_address}:{conn.local_port}."
                    ),
                    target=f"{conn.local_address}:{conn.local_port}",
                    raw_data=conn.model_dump(),
                ))

        return findings

    @staticmethod
    def _is_external(address: str) -> bool:
        """Check if an address is external (not RFC1918, loopback, or link-local).

        RFC1918 ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
        Also treats IPv6 loopback/link-local/zero as internal.
        """
        if not address:
            return False

        addr = address.strip()

        # IPv6 non-external
        if ":" in addr:
            # ::1 (loopback), :: (any), fe80: (link-local), fd/fc (ULA)
            if addr in ("::", "::1"):
                return False
            lower = addr.lower()
            if lower.startswith("fe80:") or lower.startswith("fd") or lower.startswith("fc"):
                return False
            # Other IPv6 — treat as external
            return True

        # IPv4 classification
        parts = addr.split(".")
        if len(parts) != 4:
            return False

        try:
            octets = [int(p) for p in parts]
        except ValueError:
            return False

        # Loopback 127.0.0.0/8
        if octets[0] == 127:
            return False
        # 0.0.0.0
        if octets[0] == 0:
            return False
        # 10.0.0.0/8
        if octets[0] == 10:
            return False
        # 172.16.0.0/12
        if octets[0] == 172 and 16 <= octets[1] <= 31:
            return False
        # 192.168.0.0/16
        if octets[0] == 192 and octets[1] == 168:
            return False
        # 169.254.0.0/16 (link-local)
        if octets[0] == 169 and octets[1] == 254:
            return False

        return True

    @staticmethod
    def _is_suspicious_listener(conn: NetworkConnection) -> bool:
        """Check if a listening connection is on a suspicious port.

        We flag listeners that bind to all interfaces (0.0.0.0 or ::)
        on high ports (>= 1024) that aren't well-known services.
        """
        # Only flag wildcard listeners on non-loopback
        addr = conn.local_address
        is_wildcard = addr in ("0.0.0.0", "::", "[::]")
        if not is_wildcard:
            return False

        # Well-known service ports to exclude
        _COMMON_PORTS = {
            80, 443, 445, 135, 139, 993, 995, 587, 25,
            3389,  # RDP
            5985, 5986,  # WinRM
            1433,  # SQL Server
            3306,  # MySQL
            5432,  # PostgreSQL
            8080, 8443,  # Common HTTP alt
        }
        if conn.local_port in _COMMON_PORTS:
            return False

        # High ports on wildcard address are suspicious
        return conn.local_port >= 1024
