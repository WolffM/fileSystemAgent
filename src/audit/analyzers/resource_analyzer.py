"""Resource analyzer — ranks processes by resource usage and flags anomalies.

Consumes process_snapshot and service_auditor data from the pipeline context.
Focuses on objective signals: high resource usage, unsigned SYSTEM services,
excessive handle/thread counts.
"""

import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set

from ..analyzer_base import AnalyzerBase
from ..models import (
    AnalyzerConfig,
    AnalyzerResult,
    Finding,
    FindingDomain,
    ProcessInfo,
    ScanStatus,
    ServiceInfo,
    SeverityLevel,
)

logger = logging.getLogger(__name__)

# Thresholds for resource anomaly detection
_DEFAULT_TOP_N = 10
_HIGH_RAM_MB = 1024  # 1 GB
_HIGH_CPU_SECONDS = 3600  # 1 hour of cumulative CPU time
_HIGH_THREAD_COUNT = 200
_HIGH_HANDLE_COUNT = 5000
_STALE_HOURS = 168  # 7 days
_ORPHAN_STALE_HOURS = 24  # 1 day — orphan must also be this old to be flagged

# Processes expected to run indefinitely — skip for stale/orphan detection
_KNOWN_LONG_RUNNING = frozenset({
    "system", "system idle process", "smss.exe", "csrss.exe",
    "wininit.exe", "services.exe", "lsass.exe", "svchost.exe",
    "dwm.exe", "explorer.exe", "winlogon.exe", "fontdrvhost.exe",
    "memory compression", "registry", "sihost.exe", "taskhostw.exe",
    "runtimebroker.exe", "dllhost.exe", "conhost.exe",
    "searchhost.exe", "startmenuexperiencehost.exe",
    "textinputhost.exe", "shellexperiencehost.exe",
    "spoolsv.exe", "wudfhost.exe", "ctfmon.exe",
    "securityhealthservice.exe", "msmpeng.exe",
    "sgrmbroker.exe", "msdtc.exe", "lsm.exe",
})


class ResourceAnalyzer(AnalyzerBase):
    """Analyzes process and service data for resource anomalies."""

    @property
    def analyzer_name(self) -> str:
        return "resource_analyzer"

    async def analyze(
        self, config: AnalyzerConfig, context: Dict[str, Any]
    ) -> AnalyzerResult:
        result = AnalyzerResult(
            analyzer_name=self.analyzer_name,
            started_at=datetime.now(),
        )

        processes = self._load_processes(context)
        services = self._load_services(context)

        if not processes and not services:
            result.status = ScanStatus.COMPLETED
            result.data = {"skipped": True, "reason": "No process or service data in context"}
            result.completed_at = datetime.now()
            return result

        findings: List[Finding] = []
        top_n = config.extra_args.get("top_n", _DEFAULT_TOP_N)

        # Rank processes by RAM
        top_ram = self._top_by_ram(processes, top_n)
        # Rank processes by thread count
        top_threads = self._top_by_threads(processes, top_n)
        # Rank processes by handle count
        top_handles = self._top_by_handles(processes, top_n)

        # Generate findings for anomalies
        findings.extend(self._find_resource_hogs(processes))
        findings.extend(self._find_unsigned_system_services(services))

        # Hygiene checks
        stale_findings, stale_procs = self._find_stale_processes(processes)
        orphan_findings, orphan_procs = self._find_orphan_processes(processes)
        findings.extend(stale_findings)
        findings.extend(orphan_findings)

        result.status = ScanStatus.COMPLETED
        result.data = {
            "top_ram": [p.model_dump() for p in top_ram],
            "top_threads": [p.model_dump() for p in top_threads],
            "top_handles": [p.model_dump() for p in top_handles],
            "stale_processes": [p.model_dump() for p in stale_procs],
            "orphan_processes": [p.model_dump() for p in orphan_procs],
            "process_count": len(processes),
            "service_count": len(services),
        }
        result.findings = findings
        result.completed_at = datetime.now()
        return result

    @staticmethod
    def _load_processes(context: Dict[str, Any]) -> List[ProcessInfo]:
        """Load ProcessInfo list from pipeline context."""
        ps_data = context.get("process_snapshot", {})
        raw_procs = ps_data.get("processes", [])
        return [ProcessInfo.model_validate(p) for p in raw_procs]

    @staticmethod
    def _load_services(context: Dict[str, Any]) -> List[ServiceInfo]:
        """Load ServiceInfo list from pipeline context."""
        svc_data = context.get("service_auditor", {})
        raw_svcs = svc_data.get("services", [])
        return [ServiceInfo.model_validate(s) for s in raw_svcs]

    @staticmethod
    def _top_by_ram(
        processes: List[ProcessInfo], n: int
    ) -> List[ProcessInfo]:
        """Return top N processes by RAM usage."""
        return sorted(processes, key=lambda p: p.ram_mb, reverse=True)[:n]

    @staticmethod
    def _top_by_threads(
        processes: List[ProcessInfo], n: int
    ) -> List[ProcessInfo]:
        """Return top N processes by thread count."""
        return sorted(processes, key=lambda p: p.thread_count, reverse=True)[:n]

    @staticmethod
    def _top_by_handles(
        processes: List[ProcessInfo], n: int
    ) -> List[ProcessInfo]:
        """Return top N processes by handle count."""
        return sorted(processes, key=lambda p: p.handle_count, reverse=True)[:n]

    @staticmethod
    def _find_resource_hogs(processes: List[ProcessInfo]) -> List[Finding]:
        """Flag processes with excessive resource usage."""
        findings = []

        for proc in processes:
            if proc.pid <= 4:
                continue

            if proc.ram_mb > _HIGH_RAM_MB:
                findings.append(Finding(
                    tool_name="resource_analyzer",
                    severity=SeverityLevel.LOW,
                    category="high_ram_usage",
                    title=f"High memory: {proc.name} ({proc.ram_mb:.0f} MB)",
                    description=(
                        f"Process {proc.name} (PID {proc.pid}) is using "
                        f"{proc.ram_mb:.0f} MB of RAM."
                    ),
                    target=proc.path or proc.name,
                    domain=FindingDomain.PERFORMANCE,
                    raw_data=proc.model_dump(),
                ))

            if proc.cpu_percent > _HIGH_CPU_SECONDS:
                findings.append(Finding(
                    tool_name="resource_analyzer",
                    severity=SeverityLevel.LOW,
                    category="high_cpu_usage",
                    title=f"High CPU time: {proc.name} ({proc.cpu_percent:.0f}s)",
                    description=(
                        f"Process {proc.name} (PID {proc.pid}) has consumed "
                        f"{proc.cpu_percent:.0f} seconds of CPU time."
                    ),
                    target=proc.path or proc.name,
                    domain=FindingDomain.PERFORMANCE,
                    raw_data=proc.model_dump(),
                ))

            if proc.thread_count > _HIGH_THREAD_COUNT:
                findings.append(Finding(
                    tool_name="resource_analyzer",
                    severity=SeverityLevel.LOW,
                    category="high_thread_count",
                    title=f"High thread count: {proc.name} ({proc.thread_count})",
                    description=(
                        f"Process {proc.name} (PID {proc.pid}) has "
                        f"{proc.thread_count} threads, which may indicate "
                        f"a thread leak or resource issue."
                    ),
                    target=proc.path or proc.name,
                    domain=FindingDomain.PERFORMANCE,
                    raw_data=proc.model_dump(),
                ))

            if proc.handle_count > _HIGH_HANDLE_COUNT:
                findings.append(Finding(
                    tool_name="resource_analyzer",
                    severity=SeverityLevel.LOW,
                    category="high_handle_count",
                    title=f"High handle count: {proc.name} ({proc.handle_count})",
                    description=(
                        f"Process {proc.name} (PID {proc.pid}) has "
                        f"{proc.handle_count} handles, which may indicate "
                        f"a handle leak."
                    ),
                    target=proc.path or proc.name,
                    domain=FindingDomain.PERFORMANCE,
                    raw_data=proc.model_dump(),
                ))

        return findings

    @staticmethod
    def _find_unsigned_system_services(
        services: List[ServiceInfo],
    ) -> List[Finding]:
        """Flag services running as SYSTEM with suspicious characteristics."""
        findings = []

        for svc in services:
            if svc.state != "Running":
                continue

            account_lower = svc.account.lower()
            is_system = any(
                s in account_lower
                for s in ("localsystem", "local system", "nt authority\\system")
            )
            if not is_system:
                continue

            if svc.system_with_writable_binary:
                findings.append(Finding(
                    tool_name="resource_analyzer",
                    severity=SeverityLevel.HIGH,
                    category="system_writable_binary",
                    title=f"SYSTEM service with writable binary: {svc.name}",
                    description=(
                        f"Service '{svc.display_name}' runs as {svc.account} "
                        f"with a writable binary path: {svc.binary_path}. "
                        f"This could allow privilege escalation."
                    ),
                    target=svc.binary_path or svc.name,
                    raw_data=svc.model_dump(),
                    mitre_attack="T1574.010",
                ))

        return findings

    @staticmethod
    def _parse_wmi_date(date_str: Optional[str]) -> Optional[datetime]:
        """Parse a WMI date string (/Date(millis)/) into a datetime."""
        if not date_str:
            return None
        m = re.search(r"/Date\((\d+)\)", str(date_str))
        if m:
            millis = int(m.group(1))
            return datetime.fromtimestamp(millis / 1000, tz=timezone.utc)
        return None

    @classmethod
    def _find_stale_processes(
        cls, processes: List[ProcessInfo]
    ) -> tuple[List[Finding], List[ProcessInfo]]:
        """Flag non-system processes running longer than _STALE_HOURS."""
        findings = []
        stale = []
        now = datetime.now(tz=timezone.utc)
        threshold = timedelta(hours=_STALE_HOURS)

        for proc in processes:
            if proc.pid <= 4:
                continue
            if proc.name.lower() in _KNOWN_LONG_RUNNING:
                continue

            created = cls._parse_wmi_date(proc.created_at)
            if created is None:
                continue

            age = now - created
            if age > threshold:
                days = age.days
                stale.append(proc)
                findings.append(Finding(
                    tool_name="resource_analyzer",
                    severity=SeverityLevel.INFO,
                    category="stale_process",
                    title=f"Stale process: {proc.name} (running {days}d)",
                    description=(
                        f"Process {proc.name} (PID {proc.pid}) has been "
                        f"running for {days} days. Started: {created.strftime('%Y-%m-%d %H:%M')}."
                    ),
                    target=proc.path or proc.name,
                    domain=FindingDomain.HYGIENE,
                    raw_data=proc.model_dump(),
                ))

        return findings, stale

    @classmethod
    def _find_orphan_processes(
        cls, processes: List[ProcessInfo]
    ) -> tuple[List[Finding], List[ProcessInfo]]:
        """Flag processes whose parent PID no longer exists.

        To reduce noise, only flags orphans that are also stale (>24h) or unsigned.
        """
        findings = []
        orphans = []
        now = datetime.now(tz=timezone.utc)
        stale_threshold = timedelta(hours=_ORPHAN_STALE_HOURS)

        all_pids: Set[int] = {proc.pid for proc in processes}

        for proc in processes:
            if proc.pid <= 4:
                continue
            if proc.name.lower() in _KNOWN_LONG_RUNNING:
                continue
            if proc.parent_pid is None:
                continue
            # Parent PID 0 and 4 are system root processes
            if proc.parent_pid in (0, 4):
                continue
            # Parent still alive — not an orphan
            if proc.parent_pid in all_pids:
                continue

            # Orphaned — but only flag if also stale or unsigned
            created = cls._parse_wmi_date(proc.created_at)
            is_stale = False
            if created:
                is_stale = (now - created) > stale_threshold

            is_unsigned = proc.is_signed is False

            if not (is_stale or is_unsigned):
                continue

            orphans.append(proc)
            reasons = []
            if is_stale and created:
                reasons.append(f"running {(now - created).days}d")
            if is_unsigned:
                reasons.append("unsigned")

            findings.append(Finding(
                tool_name="resource_analyzer",
                severity=SeverityLevel.INFO,
                category="orphan_process",
                title=f"Orphan process: {proc.name} (parent PID {proc.parent_pid} gone)",
                description=(
                    f"Process {proc.name} (PID {proc.pid}) has no living parent "
                    f"(parent PID {proc.parent_pid}). Flagged because: {', '.join(reasons)}."
                ),
                target=proc.path or proc.name,
                domain=FindingDomain.HYGIENE,
                raw_data=proc.model_dump(),
            ))

        return findings, orphans
