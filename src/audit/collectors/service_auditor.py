"""Service auditor collector — Windows service configuration analysis."""

import json
import logging
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

from ..collector_base import CollectorBase
from ..models import (
    CollectorConfig,
    CollectorResult,
    Finding,
    ScanStatus,
    ServiceInfo,
    SeverityLevel,
)

logger = logging.getLogger(__name__)

_PS_SERVICE_SCRIPT = r"""
Get-CimInstance Win32_Service |
    Select-Object Name, DisplayName, State, StartMode, PathName,
                  StartName, Description |
    ConvertTo-Json -Depth 3 -Compress
"""

# PowerShell script to check if binary paths are writable by non-admin users
_PS_ACL_CHECK_SCRIPT = r"""
param([string[]]$Paths)
$results = @()
foreach ($p in $Paths) {
    if ($p -and (Test-Path $p -ErrorAction SilentlyContinue)) {
        try {
            $acl = Get-Acl $p -ErrorAction SilentlyContinue
            $writable = $acl.Access | Where-Object {
                $_.IdentityReference -match 'BUILTIN\\Users|Everyone|Authenticated Users' -and
                $_.FileSystemRights -match 'Write|FullControl|Modify' -and
                $_.AccessControlType -eq 'Allow'
            }
            if ($writable) { $results += $p }
        } catch { }
    }
}
$results | ConvertTo-Json -Compress
"""


class ServiceAuditorCollector(CollectorBase):
    """Audits Windows service configurations for vulnerabilities."""

    @property
    def collector_name(self) -> str:
        return "service_auditor"

    async def collect(
        self, config: CollectorConfig, context: Dict[str, Any]
    ) -> CollectorResult:
        result = CollectorResult(
            collector_name=self.collector_name,
            started_at=datetime.now(),
        )

        try:
            stdout = await self._run_powershell(
                _PS_SERVICE_SCRIPT, timeout=config.timeout
            )
            raw_services = json.loads(stdout)
            if isinstance(raw_services, dict):
                raw_services = [raw_services]

            services = self._parse_services(raw_services)

            # Check writable binaries for SYSTEM services (best-effort)
            await self._check_writable_binaries(services, config.timeout)

            findings = self._analyze(services)

            result.status = ScanStatus.COMPLETED
            result.data = {
                "services": [s.model_dump() for s in services],
                "count": len(services),
            }
            result.findings = findings

        except Exception as e:
            result.status = ScanStatus.FAILED
            result.error_message = str(e)
            logger.error(f"Service audit failed: {e}", exc_info=True)

        result.completed_at = datetime.now()
        if result.started_at:
            result.duration_seconds = (
                result.completed_at - result.started_at
            ).total_seconds()
        return result

    def _parse_services(self, raw: List[dict]) -> List[ServiceInfo]:
        """Parse PowerShell Win32_Service JSON into ServiceInfo models."""
        services = []
        for entry in raw:
            try:
                path = entry.get("PathName") or ""
                account = entry.get("StartName") or ""
                svc = ServiceInfo(
                    name=entry.get("Name", ""),
                    display_name=entry.get("DisplayName", ""),
                    state=entry.get("State", "Unknown"),
                    start_mode=entry.get("StartMode", "Unknown"),
                    binary_path=path or None,
                    account=account,
                    description=entry.get("Description"),
                    unquoted_path=self._has_unquoted_path(path),
                    non_standard_binary_location=self._is_non_standard(path),
                )
                services.append(svc)
            except Exception as e:
                logger.debug(f"Skipping service entry: {e}")
        return services

    async def _check_writable_binaries(
        self, services: List[ServiceInfo], timeout: int
    ) -> None:
        """Check if SYSTEM service binaries are writable by non-admin users."""
        # Filter to running SYSTEM services with a binary path
        system_services = [
            svc for svc in services
            if svc.state == "Running"
            and svc.binary_path
            and self._is_system_account(svc.account)
        ]
        if not system_services:
            return

        # Extract exe paths (strip quotes and arguments)
        path_to_svcs: Dict[str, List[ServiceInfo]] = {}
        for svc in system_services:
            exe_path = self._extract_exe_path(svc.binary_path)
            if exe_path:
                path_to_svcs.setdefault(exe_path, []).append(svc)

        paths = list(path_to_svcs.keys())[:50]  # Limit to 50
        if not paths:
            return

        path_args = ",".join(f"'{p}'" for p in paths)
        script = f"$Paths = @({path_args})\n{_PS_ACL_CHECK_SCRIPT}"

        try:
            stdout = await self._run_powershell(script, timeout=min(timeout, 30))
            if not stdout.strip():
                return
            writable_paths = json.loads(stdout)
            if isinstance(writable_paths, str):
                writable_paths = [writable_paths]
            if not writable_paths:
                return

            for wp in writable_paths:
                for svc in path_to_svcs.get(wp, []):
                    svc.system_with_writable_binary = True
        except Exception as e:
            logger.debug(f"ACL check failed: {e}")

    @staticmethod
    def _extract_exe_path(binary_path: str) -> Optional[str]:
        """Extract the executable path from a service binary path string."""
        if not binary_path:
            return None
        path = binary_path.strip()
        if path.startswith('"'):
            # Quoted path: extract between quotes
            end = path.find('"', 1)
            if end > 0:
                return path[1:end]
            return path[1:]
        # Unquoted: take everything before first space-dash or space-slash argument
        exe = re.split(r'\s+-', path)[0].strip()
        exe = re.split(r'\s+/', exe)[0].strip()
        return exe if exe else None

    def _analyze(self, services: List[ServiceInfo]) -> List[Finding]:
        """Generate findings from service data."""
        findings = []

        for svc in services:
            if not svc.binary_path:
                continue

            # Unquoted service path (potential privilege escalation)
            if svc.unquoted_path:
                findings.append(Finding(
                    tool_name=self.collector_name,
                    severity=SeverityLevel.HIGH,
                    category="unquoted_service_path",
                    title=f"Unquoted service path: {svc.name}",
                    description=(
                        f"Service '{svc.display_name}' has an unquoted binary "
                        f"path with spaces, which could allow privilege "
                        f"escalation. Path: {svc.binary_path}"
                    ),
                    target=svc.binary_path,
                    raw_data=svc.model_dump(),
                    mitre_attack="T1574.009",
                ))

            # SYSTEM service running from non-standard location
            if (
                self._is_system_account(svc.account)
                and svc.non_standard_binary_location
                and svc.state == "Running"
            ):
                findings.append(Finding(
                    tool_name=self.collector_name,
                    severity=SeverityLevel.MEDIUM,
                    category="system_service_non_standard",
                    title=f"SYSTEM service in non-standard path: {svc.name}",
                    description=(
                        f"Service '{svc.display_name}' runs as {svc.account} "
                        f"from a non-standard location: {svc.binary_path}"
                    ),
                    target=svc.binary_path,
                    raw_data=svc.model_dump(),
                ))

        return findings

    @staticmethod
    def _has_unquoted_path(path: str) -> bool:
        """Check if a service path contains spaces but is not quoted.

        An unquoted path like:
            C:\\Program Files\\My App\\service.exe -arg
        is vulnerable because Windows will try:
            C:\\Program.exe
            C:\\Program Files\\My.exe
            C:\\Program Files\\My App\\service.exe
        """
        if not path:
            return False
        path = path.strip()
        # Already quoted
        if path.startswith('"'):
            return False
        # Extract the executable path (before any arguments)
        # Split on common argument indicators
        exe_path = re.split(r'\s+-', path)[0].strip()
        exe_path = re.split(r'\s+/', exe_path)[0].strip()
        # If it ends with .exe and has no spaces, it's fine
        if " " not in exe_path:
            return False
        # Has spaces and is not quoted
        return True

    @staticmethod
    def _is_non_standard(path: str) -> bool:
        """Check if a service binary is in a non-standard location."""
        if not path:
            return False
        normalized = path.lower().strip().strip('"').replace("/", "\\")
        standard_prefixes = (
            "c:\\windows\\",
            "c:\\program files\\",
            "c:\\program files (x86)\\",
            "c:\\programdata\\",
        )
        return not any(normalized.startswith(p) for p in standard_prefixes)

    @staticmethod
    def _is_system_account(account: str) -> bool:
        """Check if the service runs under a high-privilege account."""
        account_lower = account.lower()
        return any(
            s in account_lower
            for s in ("localsystem", "local system", "nt authority\\system")
        )
