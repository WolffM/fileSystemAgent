"""Process snapshot collector — WMI/CIM process inventory with resource metrics."""

import json
import logging
from datetime import datetime
from typing import Any, Dict, List

from ..collector_base import CollectorBase
from ..models import (
    CollectorConfig,
    CollectorResult,
    Finding,
    ProcessInfo,
    ScanStatus,
    SeverityLevel,
)

logger = logging.getLogger(__name__)

# PowerShell script to collect process data with owner info as JSON
_PS_PROCESS_SCRIPT = r"""
Get-CimInstance Win32_Process | ForEach-Object {
    $owner = Invoke-CimMethod -InputObject $_ -MethodName GetOwner -ErrorAction SilentlyContinue
    $_ | Select-Object ProcessId, Name, ExecutablePath, CommandLine,
                      ParentProcessId, ThreadCount, HandleCount,
                      WorkingSetSize, CreationDate,
                      @{N='OwnerDomain';E={$owner.Domain}},
                      @{N='OwnerUser';E={$owner.User}}
} | ConvertTo-Json -Depth 3 -Compress
"""

# Fallback script without owner resolution (faster, no GetOwner per-process)
_PS_PROCESS_SCRIPT_FAST = r"""
Get-CimInstance Win32_Process |
    Select-Object ProcessId, Name, ExecutablePath, CommandLine,
                  ParentProcessId, ThreadCount, HandleCount,
                  WorkingSetSize, CreationDate |
    ConvertTo-Json -Depth 3 -Compress
"""

# PowerShell script to get CPU time per process (cumulative seconds)
_PS_CPU_SCRIPT = r"""
Get-Process -ErrorAction SilentlyContinue |
    Where-Object { $_.Id -ne 0 } |
    Select-Object Id, @{N='CpuSeconds';E={[math]::Round($_.CPU, 2)}} |
    ConvertTo-Json -Compress
"""

# PowerShell script for signature check on a list of paths
_PS_SIGNATURE_SCRIPT = r"""
param([string[]]$Paths)
$results = @{}
foreach ($p in $Paths) {
    if ($p -and (Test-Path $p -ErrorAction SilentlyContinue)) {
        try {
            $sig = Get-AuthenticodeSignature $p -ErrorAction SilentlyContinue
            $results[$p] = @{
                Status = $sig.Status.ToString()
                Signer = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { $null }
            }
        } catch { }
    }
}
$results | ConvertTo-Json -Depth 3 -Compress
"""


class ProcessSnapshotCollector(CollectorBase):
    """Collects a snapshot of all running processes via WMI."""

    @property
    def collector_name(self) -> str:
        return "process_snapshot"

    async def collect(
        self, config: CollectorConfig, context: Dict[str, Any]
    ) -> CollectorResult:
        result = CollectorResult(
            collector_name=self.collector_name,
            started_at=datetime.now(),
        )

        try:
            # Try enriched script with owner info; fall back to fast script
            raw_processes = await self._collect_processes(config.timeout)

            processes = self._parse_processes(raw_processes)

            # CPU time enrichment (best-effort)
            await self._sample_cpu(processes, config.timeout)

            # Signature check for processes with paths (best-effort)
            signatures = await self._check_signatures(processes, config.timeout)
            self._apply_signatures(processes, signatures)

            findings = self._analyze(processes)

            result.status = ScanStatus.COMPLETED
            result.data = {
                "processes": [p.model_dump() for p in processes],
                "count": len(processes),
            }
            result.findings = findings

        except Exception as e:
            result.status = ScanStatus.FAILED
            result.error_message = str(e)
            logger.error(f"Process snapshot failed: {e}", exc_info=True)

        result.completed_at = datetime.now()
        if result.started_at:
            result.duration_seconds = (
                result.completed_at - result.started_at
            ).total_seconds()
        return result

    async def _collect_processes(self, timeout: int) -> List[dict]:
        """Collect process data, with fallback to fast script if owner query is slow."""
        try:
            stdout = await self._run_powershell(
                _PS_PROCESS_SCRIPT, timeout=min(timeout, 45)
            )
            raw = json.loads(stdout)
            return [raw] if isinstance(raw, dict) else raw
        except Exception as e:
            logger.debug(f"Enriched process script failed ({e}), falling back to fast script")
            stdout = await self._run_powershell(
                _PS_PROCESS_SCRIPT_FAST, timeout=timeout
            )
            raw = json.loads(stdout)
            return [raw] if isinstance(raw, dict) else raw

    async def _sample_cpu(
        self, processes: List[ProcessInfo], timeout: int
    ) -> None:
        """Enrich processes with cumulative CPU time (best-effort)."""
        try:
            stdout = await self._run_powershell(
                _PS_CPU_SCRIPT, timeout=min(timeout, 15)
            )
            if not stdout.strip():
                return
            raw_cpu = json.loads(stdout)
            if isinstance(raw_cpu, dict):
                raw_cpu = [raw_cpu]

            cpu_by_pid = {
                entry["Id"]: entry.get("CpuSeconds", 0.0) or 0.0
                for entry in raw_cpu
                if entry.get("Id") is not None
            }

            for proc in processes:
                if proc.pid in cpu_by_pid:
                    proc.cpu_percent = cpu_by_pid[proc.pid]
        except Exception as e:
            logger.debug(f"CPU sampling failed: {e}")

    def _parse_processes(self, raw: List[dict]) -> List[ProcessInfo]:
        """Parse PowerShell Win32_Process JSON into ProcessInfo models."""
        processes = []
        for entry in raw:
            try:
                ws = entry.get("WorkingSetSize", 0) or 0
                # Build user string from owner fields if available
                owner_domain = entry.get("OwnerDomain")
                owner_user = entry.get("OwnerUser")
                user = None
                if owner_user:
                    user = f"{owner_domain}\\{owner_user}" if owner_domain else owner_user

                processes.append(ProcessInfo(
                    pid=entry.get("ProcessId", 0),
                    name=entry.get("Name", ""),
                    path=entry.get("ExecutablePath"),
                    command_line=entry.get("CommandLine"),
                    parent_pid=entry.get("ParentProcessId"),
                    user=user,
                    thread_count=entry.get("ThreadCount", 0) or 0,
                    handle_count=entry.get("HandleCount", 0) or 0,
                    ram_mb=round(ws / (1024 * 1024), 2),
                    created_at=entry.get("CreationDate"),
                ))
            except Exception as e:
                logger.debug(f"Skipping process entry: {e}")
        return processes

    async def _check_signatures(
        self, processes: List[ProcessInfo], timeout: int
    ) -> Dict[str, dict]:
        """Check Authenticode signatures for process executables."""
        paths = list({p.path for p in processes if p.path})
        if not paths:
            return {}

        # Build comma-separated path list for PowerShell
        path_args = ",".join(f"'{p}'" for p in paths[:50])  # Limit to 50
        script = f"$Paths = @({path_args})\n{_PS_SIGNATURE_SCRIPT}"

        try:
            stdout = await self._run_powershell(script, timeout=min(timeout, 30))
            return json.loads(stdout) if stdout.strip() else {}
        except Exception as e:
            logger.debug(f"Signature check failed: {e}")
            return {}

    def _apply_signatures(
        self, processes: List[ProcessInfo], signatures: Dict[str, dict]
    ) -> None:
        """Apply signature results to process list."""
        for proc in processes:
            if proc.path and proc.path in signatures:
                sig = signatures[proc.path]
                proc.is_signed = sig.get("Status") == "Valid"
                proc.signer = sig.get("Signer")

    def _analyze(self, processes: List[ProcessInfo]) -> List[Finding]:
        """Generate findings from process data."""
        findings = []

        for proc in processes:
            # Skip system processes
            if proc.pid <= 4 or not proc.path:
                continue

            # Unsigned process with a path
            if proc.is_signed is False:
                findings.append(Finding(
                    tool_name=self.collector_name,
                    severity=SeverityLevel.MEDIUM,
                    category="unsigned_process",
                    title=f"Unsigned process: {proc.name}",
                    description=(
                        f"Process {proc.name} (PID {proc.pid}) is not "
                        f"digitally signed. Path: {proc.path}"
                    ),
                    target=proc.path,
                    raw_data=proc.model_dump(),
                ))

            # Suspicious path (not in standard locations)
            if proc.path and not self._is_standard_path(proc.path):
                findings.append(Finding(
                    tool_name=self.collector_name,
                    severity=SeverityLevel.LOW,
                    category="non_standard_path",
                    title=f"Non-standard path: {proc.name}",
                    description=(
                        f"Process {proc.name} (PID {proc.pid}) is running "
                        f"from a non-standard location: {proc.path}"
                    ),
                    target=proc.path,
                    raw_data=proc.model_dump(),
                ))

        return findings

    @staticmethod
    def _is_standard_path(path: str) -> bool:
        """Check if a path is in a standard Windows location."""
        normalized = path.lower().replace("/", "\\")
        standard_prefixes = (
            "c:\\windows\\",
            "c:\\program files\\",
            "c:\\program files (x86)\\",
            "c:\\programdata\\",
        )
        return any(normalized.startswith(p) for p in standard_prefixes)
