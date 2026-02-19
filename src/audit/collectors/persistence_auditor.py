"""Persistence auditor collector — scheduled tasks, run keys, and WMI subscriptions."""

import json
import logging
from datetime import datetime
from typing import Any, Dict, List

from ..collector_base import CollectorBase
from ..models import (
    CollectorConfig,
    CollectorResult,
    Finding,
    RunKeyEntry,
    ScanStatus,
    ScheduledTaskInfo,
    SeverityLevel,
)

logger = logging.getLogger(__name__)

# Scheduled task state enum from Windows
_TASK_STATE_MAP = {
    0: "Unknown",
    1: "Disabled",
    2: "Queued",
    3: "Ready",
    4: "Running",
}

_TASK_RUNLEVEL_MAP = {
    0: "Limited",
    1: "Highest",
}

_PS_SCHEDULED_TASKS = r"""
Get-ScheduledTask | ForEach-Object {
    [PSCustomObject]@{
        TaskName  = $_.TaskName
        TaskPath  = $_.TaskPath
        State     = $_.State
        Execute   = if ($_.Actions.Count -gt 0) { $_.Actions[0].Execute } else { $null }
        Arguments = if ($_.Actions.Count -gt 0) { $_.Actions[0].Arguments } else { $null }
        UserId    = $_.Principal.UserId
        RunLevel  = $_.Principal.RunLevel
    }
} | ConvertTo-Json -Depth 3 -Compress
"""

_PS_RUN_KEYS = r"""
$runKeyPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
)
$results = @()
foreach ($path in $runKeyPaths) {
    if (Test-Path $path) {
        $props = Get-ItemProperty $path -ErrorAction SilentlyContinue
        if ($props) {
            $props.PSObject.Properties |
                Where-Object { $_.Name -notin @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') } |
                ForEach-Object {
                    $results += [PSCustomObject]@{
                        RegistryPath = $path
                        Name  = $_.Name
                        Value = $_.Value
                    }
                }
        }
    }
}
$results | ConvertTo-Json -Depth 3 -Compress
"""


class PersistenceAuditorCollector(CollectorBase):
    """Audits Windows persistence mechanisms."""

    @property
    def collector_name(self) -> str:
        return "persistence_auditor"

    async def collect(
        self, config: CollectorConfig, context: Dict[str, Any]
    ) -> CollectorResult:
        result = CollectorResult(
            collector_name=self.collector_name,
            started_at=datetime.now(),
        )

        tasks: List[ScheduledTaskInfo] = []
        run_keys: List[RunKeyEntry] = []
        errors: List[str] = []

        # Collect scheduled tasks
        try:
            stdout = await self._run_powershell(
                _PS_SCHEDULED_TASKS, timeout=config.timeout
            )
            raw_tasks = json.loads(stdout) if stdout.strip() else []
            if isinstance(raw_tasks, dict):
                raw_tasks = [raw_tasks]
            tasks = self._parse_tasks(raw_tasks)
        except Exception as e:
            errors.append(f"Scheduled tasks: {e}")
            logger.warning(f"Failed to collect scheduled tasks: {e}")

        # Collect run keys
        try:
            stdout = await self._run_powershell(
                _PS_RUN_KEYS, timeout=config.timeout
            )
            raw_keys = json.loads(stdout) if stdout.strip() else []
            if isinstance(raw_keys, dict):
                raw_keys = [raw_keys]
            run_keys = self._parse_run_keys(raw_keys)
        except Exception as e:
            errors.append(f"Run keys: {e}")
            logger.warning(f"Failed to collect run keys: {e}")

        # Analyze
        findings = self._analyze_tasks(tasks) + self._analyze_run_keys(run_keys)

        result.status = ScanStatus.COMPLETED
        result.data = {
            "scheduled_tasks": [t.model_dump() for t in tasks],
            "run_keys": [r.model_dump() for r in run_keys],
            "task_count": len(tasks),
            "run_key_count": len(run_keys),
            "errors": errors,
        }
        result.findings = findings

        result.completed_at = datetime.now()
        if result.started_at:
            result.duration_seconds = (
                result.completed_at - result.started_at
            ).total_seconds()
        return result

    def _parse_tasks(self, raw: List[dict]) -> List[ScheduledTaskInfo]:
        """Parse PowerShell scheduled task JSON."""
        tasks = []
        for entry in raw:
            try:
                state_raw = entry.get("State", 0)
                if isinstance(state_raw, int):
                    state = _TASK_STATE_MAP.get(state_raw, f"Unknown({state_raw})")
                else:
                    state = str(state_raw)

                run_level_raw = entry.get("RunLevel", 0)
                if isinstance(run_level_raw, int):
                    run_level = _TASK_RUNLEVEL_MAP.get(run_level_raw, "Limited")
                else:
                    run_level = str(run_level_raw)

                tasks.append(ScheduledTaskInfo(
                    task_name=entry.get("TaskName", ""),
                    task_path=entry.get("TaskPath", ""),
                    state=state,
                    execute=entry.get("Execute"),
                    arguments=entry.get("Arguments"),
                    user_id=entry.get("UserId"),
                    run_level=run_level,
                ))
            except Exception as e:
                logger.debug(f"Skipping task entry: {e}")
        return tasks

    def _parse_run_keys(self, raw: List[dict]) -> List[RunKeyEntry]:
        """Parse PowerShell run key JSON."""
        entries = []
        for entry in raw:
            try:
                entries.append(RunKeyEntry(
                    registry_path=entry.get("RegistryPath", ""),
                    name=entry.get("Name", ""),
                    value=entry.get("Value", ""),
                ))
            except Exception as e:
                logger.debug(f"Skipping run key entry: {e}")
        return entries

    def _analyze_tasks(self, tasks: List[ScheduledTaskInfo]) -> List[Finding]:
        """Generate findings from scheduled task data."""
        findings = []

        for task in tasks:
            if task.state == "Disabled":
                continue

            # Tasks running with highest privileges
            if task.run_level == "Highest":
                findings.append(Finding(
                    tool_name=self.collector_name,
                    severity=SeverityLevel.MEDIUM,
                    category="elevated_scheduled_task",
                    title=f"Elevated task: {task.task_name}",
                    description=(
                        f"Scheduled task '{task.task_name}' runs with highest "
                        f"privileges. Execute: {task.execute or 'N/A'}"
                    ),
                    target=task.execute or task.task_name,
                    raw_data=task.model_dump(),
                ))

            # Tasks executing from non-standard locations
            if task.execute and self._is_suspicious_task_path(task.execute):
                findings.append(Finding(
                    tool_name=self.collector_name,
                    severity=SeverityLevel.MEDIUM,
                    category="suspicious_task_path",
                    title=f"Non-standard task executable: {task.task_name}",
                    description=(
                        f"Scheduled task '{task.task_name}' executes from "
                        f"a non-standard location: {task.execute}"
                    ),
                    target=task.execute,
                    raw_data=task.model_dump(),
                ))

        return findings

    def _analyze_run_keys(self, run_keys: List[RunKeyEntry]) -> List[Finding]:
        """Generate findings from registry run key data."""
        findings = []

        for entry in run_keys:
            # Extract the executable path from the value
            exe_path = self._extract_exe_path(entry.value)

            if exe_path and self._is_suspicious_run_key_path(exe_path):
                findings.append(Finding(
                    tool_name=self.collector_name,
                    severity=SeverityLevel.MEDIUM,
                    category="suspicious_run_key",
                    title=f"Non-standard run key: {entry.name}",
                    description=(
                        f"Run key '{entry.name}' in {entry.registry_path} "
                        f"points to a non-standard location: {exe_path}"
                    ),
                    target=exe_path,
                    raw_data=entry.model_dump(),
                ))

        return findings

    @staticmethod
    def _is_suspicious_task_path(execute: str) -> bool:
        """Check if a scheduled task executable is in a suspicious location."""
        normalized = execute.lower().strip().strip('"').replace("/", "\\")
        standard_prefixes = (
            "c:\\windows\\",
            "c:\\program files\\",
            "c:\\program files (x86)\\",
            "c:\\programdata\\",
            # PowerShell and system tools are standard
            "powershell",
            "cmd",
            "%systemroot%",
            "%windir%",
        )
        return not any(normalized.startswith(p) for p in standard_prefixes)

    @staticmethod
    def _is_suspicious_run_key_path(exe_path: str) -> bool:
        """Check if a run key executable is in a suspicious location.

        More lenient than task path check — user AppData is common for
        legitimate auto-start apps (Discord, Steam, etc.).
        """
        normalized = exe_path.lower().strip().strip('"').replace("/", "\\")
        standard_prefixes = (
            "c:\\windows\\",
            "c:\\program files\\",
            "c:\\program files (x86)\\",
            "c:\\programdata\\",
        )
        # Known user locations (AppData) are common for legitimate apps
        user_app_prefixes = (
            "c:\\users\\",  # User profile paths are accepted
        )
        if any(normalized.startswith(p) for p in standard_prefixes):
            return False
        if any(normalized.startswith(p) for p in user_app_prefixes):
            return False
        return True

    @staticmethod
    def _extract_exe_path(value: str) -> str:
        """Extract the executable path from a run key value.

        Handles quoted paths like: "C:\\Program Files\\App\\app.exe" --flag
        And unquoted paths like: C:\\Windows\\system32\\app.exe
        """
        value = value.strip()
        if value.startswith('"'):
            # Quoted path — extract everything between first pair of quotes
            end = value.find('"', 1)
            if end > 0:
                return value[1:end]
        # Unquoted — take everything before first space (if it looks like a path)
        parts = value.split()
        if parts:
            return parts[0]
        return value
