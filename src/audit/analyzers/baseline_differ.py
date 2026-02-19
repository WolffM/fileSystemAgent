"""Baseline differ — compares current scan data against a saved baseline.

On first run (no baseline exists), saves the current data as the baseline.
On subsequent runs, produces findings for new/removed processes, services,
network listeners, and persistence entries.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from ..analyzer_base import AnalyzerBase
from ..models import (
    AnalyzerConfig,
    AnalyzerResult,
    Finding,
    ScanStatus,
    SeverityLevel,
)

logger = logging.getLogger(__name__)

_DEFAULT_BASELINE_DIR = "./data/audit/baselines"


class BaselineDiffer(AnalyzerBase):
    """Compares current scan data against a saved baseline."""

    def __init__(self, baseline_dir: str = _DEFAULT_BASELINE_DIR):
        self._baseline_dir = Path(baseline_dir)

    @property
    def analyzer_name(self) -> str:
        return "baseline_differ"

    async def analyze(
        self, config: AnalyzerConfig, context: Dict[str, Any]
    ) -> AnalyzerResult:
        result = AnalyzerResult(
            analyzer_name=self.analyzer_name,
            started_at=datetime.now(),
        )

        baseline_dir = Path(
            config.extra_args.get("baseline_dir", str(self._baseline_dir))
        )
        baseline = self._load_baseline(baseline_dir)

        if baseline is None:
            # First run — save current as baseline
            self._save_baseline(baseline_dir, context)
            result.status = ScanStatus.COMPLETED
            result.data = {
                "first_run": True,
                "baseline_saved": True,
                "baseline_dir": str(baseline_dir),
            }
            result.completed_at = datetime.now()
            return result

        # Diff each data category
        findings: List[Finding] = []
        diff_summary: Dict[str, Any] = {}

        # Process diff
        if "process_snapshot" in context or "process_snapshot" in baseline:
            proc_diff = self._diff_processes(
                baseline.get("process_snapshot", {}),
                context.get("process_snapshot", {}),
            )
            findings.extend(proc_diff["findings"])
            diff_summary["processes"] = proc_diff["summary"]

        # Service diff
        if "service_auditor" in context or "service_auditor" in baseline:
            svc_diff = self._diff_services(
                baseline.get("service_auditor", {}),
                context.get("service_auditor", {}),
            )
            findings.extend(svc_diff["findings"])
            diff_summary["services"] = svc_diff["summary"]

        # Network diff
        if "network_mapper" in context or "network_mapper" in baseline:
            net_diff = self._diff_network(
                baseline.get("network_mapper", {}),
                context.get("network_mapper", {}),
            )
            findings.extend(net_diff["findings"])
            diff_summary["network"] = net_diff["summary"]

        # Persistence diff
        if "persistence_auditor" in context or "persistence_auditor" in baseline:
            pers_diff = self._diff_persistence(
                baseline.get("persistence_auditor", {}),
                context.get("persistence_auditor", {}),
            )
            findings.extend(pers_diff["findings"])
            diff_summary["persistence"] = pers_diff["summary"]

        result.status = ScanStatus.COMPLETED
        result.data = {
            "first_run": False,
            "diff_summary": diff_summary,
            "total_changes": sum(
                s.get("added", 0) + s.get("removed", 0)
                for s in diff_summary.values()
            ),
        }
        result.findings = findings
        result.completed_at = datetime.now()
        return result

    # ---- Diff methods ----

    def _diff_processes(
        self, baseline_data: dict, current_data: dict
    ) -> Dict[str, Any]:
        """Diff process lists by name+path key."""
        baseline_procs = {
            (p.get("name", ""), p.get("path") or ""): p
            for p in baseline_data.get("processes", [])
        }
        current_procs = {
            (p.get("name", ""), p.get("path") or ""): p
            for p in current_data.get("processes", [])
        }

        added = set(current_procs.keys()) - set(baseline_procs.keys())
        removed = set(baseline_procs.keys()) - set(current_procs.keys())

        findings = []
        for key in added:
            proc = current_procs[key]
            name, path = key
            findings.append(Finding(
                tool_name=self.analyzer_name,
                severity=SeverityLevel.LOW,
                category="new_process",
                title=f"New process: {name}",
                description=(
                    f"Process '{name}' was not in the baseline. "
                    f"Path: {path or 'N/A'}"
                ),
                target=path or name,
                raw_data=proc,
            ))

        for key in removed:
            name, path = key
            findings.append(Finding(
                tool_name=self.analyzer_name,
                severity=SeverityLevel.INFO,
                category="removed_process",
                title=f"Removed process: {name}",
                description=(
                    f"Process '{name}' was in the baseline but is no "
                    f"longer running. Path: {path or 'N/A'}"
                ),
                target=path or name,
            ))

        return {
            "findings": findings,
            "summary": {"added": len(added), "removed": len(removed)},
        }

    def _diff_services(
        self, baseline_data: dict, current_data: dict
    ) -> Dict[str, Any]:
        """Diff service lists by name key."""
        baseline_svcs = {
            s.get("name", ""): s
            for s in baseline_data.get("services", [])
        }
        current_svcs = {
            s.get("name", ""): s
            for s in current_data.get("services", [])
        }

        added = set(current_svcs.keys()) - set(baseline_svcs.keys())
        removed = set(baseline_svcs.keys()) - set(current_svcs.keys())

        findings = []
        for name in added:
            svc = current_svcs[name]
            account = svc.get("account", "")
            is_system = any(
                s in account.lower()
                for s in ("localsystem", "local system", "nt authority\\system")
            )
            severity = SeverityLevel.HIGH if is_system else SeverityLevel.MEDIUM

            findings.append(Finding(
                tool_name=self.analyzer_name,
                severity=severity,
                category="new_service",
                title=f"New service: {name}",
                description=(
                    f"Service '{svc.get('display_name', name)}' was not "
                    f"in the baseline. Account: {account}, "
                    f"State: {svc.get('state', 'Unknown')}"
                ),
                target=svc.get("binary_path") or name,
                raw_data=svc,
            ))

        for name in removed:
            findings.append(Finding(
                tool_name=self.analyzer_name,
                severity=SeverityLevel.INFO,
                category="removed_service",
                title=f"Removed service: {name}",
                description=f"Service '{name}' was in the baseline but no longer exists.",
                target=name,
            ))

        return {
            "findings": findings,
            "summary": {"added": len(added), "removed": len(removed)},
        }

    def _diff_network(
        self, baseline_data: dict, current_data: dict
    ) -> Dict[str, Any]:
        """Diff network listeners (Listen state) by address:port key."""
        baseline_listeners = self._extract_listeners(baseline_data)
        current_listeners = self._extract_listeners(current_data)

        baseline_keys = set(baseline_listeners.keys())
        current_keys = set(current_listeners.keys())

        added = current_keys - baseline_keys
        removed = baseline_keys - current_keys

        findings = []
        for key in added:
            conn = current_listeners[key]
            findings.append(Finding(
                tool_name=self.analyzer_name,
                severity=SeverityLevel.MEDIUM,
                category="new_listener",
                title=f"New listener: {key}",
                description=(
                    f"New listening port {key} "
                    f"(process: {conn.get('process_name', 'unknown')})"
                ),
                target=key,
                raw_data=conn,
            ))

        for key in removed:
            findings.append(Finding(
                tool_name=self.analyzer_name,
                severity=SeverityLevel.INFO,
                category="removed_listener",
                title=f"Removed listener: {key}",
                description=f"Listening port {key} is no longer active.",
                target=key,
            ))

        return {
            "findings": findings,
            "summary": {"added": len(added), "removed": len(removed)},
        }

    def _diff_persistence(
        self, baseline_data: dict, current_data: dict
    ) -> Dict[str, Any]:
        """Diff persistence mechanisms (scheduled tasks + run keys)."""
        findings = []
        total_added = 0
        total_removed = 0

        # Scheduled tasks
        baseline_tasks = {
            t.get("task_name", ""): t
            for t in baseline_data.get("scheduled_tasks", [])
        }
        current_tasks = {
            t.get("task_name", ""): t
            for t in current_data.get("scheduled_tasks", [])
        }

        added_tasks = set(current_tasks.keys()) - set(baseline_tasks.keys())
        removed_tasks = set(baseline_tasks.keys()) - set(current_tasks.keys())
        total_added += len(added_tasks)
        total_removed += len(removed_tasks)

        for name in added_tasks:
            task = current_tasks[name]
            findings.append(Finding(
                tool_name=self.analyzer_name,
                severity=SeverityLevel.MEDIUM,
                category="new_scheduled_task",
                title=f"New scheduled task: {name}",
                description=(
                    f"Scheduled task '{name}' was not in the baseline. "
                    f"Execute: {task.get('execute', 'N/A')}"
                ),
                target=task.get("execute") or name,
                raw_data=task,
            ))

        for name in removed_tasks:
            findings.append(Finding(
                tool_name=self.analyzer_name,
                severity=SeverityLevel.INFO,
                category="removed_scheduled_task",
                title=f"Removed scheduled task: {name}",
                description=f"Scheduled task '{name}' no longer exists.",
                target=name,
            ))

        # Run keys
        baseline_keys = {
            (r.get("registry_path", ""), r.get("name", "")): r
            for r in baseline_data.get("run_keys", [])
        }
        current_keys = {
            (r.get("registry_path", ""), r.get("name", "")): r
            for r in current_data.get("run_keys", [])
        }

        added_keys = set(current_keys.keys()) - set(baseline_keys.keys())
        removed_keys = set(baseline_keys.keys()) - set(current_keys.keys())
        total_added += len(added_keys)
        total_removed += len(removed_keys)

        for key in added_keys:
            entry = current_keys[key]
            findings.append(Finding(
                tool_name=self.analyzer_name,
                severity=SeverityLevel.MEDIUM,
                category="new_run_key",
                title=f"New run key: {key[1]}",
                description=(
                    f"Run key '{key[1]}' added to {key[0]}. "
                    f"Value: {entry.get('value', 'N/A')}"
                ),
                target=entry.get("value") or key[1],
                raw_data=entry,
            ))

        for key in removed_keys:
            findings.append(Finding(
                tool_name=self.analyzer_name,
                severity=SeverityLevel.INFO,
                category="removed_run_key",
                title=f"Removed run key: {key[1]}",
                description=f"Run key '{key[1]}' removed from {key[0]}.",
                target=key[1],
            ))

        return {
            "findings": findings,
            "summary": {"added": total_added, "removed": total_removed},
        }

    # ---- Helpers ----

    @staticmethod
    def _extract_listeners(data: dict) -> Dict[str, dict]:
        """Extract Listen-state connections keyed by address:port."""
        listeners = {}
        for conn in data.get("connections", []):
            if conn.get("state") == "Listen":
                key = f"{conn.get('local_address', '')}:{conn.get('local_port', '')}"
                listeners[key] = conn
        return listeners

    # ---- Baseline persistence ----

    @staticmethod
    def _load_baseline(baseline_dir: Path) -> Optional[Dict[str, Any]]:
        """Load the most recent baseline from disk."""
        if not baseline_dir.is_dir():
            return None

        json_files = sorted(
            baseline_dir.glob("baseline_*.json"),
            key=lambda f: f.stat().st_mtime,
            reverse=True,
        )
        if not json_files:
            return None

        try:
            return json.loads(json_files[0].read_text())
        except Exception as e:
            logger.warning(f"Failed to load baseline: {e}")
            return None

    @staticmethod
    def _save_baseline(
        baseline_dir: Path, context: Dict[str, Any]
    ) -> Optional[Path]:
        """Save current context as a baseline."""
        try:
            baseline_dir.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filepath = baseline_dir / f"baseline_{timestamp}.json"
            filepath.write_text(json.dumps(context, indent=2, default=str))
            logger.info(f"Saved baseline to {filepath}")
            return filepath
        except Exception as e:
            logger.error(f"Failed to save baseline: {e}")
            return None

    @classmethod
    def save_baseline_from_context(
        cls, context: Dict[str, Any], baseline_dir: str = _DEFAULT_BASELINE_DIR
    ) -> Optional[Path]:
        """Public method for CLI to save a baseline from context data."""
        return cls._save_baseline(Path(baseline_dir), context)

    @classmethod
    def get_baseline_info(
        cls, baseline_dir: str = _DEFAULT_BASELINE_DIR
    ) -> Optional[Dict[str, Any]]:
        """Get info about the current baseline for CLI display."""
        bdir = Path(baseline_dir)
        if not bdir.is_dir():
            return None

        json_files = sorted(
            bdir.glob("baseline_*.json"),
            key=lambda f: f.stat().st_mtime,
            reverse=True,
        )
        if not json_files:
            return None

        latest = json_files[0]
        try:
            data = json.loads(latest.read_text())
            return {
                "path": str(latest),
                "modified": datetime.fromtimestamp(latest.stat().st_mtime).isoformat(),
                "collectors": list(data.keys()),
                "file_count": len(json_files),
            }
        except Exception:
            return None

    @classmethod
    def clear_baselines(cls, baseline_dir: str = _DEFAULT_BASELINE_DIR) -> int:
        """Remove all baseline files. Returns count of files removed."""
        bdir = Path(baseline_dir)
        if not bdir.is_dir():
            return 0
        count = 0
        for f in bdir.glob("baseline_*.json"):
            f.unlink()
            count += 1
        return count
