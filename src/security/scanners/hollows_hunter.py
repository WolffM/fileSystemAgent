"""HollowsHunter scanner — in-memory process implant detection.

Scans all running processes (or a specific PID) for memory anomalies:
hollowed modules, injected code, patched entry points, and suspicious threads.
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..models import Finding, ScanConfig, ScanResult, SeverityLevel
from ..result_parser import ResultParser
from ..scanner_base import ScannerBase
from ..tool_manager import ToolManager

logger = logging.getLogger(__name__)

# Anomaly type -> (severity, MITRE ATT&CK ID, description)
ANOMALY_SEVERITY = {
    "replaced": (
        SeverityLevel.CRITICAL,
        "T1055.012",
        "Process hollowing — entire module replaced in memory",
    ),
    "implanted": (
        SeverityLevel.CRITICAL,
        "T1055",
        "Code injection — foreign code implanted into process",
    ),
    "hdr_modified": (
        SeverityLevel.HIGH,
        "T1055",
        "PE header modification — headers tampered in memory",
    ),
    "patched": (
        SeverityLevel.MEDIUM,
        "T1574",
        "Inline patching — code bytes modified (possible hook)",
    ),
    "iat_hooked": (
        SeverityLevel.HIGH,
        "T1574",
        "IAT hooking — import address table entries redirected",
    ),
    "unreachable_file": (
        SeverityLevel.MEDIUM,
        None,
        "Unreachable file — module on disk cannot be accessed",
    ),
    "other": (
        SeverityLevel.LOW,
        None,
        "Other anomaly detected",
    ),
}


class HollowsHunterScanner(ScannerBase):
    """HollowsHunter in-memory process scanner."""

    @property
    def tool_name(self) -> str:
        return "hollows_hunter"

    def build_command(self, scan_config: ScanConfig, output_dir: Path) -> List[str]:
        exe = str(self.tool_manager.get_tool_path("hollows_hunter"))
        cmd = [exe, "/json", "/dir", str(output_dir)]

        # Scan specific PID
        if scan_config.target.target_type == "process":
            cmd.extend(["/pid", scan_config.target.target_value])

        # Extra args
        if scan_config.extra_args.get("loop", False):
            cmd.append("/loop")
        if "shellc" in scan_config.extra_args:
            cmd.extend(["/shellc", str(scan_config.extra_args["shellc"])])

        return cmd

    def parse_output(self, scan_result: ScanResult) -> List[Finding]:
        """Parse HollowsHunter JSON output into findings."""
        findings: List[Finding] = []

        # Parse from output files (HollowsHunter writes to output_dir)
        for output_file in scan_result.output_files:
            if Path(output_file).name == "scan_report.json":
                output_dir = Path(output_file).parent
                raw_findings = ResultParser.parse_hollows_hunter_report(output_dir)
                for raw in raw_findings:
                    findings.extend(self._raw_to_findings(raw))
                break  # Only process the top-level report once

        return findings

    def _raw_to_findings(self, raw: Dict[str, Any]) -> List[Finding]:
        """Convert a raw process finding dict into Finding objects.

        Creates one Finding per anomaly type found in the process.
        """
        findings: List[Finding] = []
        pid = raw.get("pid", "unknown")
        name = raw.get("name", "unknown")

        for anomaly_type, (severity, mitre, desc) in ANOMALY_SEVERITY.items():
            count = raw.get(anomaly_type, 0)
            if count > 0:
                findings.append(
                    Finding(
                        tool_name="hollows_hunter",
                        severity=severity,
                        category="memory_anomaly",
                        title=f"HollowsHunter: {anomaly_type} in {name} (PID {pid})",
                        description=(
                            f"{desc}. Found {count} {anomaly_type} anomal"
                            f"{'ies' if count > 1 else 'y'} "
                            f"in process {name} (PID {pid})."
                        ),
                        target=f"PID:{pid}",
                        raw_data=raw,
                        mitre_attack=mitre,
                    )
                )

        return findings
