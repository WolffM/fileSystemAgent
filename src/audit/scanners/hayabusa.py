"""Hayabusa scanner — Windows event log threat hunting and timeline generation.

Supports live analysis of local event logs or offline .evtx files.
"""

import csv
import io
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..models import Finding, ScanConfig, ScanResult, SeverityLevel
from ..result_parser import ResultParser
from ..scanner_base import ScannerBase
from ..tool_manager import ToolManager

logger = logging.getLogger(__name__)


class HayabusaScanner(ScannerBase):
    """Hayabusa event log threat hunter."""

    @property
    def tool_name(self) -> str:
        return "hayabusa"

    def __init__(
        self,
        tool_manager: ToolManager,
        config: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(tool_manager, config)
        self.min_level = self.config.get("min_level", "medium")

    def build_command(self, scan_config: ScanConfig, output_dir: Path) -> List[str]:
        exe = str(self.tool_manager.get_tool_path("hayabusa"))
        output_file = output_dir / "hayabusa_timeline.csv"

        cmd = [exe, "csv-timeline", "--no-wizard"]

        # Live analysis vs offline evtx
        if scan_config.target.target_value in ("live", ""):
            cmd.append("-l")
        else:
            cmd.extend(["-d", scan_config.target.target_value])

        min_level = scan_config.extra_args.get("min_level", self.min_level)
        cmd.extend(["-m", min_level])
        cmd.extend(["-o", str(output_file)])

        # Quiet mode to suppress interactive prompts
        cmd.append("-q")

        return cmd

    def parse_output(self, scan_result: ScanResult) -> List[Finding]:
        """Parse Hayabusa CSV timeline output."""
        findings: List[Finding] = []

        # Find the output CSV file
        csv_file = None
        for f in scan_result.output_files:
            if f.endswith(".csv"):
                csv_file = f
                break

        if csv_file:
            try:
                text = Path(csv_file).read_text(encoding="utf-8", errors="replace")
                findings.extend(self._parse_csv_timeline(text))
            except OSError as e:
                logger.error(f"Failed to read Hayabusa output: {e}")

        # Also try parsing stdout (hayabusa may output summary info)
        if not findings and scan_result.stdout:
            findings.extend(self._parse_csv_timeline(scan_result.stdout))

        return findings

    def _parse_csv_timeline(self, text: str) -> List[Finding]:
        """Parse Hayabusa CSV timeline rows into Findings."""
        findings: List[Finding] = []

        rows = ResultParser.parse_csv_output(text)
        for row in rows:
            # Hayabusa CSV columns: Timestamp, Computer, Channel, EventID,
            # Level, RecordID, RuleTitle, Details, ExtraFieldInfo, RuleFile, ...
            level = row.get("Level", row.get("level", ""))
            severity = ResultParser.severity_from_hayabusa_level(level)

            # Skip info-level unless configured to include them
            if severity == SeverityLevel.INFO:
                continue

            title = row.get("RuleTitle", row.get("rule_title", "Unknown rule"))
            timestamp = row.get("Timestamp", row.get("timestamp", ""))
            computer = row.get("Computer", row.get("computer", ""))
            channel = row.get("Channel", row.get("channel", ""))
            details = row.get("Details", row.get("details", ""))

            findings.append(
                Finding(
                    tool_name="hayabusa",
                    severity=severity,
                    category="event_log_alert",
                    title=f"Hayabusa: {title}",
                    description=(
                        f"[{level}] {title} on {computer} "
                        f"(Channel: {channel}) — {details}"
                    ),
                    target=f"{computer}:{channel}",
                    raw_data=dict(row),
                )
            )

        return findings
