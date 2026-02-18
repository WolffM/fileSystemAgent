"""Chainsaw scanner — multi-artifact forensic triage.

Analyzes .evtx files, MFT records, Shimcache, SRUM, and registry hives
using Sigma rules and built-in detection logic.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..models import Finding, ScanConfig, ScanResult, SeverityLevel
from ..result_parser import ResultParser
from ..scanner_base import ScannerBase
from ..tool_manager import ToolManager

logger = logging.getLogger(__name__)


class ChainsawScanner(ScannerBase):
    """Chainsaw forensic triage scanner."""

    @property
    def tool_name(self) -> str:
        return "chainsaw"

    def __init__(
        self,
        tool_manager: ToolManager,
        config: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(tool_manager, config)
        self.sigma_dir = self.config.get("sigma_dir", "./rules/sigma")
        self.mapping_file = self.config.get("mapping_file")

    def build_command(self, scan_config: ScanConfig, output_dir: Path) -> List[str]:
        exe = str(self.tool_manager.get_tool_path("chainsaw"))

        # Usage: chainsaw hunt [RULES] [PATH]... -s <SIGMA> --mapping <MAPPING>
        cmd = [exe, "hunt"]

        # Sigma rules via -s flag (not as positional RULES arg)
        sigma_dir = scan_config.extra_args.get("sigma_dir", self.sigma_dir)
        if Path(sigma_dir).exists():
            cmd.extend(["-s", str(Path(sigma_dir).resolve())])

        # Target directory (evtx files, or broader artifact path)
        target = scan_config.target.target_value
        if not target:
            target = "C:\\Windows\\System32\\winevt\\Logs"
        cmd.append(target)

        # Mapping file for Sigma rule translation
        mapping = scan_config.extra_args.get("mapping_file", self.mapping_file)
        if mapping and Path(mapping).exists():
            cmd.extend(["--mapping", str(Path(mapping).resolve())])

        # JSON output to stdout, suppress banner
        cmd.extend(["--json", "-q"])

        return cmd

    def _is_success_return_code(self, return_code) -> bool:
        # Chainsaw returns 1 when detections are found (not an error)
        return return_code == 1

    def parse_output(self, scan_result: ScanResult) -> List[Finding]:
        """Parse Chainsaw JSON output."""
        findings: List[Finding] = []

        # Try output files first
        for f in scan_result.output_files:
            if f.endswith(".json"):
                try:
                    data = ResultParser.parse_json_file(f)
                    findings.extend(self._parse_detections(data))
                except (json.JSONDecodeError, OSError) as e:
                    logger.error(f"Failed to parse Chainsaw output {f}: {e}")

        # Fall back to parsing stdout (Chainsaw may write JSON to stdout)
        if not findings and scan_result.stdout:
            # Extract JSON from stdout (may be mixed with banner text)
            text = scan_result.stdout.strip()
            # Find JSON array or object in the output
            for start_char in ("[", "{"):
                idx = text.find(start_char)
                if idx >= 0:
                    json_text = text[idx:]
                    try:
                        data = json.loads(json_text)
                        findings.extend(self._parse_detections(data))
                        break
                    except json.JSONDecodeError:
                        continue

        return findings

    def _parse_detections(self, data) -> List[Finding]:
        """Parse detection data from either a list or dict structure."""
        findings: List[Finding] = []
        if isinstance(data, list):
            for detection in data:
                findings.extend(self._detection_to_findings(detection))
        elif isinstance(data, dict):
            detections = data.get("detections", data.get("hits", [data]))
            for detection in detections:
                findings.extend(self._detection_to_findings(detection))
        return findings

    def _detection_to_findings(self, detection: Dict[str, Any]) -> List[Finding]:
        """Convert a Chainsaw detection to Finding objects."""
        findings: List[Finding] = []

        name = detection.get("name", detection.get("title", "Unknown detection"))
        level = detection.get("level", detection.get("severity", "medium"))
        severity = ResultParser.severity_from_sigma_level(level)

        # Skip info-level findings
        if severity == SeverityLevel.INFO:
            return findings

        timestamp = detection.get("timestamp", "")
        source = detection.get("source", detection.get("document", {}).get("path", ""))
        authors = detection.get("authors", "")

        description_parts = [name]
        if timestamp:
            description_parts.append(f"at {timestamp}")
        if source:
            description_parts.append(f"in {source}")

        findings.append(
            Finding(
                tool_name="chainsaw",
                severity=severity,
                category="event_log_alert",
                title=f"Chainsaw: {name}",
                description=" ".join(description_parts),
                target=str(source),
                raw_data=detection,
            )
        )

        return findings
