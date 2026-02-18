"""YARA-X scanner — pattern-based malware detection.

Scans files and process memory against YARA rule sets.
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


class YaraScanner(ScannerBase):
    """YARA-X pattern-based malware scanner."""

    @property
    def tool_name(self) -> str:
        return "yara_x"

    def __init__(
        self,
        tool_manager: ToolManager,
        config: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(tool_manager, config)
        self.rules_dir = self.config.get("rules_dir", "./rules/yara")

    def build_command(self, scan_config: ScanConfig, output_dir: Path) -> List[str]:
        exe = str(self.tool_manager.get_tool_path("yara_x"))
        rules_dir = scan_config.extra_args.get("rules_dir", self.rules_dir)
        output_file = output_dir / "yara_results.json"

        cmd = [exe, "scan", str(rules_dir)]

        # Target: path or PID
        if scan_config.target.target_type == "process":
            cmd.extend(["--pid", scan_config.target.target_value])
        else:
            cmd.append(scan_config.target.target_value)

        cmd.extend(["--output-format", "json"])

        # Recurse into directories
        if scan_config.target.recursive:
            cmd.append("-r")

        return cmd

    def parse_output(self, scan_result: ScanResult) -> List[Finding]:
        """Parse YARA-X JSON output into findings.

        YARA-X v1.x outputs a single JSON object:
        {"version": "...", "matches": [{"rule": "...", "file": "..."}]}
        """
        findings: List[Finding] = []

        text = scan_result.stdout.strip()
        if not text:
            return findings

        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            # Fall back to line-by-line parsing for unexpected formats
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    findings.extend(self._match_to_findings(data))
                except json.JSONDecodeError:
                    continue
            return findings

        # YARA-X v1.x format: {"version": "...", "matches": [...]}
        if "matches" in data:
            for match in data["matches"]:
                findings.extend(self._match_to_findings(match))
        else:
            # Single match object
            findings.extend(self._match_to_findings(data))

        return findings

    def _match_to_findings(self, match: Dict[str, Any]) -> List[Finding]:
        """Convert a single YARA match to Finding objects."""
        findings: List[Finding] = []

        # YARA-X v1.x: {"rule": "RuleName", "file": "path"}
        # Also support older format: {"path": "...", "rules": [...]}
        if "rule" in match:
            rule_name = match["rule"]
            file_path = match.get("file", "unknown")
            metadata = match.get("metadata", {})

            severity = SeverityLevel.HIGH
            if isinstance(metadata, dict) and "severity" in metadata:
                sev = metadata["severity"].lower()
                severity = {
                    "critical": SeverityLevel.CRITICAL,
                    "high": SeverityLevel.HIGH,
                    "medium": SeverityLevel.MEDIUM,
                    "low": SeverityLevel.LOW,
                    "info": SeverityLevel.INFO,
                }.get(sev, SeverityLevel.HIGH)

            description = (
                metadata.get("description", f"YARA rule '{rule_name}' matched")
                if isinstance(metadata, dict) else f"YARA rule '{rule_name}' matched"
            )
            mitre = metadata.get("mitre_attack") if isinstance(metadata, dict) else None

            findings.append(
                Finding(
                    tool_name="yara_x",
                    severity=severity,
                    category="suspicious_pattern",
                    title=f"YARA: {rule_name}",
                    description=f"{description} — matched in {file_path}",
                    target=file_path,
                    raw_data=match,
                    mitre_attack=mitre,
                )
            )
        elif "rules" in match:
            # Older format: {"path": "...", "rules": [{"identifier": "..."}]}
            file_path = match.get("path", "unknown")
            for rule in match["rules"]:
                rule_name = rule.get("identifier", "unknown_rule")
                metadata = rule.get("metadata", {})

                severity = SeverityLevel.HIGH
                if "severity" in metadata:
                    sev = metadata["severity"].lower()
                    severity = {
                        "critical": SeverityLevel.CRITICAL,
                        "high": SeverityLevel.HIGH,
                        "medium": SeverityLevel.MEDIUM,
                        "low": SeverityLevel.LOW,
                        "info": SeverityLevel.INFO,
                    }.get(sev, SeverityLevel.HIGH)

                description = metadata.get(
                    "description",
                    f"YARA rule '{rule_name}' matched"
                )
                mitre = metadata.get("mitre_attack")

                findings.append(
                    Finding(
                        tool_name="yara_x",
                        severity=severity,
                        category="suspicious_pattern",
                        title=f"YARA: {rule_name}",
                        description=f"{description} — matched in {file_path}",
                        target=file_path,
                        raw_data=match,
                        mitre_attack=mitre,
                    )
                )

        return findings
