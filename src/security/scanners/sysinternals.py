"""Sysinternals CLI tool scanners — autorunsc, sigcheck, listdlls.

These are proprietary freeware from Microsoft (not FOSS) but are essential
complements for persistence auditing and unsigned binary/DLL detection.
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


class AutorunscScanner(ScannerBase):
    """Autoruns CLI scanner — enumerates persistence locations."""

    @property
    def tool_name(self) -> str:
        return "autorunsc"

    def build_command(self, scan_config: ScanConfig, output_dir: Path) -> List[str]:
        exe = str(self.tool_manager.get_tool_path("autorunsc"))
        cmd = [
            exe,
            "-a", "*",      # All autostart categories
            "-c",            # CSV output
            "-h",            # Show file hashes
            "-s",            # Verify digital signatures
            "-m",            # Hide Microsoft entries
            "-accepteula",
        ]
        # VirusTotal checking (optional, requires internet)
        if scan_config.extra_args.get("virustotal", False):
            cmd.append("-vt")

        return cmd

    def parse_output(self, scan_result: ScanResult) -> List[Finding]:
        """Parse autorunsc CSV output for suspicious entries."""
        findings: List[Finding] = []
        text = scan_result.stdout
        if not text:
            return findings

        rows = ResultParser.parse_csv_output(text)
        for row in rows:
            signer = row.get("Signer", row.get("Publisher", ""))
            verified = row.get("Verified", "")
            entry = row.get("Entry", row.get("Entry Location", ""))
            image_path = row.get("Image Path", "")
            launch_string = row.get("Launch String", "")

            # Flag unsigned entries
            if verified and "not verified" in verified.lower():
                findings.append(
                    Finding(
                        tool_name="autorunsc",
                        severity=SeverityLevel.HIGH,
                        category="persistence",
                        title=f"Autoruns: unsigned entry at {entry}",
                        description=(
                            f"Unsigned autostart entry: {entry}. "
                            f"Image: {image_path}. Launch: {launch_string}"
                        ),
                        target=image_path or entry,
                        raw_data=dict(row),
                        mitre_attack="T1547",
                    )
                )
            # Flag entries with VirusTotal hits
            vt_detection = row.get("VT detection", row.get("VirusTotal", ""))
            if vt_detection and vt_detection not in ("", "0|0", "Unknown"):
                try:
                    parts = vt_detection.split("|")
                    if len(parts) == 2 and int(parts[0]) > 0:
                        findings.append(
                            Finding(
                                tool_name="autorunsc",
                                severity=SeverityLevel.CRITICAL,
                                category="persistence",
                                title=f"Autoruns: VT hit on {entry}",
                                description=(
                                    f"VirusTotal detection {vt_detection} "
                                    f"for autostart entry: {entry}. "
                                    f"Image: {image_path}"
                                ),
                                target=image_path or entry,
                                raw_data=dict(row),
                                mitre_attack="T1547",
                            )
                        )
                except (ValueError, IndexError):
                    pass

        return findings


class SigcheckScanner(ScannerBase):
    """Sigcheck scanner — finds unsigned executables."""

    @property
    def tool_name(self) -> str:
        return "sigcheck"

    def __init__(
        self,
        tool_manager: ToolManager,
        config: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(tool_manager, config)
        self.target_path = self.config.get("target_path", "C:\\Windows\\System32")

    def build_command(self, scan_config: ScanConfig, output_dir: Path) -> List[str]:
        exe = str(self.tool_manager.get_tool_path("sigcheck"))
        target = scan_config.target.target_value or self.target_path

        cmd = [
            exe,
            "-u",            # Show only unsigned files
            "-e",            # Scan executables only
            "-s",            # Recurse subdirectories
            "-c",            # CSV output
            "-accepteula",
            target,
        ]
        return cmd

    def parse_output(self, scan_result: ScanResult) -> List[Finding]:
        """Parse sigcheck CSV output for unsigned binaries."""
        findings: List[Finding] = []
        text = scan_result.stdout
        if not text:
            return findings

        rows = ResultParser.parse_csv_output(text)
        for row in rows:
            path = row.get("Path", "")
            verified = row.get("Verified", "")
            publisher = row.get("Publisher", "")

            if verified.lower() == "unsigned":
                findings.append(
                    Finding(
                        tool_name="sigcheck",
                        severity=SeverityLevel.MEDIUM,
                        category="unsigned_binary",
                        title=f"Sigcheck: unsigned binary {Path(path).name}",
                        description=(
                            f"Unsigned executable found: {path}. "
                            f"Publisher: {publisher or 'unknown'}"
                        ),
                        target=path,
                        raw_data=dict(row),
                    )
                )

        return findings


class ListDllsScanner(ScannerBase):
    """ListDLLs scanner — detects unsigned DLLs loaded into processes."""

    @property
    def tool_name(self) -> str:
        return "listdlls"

    def build_command(self, scan_config: ScanConfig, output_dir: Path) -> List[str]:
        exe = str(self.tool_manager.get_tool_path("listdlls"))
        cmd = [
            exe,
            "-u",            # Show only unsigned DLLs
            "-accepteula",
        ]
        return cmd

    def parse_output(self, scan_result: ScanResult) -> List[Finding]:
        """Parse listdlls text output for unsigned loaded DLLs.

        listdlls output format (text, not CSV):
        ==============================================================================
        <process_name> pid: <pid>
        Command line: <cmdline>
        ...
          0x<base>  0x<size>  <version>  <path>
        """
        findings: List[Finding] = []
        text = scan_result.stdout
        if not text:
            return findings

        current_process = ""
        current_pid = ""

        for line in text.splitlines():
            line = line.strip()

            # Process header line
            if "pid:" in line.lower():
                parts = line.split("pid:")
                if len(parts) == 2:
                    current_process = parts[0].strip()
                    current_pid = parts[1].strip()
                continue

            # DLL line: starts with 0x (hex address)
            if line.startswith("0x"):
                parts = line.split()
                if len(parts) >= 4:
                    dll_path = " ".join(parts[3:])  # Path may contain spaces
                    findings.append(
                        Finding(
                            tool_name="listdlls",
                            severity=SeverityLevel.MEDIUM,
                            category="unsigned_dll",
                            title=f"ListDLLs: unsigned DLL in {current_process}",
                            description=(
                                f"Unsigned DLL loaded into {current_process} "
                                f"(PID {current_pid}): {dll_path}"
                            ),
                            target=dll_path,
                            raw_data={
                                "process": current_process,
                                "pid": current_pid,
                                "dll_path": dll_path,
                            },
                            mitre_attack="T1055.001",
                        )
                    )

        return findings
