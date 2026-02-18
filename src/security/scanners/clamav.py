"""ClamAV scanner — signature-based antivirus scanning.

Two-phase operation: freshclam updates signatures, then clamscan runs the scan.
ClamAV returns exit code 1 when malware is found (not an error).
"""

import asyncio
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..models import Finding, ScanConfig, ScanResult, ScanStatus, SeverityLevel
from ..result_parser import ResultParser
from ..scanner_base import ScannerBase
from ..tool_manager import ToolManager

logger = logging.getLogger(__name__)


class ClamAVScanner(ScannerBase):
    """ClamAV antivirus scanner using clamscan CLI."""

    @property
    def tool_name(self) -> str:
        return "clamav"

    def __init__(
        self,
        tool_manager: ToolManager,
        config: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(tool_manager, config)
        self.update_before_scan = self.config.get("update_before_scan", True)

    def build_command(self, scan_config: ScanConfig, output_dir: Path) -> List[str]:
        exe = str(self.tool_manager.get_tool_path("clamav"))
        log_file = output_dir / "clamscan.log"

        cmd = [exe]
        if scan_config.target.recursive:
            cmd.append("-r")
        cmd.append(f"--log={log_file}")

        # Extra args
        if "max_filesize" in scan_config.extra_args:
            cmd.append(f"--max-filesize={scan_config.extra_args['max_filesize']}")
        if "max_scansize" in scan_config.extra_args:
            cmd.append(f"--max-scansize={scan_config.extra_args['max_scansize']}")
        if scan_config.extra_args.get("no_summary", False):
            cmd.append("--no-summary")

        cmd.append(scan_config.target.target_value)
        return cmd

    def parse_output(self, scan_result: ScanResult) -> List[Finding]:
        """Parse clamscan stdout/log for detections."""
        # clamscan writes detections to both stdout and log file
        text = scan_result.stdout
        parsed = ResultParser.parse_clamscan_log(text)

        findings: List[Finding] = []
        for detection in parsed["detections"]:
            findings.append(
                Finding(
                    tool_name="clamav",
                    severity=SeverityLevel.HIGH,
                    category="malware_signature",
                    title=f"ClamAV: {detection['malware']}",
                    description=(
                        f"ClamAV detected known malware signature "
                        f"'{detection['malware']}' in file: {detection['file']}"
                    ),
                    target=detection["file"],
                    raw_data=detection,
                )
            )
        return findings

    def _is_success_return_code(self, return_code: Optional[int]) -> bool:
        # ClamAV: 0 = no malware, 1 = malware found, 2 = error
        return return_code == 1

    async def run(self, scan_config: ScanConfig) -> ScanResult:
        """Override to optionally run freshclam before scanning."""
        if self.update_before_scan and not scan_config.dry_run:
            await self._update_signatures()
        return await super().run(scan_config)

    async def _update_signatures(self) -> None:
        """Run freshclam to update ClamAV signature database."""
        try:
            freshclam_path = self.tool_manager.get_tool_path("freshclam")
        except FileNotFoundError:
            self.logger.warning("freshclam not found, skipping signature update")
            return

        self.logger.info("Updating ClamAV signatures via freshclam...")
        try:
            process = await asyncio.create_subprocess_exec(
                str(freshclam_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=120
            )
            if process.returncode == 0:
                self.logger.info("ClamAV signatures updated successfully")
            else:
                self.logger.warning(
                    f"freshclam exited with code {process.returncode}: "
                    f"{stderr.decode('utf-8', errors='replace')}"
                )
        except asyncio.TimeoutError:
            self.logger.warning("freshclam timed out after 120s")
        except Exception as e:
            self.logger.warning(f"Failed to update ClamAV signatures: {e}")
