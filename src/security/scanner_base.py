"""Abstract base class for all security scanners.

Implements the template method pattern: subclasses override
build_command() and parse_output(), while run() handles the
common subprocess lifecycle.
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import Finding, ScanConfig, ScanResult, ScanStatus
from .tool_manager import ToolManager

logger = logging.getLogger(__name__)


class ScannerBase(ABC):
    """Abstract base for security tool scanners.

    Subclasses must implement:
      - tool_name: str property identifying the registered tool
      - build_command(scan_config) -> list of CLI arguments
      - parse_output(scan_result) -> list of normalized Finding objects
    """

    def __init__(
        self,
        tool_manager: ToolManager,
        config: Optional[Dict[str, Any]] = None,
    ):
        self.tool_manager = tool_manager
        self.config = config or {}
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    @property
    @abstractmethod
    def tool_name(self) -> str:
        """The registered tool name (e.g. 'hollows_hunter')."""

    @abstractmethod
    def build_command(self, scan_config: ScanConfig, output_dir: Path) -> List[str]:
        """Build the CLI command as a list of strings.

        Args:
            scan_config: The scan configuration.
            output_dir: Timestamped directory for this scan's output files.

        Returns:
            Command list suitable for asyncio.create_subprocess_exec.
        """

    @abstractmethod
    def parse_output(self, scan_result: ScanResult) -> List[Finding]:
        """Parse tool output into normalized Finding objects.

        Args:
            scan_result: The completed ScanResult with stdout, stderr,
                         and output_files populated.

        Returns:
            List of Finding objects extracted from the output.
        """

    def is_available(self) -> bool:
        """Check if the tool is installed and usable."""
        try:
            tool = self.tool_manager.check_tool(self.tool_name)
            return tool.installed
        except KeyError:
            return False

    async def run(self, scan_config: ScanConfig) -> ScanResult:
        """Execute the scan. This is the template method.

        1. Verify tool is available
        2. Create output directory
        3. Build command
        4. If dry_run, log and return
        5. Execute subprocess with timeout
        6. Parse output into findings
        7. Return ScanResult
        """
        result = ScanResult(
            tool_name=self.tool_name,
            config=scan_config,
        )

        # 1. Verify tool
        if not self.is_available():
            result.status = ScanStatus.SKIPPED
            result.error_message = (
                f"{self.tool_name} is not installed. "
                f"Run 'python main.py security setup' or install manually."
            )
            self.logger.warning(result.error_message)
            return result

        # 2. Create output directory
        output_dir = self._create_output_dir(scan_config)

        # 3. Build command
        try:
            cmd = self.build_command(scan_config, output_dir)
        except Exception as e:
            result.status = ScanStatus.FAILED
            result.error_message = f"Failed to build command: {e}"
            self.logger.error(result.error_message)
            return result

        self.logger.info(f"Running {self.tool_name}: {' '.join(cmd)}")

        # 4. Dry run
        if scan_config.dry_run:
            result.status = ScanStatus.COMPLETED
            result.stdout = f"[DRY RUN] Would execute: {' '.join(cmd)}"
            self.logger.info(result.stdout)
            return result

        # 5. Execute subprocess
        result.status = ScanStatus.RUNNING
        result.started_at = datetime.now()

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                process.communicate(),
                timeout=scan_config.timeout,
            )
            result.return_code = process.returncode
            result.stdout = stdout_bytes.decode("utf-8", errors="replace")
            result.stderr = stderr_bytes.decode("utf-8", errors="replace")

            # Collect output files
            if output_dir.exists():
                result.output_files = [
                    str(f) for f in output_dir.rglob("*") if f.is_file()
                ]

        except asyncio.TimeoutError:
            result.status = ScanStatus.TIMED_OUT
            result.error_message = (
                f"{self.tool_name} timed out after {scan_config.timeout}s"
            )
            self.logger.error(result.error_message)
            # Try to kill the process
            try:
                process.kill()
                await process.wait()
            except Exception:
                pass
            result.completed_at = datetime.now()
            if result.started_at:
                result.duration_seconds = (
                    result.completed_at - result.started_at
                ).total_seconds()
            return result

        except Exception as e:
            result.status = ScanStatus.FAILED
            result.error_message = f"Subprocess error: {e}"
            self.logger.error(result.error_message, exc_info=True)
            result.completed_at = datetime.now()
            if result.started_at:
                result.duration_seconds = (
                    result.completed_at - result.started_at
                ).total_seconds()
            return result

        result.completed_at = datetime.now()
        if result.started_at:
            result.duration_seconds = (
                result.completed_at - result.started_at
            ).total_seconds()

        # 6. Parse output
        try:
            result.findings = self.parse_output(result)
        except Exception as e:
            self.logger.error(f"Failed to parse {self.tool_name} output: {e}", exc_info=True)
            # Don't fail the whole scan — raw output is still captured
            result.findings = []

        # Determine final status
        if result.return_code == 0 or self._is_success_return_code(result.return_code):
            result.status = ScanStatus.COMPLETED
        else:
            result.status = ScanStatus.FAILED
            if not result.error_message:
                result.error_message = (
                    f"{self.tool_name} exited with code {result.return_code}"
                )

        self.logger.info(
            f"{self.tool_name} completed: {result.findings_count} findings, "
            f"exit code {result.return_code}"
        )
        return result

    def _create_output_dir(self, scan_config: ScanConfig) -> Path:
        """Create a timestamped output directory for this scan run."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = Path(scan_config.output_dir) / self.tool_name / timestamp
        output_dir.mkdir(parents=True, exist_ok=True)
        return output_dir

    def _is_success_return_code(self, return_code: Optional[int]) -> bool:
        """Override in subclasses where non-zero exit codes indicate findings, not errors.

        For example, ClamAV returns 1 when malware is found (which is a success,
        not an error). YARA returns 0 always.
        """
        return False
