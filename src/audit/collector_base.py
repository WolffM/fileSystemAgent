"""Abstract base class for native Windows data collectors.

Collectors gather system information via WMI/CIM, PowerShell, or registry
reads — no external tool binary required. They follow a simpler pattern
than ScannerBase: collect() runs the collection logic and returns a
CollectorResult with structured data and optional findings.
"""

import asyncio
import ctypes
import logging
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, Optional

from .models import CollectorConfig, CollectorResult, Finding, ScanStatus

logger = logging.getLogger(__name__)


class CollectorBase(ABC):
    """Abstract base for native Windows data collectors."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self._admin_cached: Optional[bool] = None

    @property
    @abstractmethod
    def collector_name(self) -> str:
        """Unique identifier for this collector."""

    @abstractmethod
    async def collect(
        self, config: CollectorConfig, context: Dict[str, Any]
    ) -> CollectorResult:
        """Run the collection logic.

        Args:
            config: Collector configuration (timeout, extra_args).
            context: Shared pipeline context dict. Collectors write their
                     structured data here for downstream analyzers.

        Returns:
            CollectorResult with structured data and optional findings.
        """

    async def run(
        self, config: CollectorConfig, context: Dict[str, Any]
    ) -> CollectorResult:
        """Execute the collector with timing, error handling, and context update.

        This is the template method — subclasses override collect().
        """
        result = CollectorResult(
            collector_name=self.collector_name,
            status=ScanStatus.RUNNING,
            started_at=datetime.now(),
        )

        try:
            result = await asyncio.wait_for(
                self.collect(config, context),
                timeout=config.timeout,
            )
        except asyncio.TimeoutError:
            result.status = ScanStatus.TIMED_OUT
            result.error_message = (
                f"{self.collector_name} timed out after {config.timeout}s"
            )
            self.logger.error(result.error_message)
        except Exception as e:
            result.status = ScanStatus.FAILED
            result.error_message = f"{self.collector_name} error: {e}"
            self.logger.error(result.error_message, exc_info=True)

        if result.started_at:
            result.completed_at = datetime.now()
            result.duration_seconds = (
                result.completed_at - result.started_at
            ).total_seconds()

        # Write collected data into the shared pipeline context
        if result.status == ScanStatus.COMPLETED and result.data:
            context[self.collector_name] = result.data

        self.logger.info(
            f"{self.collector_name} {result.status.value}: "
            f"{result.findings_count} findings"
        )
        return result

    async def _run_powershell(
        self, script: str, timeout: int = 30
    ) -> str:
        """Execute a PowerShell script and return stdout.

        Args:
            script: PowerShell script text to execute.
            timeout: Seconds before killing the process.

        Returns:
            stdout as a string.

        Raises:
            RuntimeError: If PowerShell exits with a non-zero return code.
        """
        process = await asyncio.create_subprocess_exec(
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            process.communicate(),
            timeout=timeout,
        )
        stdout = stdout_bytes.decode("utf-8", errors="replace")
        stderr = stderr_bytes.decode("utf-8", errors="replace")

        if process.returncode != 0:
            raise RuntimeError(
                f"PowerShell exited with code {process.returncode}: {stderr[:500]}"
            )
        return stdout

    def _is_admin(self) -> bool:
        """Check if the current process has admin privileges. Result is cached."""
        if self._admin_cached is None:
            try:
                self._admin_cached = bool(
                    ctypes.windll.shell32.IsUserAnAdmin()  # type: ignore[attr-defined]
                )
            except (AttributeError, OSError):
                # Not on Windows or ctypes unavailable
                self._admin_cached = False
        return self._admin_cached
