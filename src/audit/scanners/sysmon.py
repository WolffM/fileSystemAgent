"""Sysmon manager — install, configure, and manage Sysmon service.

Sysmon is not a scanner; it's a continuous telemetry generator that
creates detailed event logs consumed by Hayabusa and Chainsaw.
This module manages Sysmon's lifecycle rather than running scans.
"""

import asyncio
import logging
from pathlib import Path
from typing import Any, Dict, Optional

from ..tool_manager import ToolManager

logger = logging.getLogger(__name__)


class SysmonManager:
    """Manages Sysmon installation and configuration."""

    def __init__(
        self,
        tool_manager: ToolManager,
        config: Optional[Dict[str, Any]] = None,
    ):
        self.tool_manager = tool_manager
        self.config = config or {}
        self.config_file = self.config.get("config_file", "./rules/sysmon/sysmonconfig.xml")
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    async def is_installed(self) -> bool:
        """Check if Sysmon service is running."""
        try:
            process = await asyncio.create_subprocess_exec(
                "sc", "query", "Sysmon64",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await process.communicate()
            output = stdout.decode("utf-8", errors="replace")
            return "RUNNING" in output
        except Exception:
            return False

    async def install(self, config_path: Optional[str] = None) -> bool:
        """Install Sysmon with the specified XML configuration.

        Requires administrator privileges.
        """
        try:
            exe = str(self.tool_manager.get_tool_path("sysmon"))
        except FileNotFoundError:
            self.logger.error("Sysmon executable not found")
            return False

        config_path = config_path or self.config_file
        if not Path(config_path).exists():
            self.logger.error(f"Sysmon config not found: {config_path}")
            return False

        self.logger.info(f"Installing Sysmon with config: {config_path}")
        try:
            process = await asyncio.create_subprocess_exec(
                exe, "-accepteula", "-i", config_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                self.logger.info("Sysmon installed successfully")
                return True
            else:
                self.logger.error(
                    f"Sysmon installation failed (code {process.returncode}): "
                    f"{stderr.decode('utf-8', errors='replace')}"
                )
                return False
        except Exception as e:
            self.logger.error(f"Failed to install Sysmon: {e}")
            return False

    async def update_config(self, config_path: Optional[str] = None) -> bool:
        """Update the running Sysmon configuration."""
        try:
            exe = str(self.tool_manager.get_tool_path("sysmon"))
        except FileNotFoundError:
            self.logger.error("Sysmon executable not found")
            return False

        config_path = config_path or self.config_file
        if not Path(config_path).exists():
            self.logger.error(f"Sysmon config not found: {config_path}")
            return False

        self.logger.info(f"Updating Sysmon config: {config_path}")
        try:
            process = await asyncio.create_subprocess_exec(
                exe, "-c", config_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                self.logger.info("Sysmon config updated successfully")
                return True
            else:
                self.logger.error(
                    f"Sysmon config update failed: "
                    f"{stderr.decode('utf-8', errors='replace')}"
                )
                return False
        except Exception as e:
            self.logger.error(f"Failed to update Sysmon config: {e}")
            return False

    async def uninstall(self) -> bool:
        """Uninstall Sysmon."""
        try:
            exe = str(self.tool_manager.get_tool_path("sysmon"))
        except FileNotFoundError:
            self.logger.error("Sysmon executable not found")
            return False

        self.logger.info("Uninstalling Sysmon...")
        try:
            process = await asyncio.create_subprocess_exec(
                exe, "-u",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await process.communicate()

            if process.returncode == 0:
                self.logger.info("Sysmon uninstalled successfully")
                return True
            else:
                self.logger.error(
                    f"Sysmon uninstall failed: "
                    f"{stderr.decode('utf-8', errors='replace')}"
                )
                return False
        except Exception as e:
            self.logger.error(f"Failed to uninstall Sysmon: {e}")
            return False

    async def get_status(self) -> Dict[str, Any]:
        """Get Sysmon service status."""
        installed = await self.is_installed()
        return {
            "installed": installed,
            "service_name": "Sysmon64",
            "config_file": self.config_file,
            "config_exists": Path(self.config_file).exists(),
        }
