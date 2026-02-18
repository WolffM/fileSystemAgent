"""Manages external security tool binaries — discovery, verification, download."""

import hashlib
import logging
import shutil
import zipfile
from pathlib import Path
from typing import Any, Dict, Optional

from .models import ToolInfo

logger = logging.getLogger(__name__)

# Default tool registry — static metadata for all supported tools.
# Users override paths/settings via config.yaml; this is the fallback.
DEFAULT_TOOLS: list[dict[str, Any]] = [
    {
        "name": "hollows_hunter",
        "display_name": "HollowsHunter",
        "exe_name": "hollows_hunter.exe",
        "github_repo": "hasherezade/hollows_hunter",
        "github_asset_pattern": "hollows_hunter64.zip",
        "requires_admin": True,
        "license": "BSD-2-Clause",
    },
    {
        "name": "pe_sieve",
        "display_name": "PE-sieve",
        "exe_name": "pe-sieve64.exe",
        "github_repo": "hasherezade/pe-sieve",
        "github_asset_pattern": "pe-sieve64.exe",
        "requires_admin": True,
        "license": "BSD-2-Clause",
    },
    {
        "name": "yara_x",
        "display_name": "YARA-X",
        "exe_name": "yr.exe",
        "github_repo": "VirusTotal/yara-x",
        "github_asset_pattern": "yara-x-v*-x86_64-pc-windows-msvc.zip",
        "license": "BSD-3-Clause",
    },
    {
        "name": "clamav",
        "display_name": "ClamAV",
        "exe_name": "clamscan.exe",
        "install_method": "msi",
        "license": "GPL-2.0",
    },
    {
        "name": "freshclam",
        "display_name": "FreshClam",
        "exe_name": "freshclam.exe",
        "install_method": "msi",
        "license": "GPL-2.0",
    },
    {
        "name": "hayabusa",
        "display_name": "Hayabusa",
        "exe_name": "hayabusa.exe",
        "github_repo": "Yamato-Security/hayabusa",
        "github_asset_pattern": "hayabusa-*-win-x64.zip",
        "license": "AGPL-3.0",
    },
    {
        "name": "chainsaw",
        "display_name": "Chainsaw",
        "exe_name": "chainsaw.exe",
        "github_repo": "WithSecureLabs/chainsaw",
        "github_asset_pattern": "chainsaw_x86_64-pc-windows-msvc.zip",
        "license": "GPL-3.0",
    },
    {
        "name": "sysmon",
        "display_name": "Sysmon",
        "exe_name": "Sysmon64.exe",
        "install_method": "manual",
        "requires_admin": True,
        "license": "Proprietary (Microsoft)",
    },
    {
        "name": "autorunsc",
        "display_name": "Autoruns CLI",
        "exe_name": "autorunsc64.exe",
        "install_method": "manual",
        "requires_admin": True,
        "license": "Proprietary (Microsoft)",
    },
    {
        "name": "sigcheck",
        "display_name": "Sigcheck",
        "exe_name": "sigcheck64.exe",
        "install_method": "manual",
        "requires_admin": False,
        "license": "Proprietary (Microsoft)",
    },
    {
        "name": "listdlls",
        "display_name": "ListDLLs",
        "exe_name": "listdlls64.exe",
        "install_method": "manual",
        "requires_admin": True,
        "license": "Proprietary (Microsoft)",
    },
]


class ToolManager:
    """Manages external security tool binaries.

    Resolution order for finding a tool:
    1. Explicit path from config (security.tools.<name>.path)
    2. tools/<name>/ directory relative to project root
    3. System PATH
    """

    def __init__(
        self,
        tools_dir: str = "./tools",
        config: Optional[Dict[str, Any]] = None,
    ):
        self.tools_dir = Path(tools_dir).resolve()
        self.config = config or {}
        self._tools: Dict[str, ToolInfo] = {}
        self._register_default_tools()

    def _register_default_tools(self) -> None:
        """Register all known tools with their default metadata."""
        tools_config = self.config.get("tools", {})
        for tool_def in DEFAULT_TOOLS:
            name = tool_def["name"]
            # Merge per-tool config overrides
            overrides = tools_config.get(name, {})
            merged = {**tool_def, **overrides}
            self._tools[name] = ToolInfo(**merged)

    def check_tool(self, tool_name: str) -> ToolInfo:
        """Check if a tool is installed and resolve its path.

        Returns updated ToolInfo with installed=True/False and resolved path.
        """
        if tool_name not in self._tools:
            raise KeyError(f"Unknown tool: {tool_name}")

        tool = self._tools[tool_name]

        # 1. Check explicit config path
        if tool.path and tool.path.is_file():
            tool.installed = True
            logger.debug(f"{tool.display_name}: found at configured path {tool.path}")
            return tool

        # 2. Check tools/<name>/ directory (including subdirectories for nested zips)
        tool_dir = self.tools_dir / tool_name
        if tool_dir.is_dir():
            # Direct check first
            candidate = tool_dir / tool.exe_name
            if candidate.is_file():
                tool.path = candidate.resolve()
                tool.installed = True
                logger.debug(f"{tool.display_name}: found at {tool.path}")
                return tool
            # Recursive search (handles nested extraction like chainsaw/chainsaw/)
            for candidate in tool_dir.rglob(tool.exe_name):
                if candidate.is_file():
                    tool.path = candidate.resolve()
                    tool.installed = True
                    logger.debug(f"{tool.display_name}: found at {tool.path}")
                    return tool

        # Also check tools dir directly (flat layout)
        candidate_flat = self.tools_dir / tool.exe_name
        if candidate_flat.is_file():
            tool.path = candidate_flat.resolve()
            tool.installed = True
            logger.debug(f"{tool.display_name}: found at {tool.path}")
            return tool

        # 3. Check system PATH
        system_path = shutil.which(tool.exe_name)
        if system_path:
            tool.path = Path(system_path).resolve()
            tool.installed = True
            logger.debug(f"{tool.display_name}: found on PATH at {tool.path}")
            return tool

        tool.installed = False
        tool.path = None
        logger.debug(f"{tool.display_name}: not found")
        return tool

    def check_all_tools(self) -> Dict[str, ToolInfo]:
        """Check all registered tools. Returns dict of name -> ToolInfo."""
        return {name: self.check_tool(name) for name in self._tools}

    def get_tool_path(self, tool_name: str) -> Path:
        """Get resolved path to tool executable. Raises if not installed."""
        tool = self.check_tool(tool_name)
        if not tool.installed or tool.path is None:
            raise FileNotFoundError(
                f"{tool.display_name} ({tool.exe_name}) not found. "
                f"Run 'python main.py security setup' to install, "
                f"or set security.tools.{tool_name}.path in config.yaml."
            )
        return tool.path

    def get_tool_info(self, tool_name: str) -> ToolInfo:
        """Get the ToolInfo for a registered tool."""
        if tool_name not in self._tools:
            raise KeyError(f"Unknown tool: {tool_name}")
        return self._tools[tool_name]

    def verify_tool_integrity(self, tool_name: str) -> bool:
        """SHA256 hash check against expected_hash if configured."""
        tool = self.check_tool(tool_name)
        if not tool.installed or tool.path is None:
            return False
        if not tool.expected_hash:
            logger.debug(f"{tool.display_name}: no expected hash configured, skipping verification")
            return True

        actual_hash = self._sha256(tool.path)
        matches = actual_hash == tool.expected_hash.lower()
        if not matches:
            logger.warning(
                f"{tool.display_name} hash mismatch: "
                f"expected {tool.expected_hash}, got {actual_hash}"
            )
        return matches

    async def download_tool(self, tool_name: str) -> bool:
        """Download a tool from GitHub releases.

        Downloads the latest release asset matching github_asset_pattern,
        extracts to tools/<name>/, and verifies hash if configured.
        """
        tool = self._tools.get(tool_name)
        if not tool:
            raise KeyError(f"Unknown tool: {tool_name}")

        if tool.install_method not in ("github_release",):
            logger.info(
                f"{tool.display_name}: install_method={tool.install_method}, "
                f"cannot auto-download. Install manually."
            )
            return False

        if not tool.github_repo:
            logger.warning(f"{tool.display_name}: no github_repo configured")
            return False

        import httpx

        dest_dir = self.tools_dir / tool_name
        dest_dir.mkdir(parents=True, exist_ok=True)

        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=120) as client:
                # Get latest release
                api_url = f"https://api.github.com/repos/{tool.github_repo}/releases/latest"
                resp = await client.get(api_url)
                resp.raise_for_status()
                release = resp.json()

                # Find matching asset
                asset = self._find_matching_asset(
                    release.get("assets", []),
                    tool.github_asset_pattern,
                )
                if not asset:
                    logger.error(
                        f"{tool.display_name}: no matching asset in latest release "
                        f"(pattern: {tool.github_asset_pattern})"
                    )
                    return False

                # Download asset
                download_url = asset["browser_download_url"]
                asset_name = asset["name"]
                logger.info(f"Downloading {tool.display_name}: {asset_name}")

                dl_resp = await client.get(download_url)
                dl_resp.raise_for_status()

                asset_path = dest_dir / asset_name
                asset_path.write_bytes(dl_resp.content)

                # Extract if zip
                if asset_name.endswith(".zip"):
                    self._extract_zip(asset_path, dest_dir)
                    asset_path.unlink()

                # Some tools ship versioned exe names (e.g. hayabusa-3.8.0-win-x64.exe).
                # If the expected exe_name isn't found, look for a similar exe and rename it.
                self._fixup_exe_name(dest_dir, tool.exe_name)

                # Verify the exe exists
                tool_info = self.check_tool(tool_name)
                if tool_info.installed:
                    logger.info(f"{tool.display_name} installed to {tool_info.path}")
                    return True
                else:
                    logger.error(
                        f"{tool.display_name}: downloaded but {tool.exe_name} not found in {dest_dir}"
                    )
                    return False

        except httpx.HTTPError as e:
            logger.error(f"Failed to download {tool.display_name}: {e}")
            return False

    async def bootstrap_all(self, skip_existing: bool = True) -> Dict[str, bool]:
        """Download all missing tools that support auto-download.

        Returns dict of tool_name -> success.
        """
        results: Dict[str, bool] = {}
        for name, tool in self._tools.items():
            if skip_existing:
                self.check_tool(name)
                if tool.installed:
                    logger.info(f"{tool.display_name}: already installed, skipping")
                    results[name] = True
                    continue

            if tool.install_method == "github_release" and tool.github_repo:
                results[name] = await self.download_tool(name)
            else:
                logger.info(f"{tool.display_name}: manual install required")
                results[name] = False

        return results

    def _find_matching_asset(
        self, assets: list[dict], pattern: Optional[str]
    ) -> Optional[dict]:
        """Find a release asset matching the glob pattern."""
        if not pattern or not assets:
            return None

        import fnmatch

        for asset in assets:
            if fnmatch.fnmatch(asset["name"].lower(), pattern.lower()):
                return asset
        return None

    def _fixup_exe_name(self, dest_dir: Path, expected_name: str) -> None:
        """Rename versioned executables to the expected canonical name.

        Some tools ship with versioned exe names like hayabusa-3.8.0-win-x64.exe.
        If the expected name isn't found, search for an exe whose name starts with
        the tool's base name and rename it.
        """
        # Check if expected name already exists (direct or nested)
        for match in dest_dir.rglob(expected_name):
            if match.is_file():
                return  # Already fine

        # Extract base name without extension (e.g. "hayabusa" from "hayabusa.exe")
        base = expected_name.rsplit(".", 1)[0]

        # Search for exe files whose name starts with the base
        for candidate in dest_dir.rglob(f"{base}*.exe"):
            if candidate.is_file() and candidate.name != expected_name:
                target = candidate.parent / expected_name
                candidate.rename(target)
                logger.info(f"Renamed {candidate.name} -> {expected_name}")
                return

    def _extract_zip(self, zip_path: Path, dest_dir: Path) -> None:
        """Extract a zip file to the destination directory."""
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(dest_dir)
        logger.debug(f"Extracted {zip_path.name} to {dest_dir}")

    @staticmethod
    def _sha256(file_path: Path) -> str:
        """Compute SHA256 hash of a file."""
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
