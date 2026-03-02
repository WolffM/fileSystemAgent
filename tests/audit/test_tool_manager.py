"""Tests for the ToolManager — path resolution, verification, registry."""

import hashlib
import io
import zipfile
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pathlib import Path

from src.audit.tool_manager import ToolManager, DEFAULT_TOOLS


class TestToolManagerRegistry:
    def test_all_default_tools_registered(self, tmp_tools_dir):
        tm = ToolManager(tools_dir=str(tmp_tools_dir))
        tools = tm.check_all_tools()
        expected_names = {t["name"] for t in DEFAULT_TOOLS}
        assert set(tools.keys()) == expected_names

    def test_unknown_tool_raises(self, tmp_tools_dir):
        tm = ToolManager(tools_dir=str(tmp_tools_dir))
        with pytest.raises(KeyError, match="Unknown tool"):
            tm.check_tool("nonexistent_tool")

    def test_get_tool_info(self, tmp_tools_dir):
        tm = ToolManager(tools_dir=str(tmp_tools_dir))
        info = tm.get_tool_info("hollows_hunter")
        assert info.display_name == "HollowsHunter"
        assert info.exe_name == "hollows_hunter.exe"
        assert info.requires_admin is True

    def test_config_overrides(self, tmp_tools_dir):
        config = {
            "tools": {
                "hollows_hunter": {
                    "requires_admin": False,
                    "expected_hash": "custom_hash",
                }
            }
        }
        tm = ToolManager(tools_dir=str(tmp_tools_dir), config=config)
        info = tm.get_tool_info("hollows_hunter")
        assert info.requires_admin is False
        assert info.expected_hash == "custom_hash"


class TestToolManagerResolution:
    def test_not_found(self, tmp_tools_dir):
        tm = ToolManager(tools_dir=str(tmp_tools_dir))
        tool = tm.check_tool("hollows_hunter")
        assert tool.installed is False
        assert tool.path is None

    def test_found_in_subdirectory(self, tmp_tools_dir):
        # Create tools/hollows_hunter/hollows_hunter.exe
        tool_dir = tmp_tools_dir / "hollows_hunter"
        tool_dir.mkdir()
        exe = tool_dir / "hollows_hunter.exe"
        exe.write_text("fake binary")

        tm = ToolManager(tools_dir=str(tmp_tools_dir))
        tool = tm.check_tool("hollows_hunter")
        assert tool.installed is True
        assert tool.path == exe.resolve()

    def test_found_flat_layout(self, tmp_tools_dir):
        # Create tools/hollows_hunter.exe directly
        exe = tmp_tools_dir / "hollows_hunter.exe"
        exe.write_text("fake binary")

        tm = ToolManager(tools_dir=str(tmp_tools_dir))
        tool = tm.check_tool("hollows_hunter")
        assert tool.installed is True
        assert tool.path == exe.resolve()

    def test_config_path_override(self, tmp_path, tmp_tools_dir):
        # Create exe at a custom location
        custom_dir = tmp_path / "custom"
        custom_dir.mkdir()
        custom_exe = custom_dir / "hollows_hunter.exe"
        custom_exe.write_text("fake binary")

        config = {
            "tools": {
                "hollows_hunter": {
                    "path": str(custom_exe),
                }
            }
        }
        tm = ToolManager(tools_dir=str(tmp_tools_dir), config=config)
        tool = tm.check_tool("hollows_hunter")
        assert tool.installed is True
        assert tool.path == custom_exe

    def test_get_tool_path_raises_when_missing(self, tmp_tools_dir):
        tm = ToolManager(tools_dir=str(tmp_tools_dir))
        with pytest.raises(FileNotFoundError, match="not found"):
            tm.get_tool_path("hollows_hunter")

    def test_get_tool_path_returns_path_when_found(self, tmp_tools_dir):
        tool_dir = tmp_tools_dir / "hayabusa"
        tool_dir.mkdir()
        exe = tool_dir / "hayabusa.exe"
        exe.write_text("fake")

        tm = ToolManager(tools_dir=str(tmp_tools_dir))
        path = tm.get_tool_path("hayabusa")
        assert path == exe.resolve()

    def test_check_all_tools(self, tmp_tools_dir):
        # Install one tool, leave others missing
        tool_dir = tmp_tools_dir / "hayabusa"
        tool_dir.mkdir()
        (tool_dir / "hayabusa.exe").write_text("fake")

        tm = ToolManager(tools_dir=str(tmp_tools_dir))
        results = tm.check_all_tools()

        assert results["hayabusa"].installed is True
        assert results["hollows_hunter"].installed is False


class TestToolManagerIntegrity:
    def test_verify_no_hash_configured(self, tmp_tools_dir):
        tool_dir = tmp_tools_dir / "hollows_hunter"
        tool_dir.mkdir()
        (tool_dir / "hollows_hunter.exe").write_text("fake")

        tm = ToolManager(tools_dir=str(tmp_tools_dir))
        # No expected_hash configured — should return True (skip verification)
        assert tm.verify_tool_integrity("hollows_hunter") is True

    def test_verify_hash_matches(self, tmp_tools_dir):
        tool_dir = tmp_tools_dir / "hollows_hunter"
        tool_dir.mkdir()
        exe = tool_dir / "hollows_hunter.exe"
        content = b"fake binary content"
        exe.write_bytes(content)
        expected_hash = hashlib.sha256(content).hexdigest()

        config = {
            "tools": {
                "hollows_hunter": {"expected_hash": expected_hash}
            }
        }
        tm = ToolManager(tools_dir=str(tmp_tools_dir), config=config)
        assert tm.verify_tool_integrity("hollows_hunter") is True

    def test_verify_hash_mismatch(self, tmp_tools_dir):
        tool_dir = tmp_tools_dir / "hollows_hunter"
        tool_dir.mkdir()
        (tool_dir / "hollows_hunter.exe").write_bytes(b"real content")

        config = {
            "tools": {
                "hollows_hunter": {"expected_hash": "0000bad0000hash"}
            }
        }
        tm = ToolManager(tools_dir=str(tmp_tools_dir), config=config)
        assert tm.verify_tool_integrity("hollows_hunter") is False

    def test_verify_not_installed(self, tmp_tools_dir):
        tm = ToolManager(tools_dir=str(tmp_tools_dir))
        assert tm.verify_tool_integrity("hollows_hunter") is False


class TestToolManagerInstallMethods:
    """Verify that DEFAULT_TOOLS registry has no manual install methods."""

    def test_no_manual_install_methods(self):
        for tool_def in DEFAULT_TOOLS:
            method = tool_def.get("install_method", "github_release")
            assert method != "manual", (
                f"{tool_def['name']} still has install_method='manual'"
            )
            assert method != "msi", (
                f"{tool_def['name']} still has install_method='msi'"
            )

    def test_sysinternals_are_direct_url(self, tmp_tools_dir):
        tm = ToolManager(tools_dir=str(tmp_tools_dir))
        sysinternals = ["sysmon", "autorunsc", "sigcheck", "listdlls"]
        for name in sysinternals:
            info = tm.get_tool_info(name)
            assert info.install_method == "direct_url", (
                f"{name} should be direct_url, got {info.install_method}"
            )
            assert info.direct_url is not None, f"{name} missing direct_url"
            assert "sysinternals.com" in info.direct_url

    def test_all_tools_are_auto_downloadable(self, tmp_tools_dir):
        tm = ToolManager(tools_dir=str(tmp_tools_dir))
        for name, tool in tm._tools.items():
            can_auto = (
                (tool.install_method == "github_release" and tool.github_repo) or
                (tool.install_method == "direct_url" and tool.direct_url) or
                (tool.install_method == "shared" and getattr(tool, "shared_with", None))
            )
            assert can_auto, f"{name} cannot be auto-downloaded"


def _make_zip_bytes(filenames: list[str]) -> bytes:
    """Create an in-memory zip containing fake exe files."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for fn in filenames:
            zf.writestr(fn, "fake binary")
    return buf.getvalue()


class TestDownloadDirectUrl:

    @pytest.mark.asyncio
    async def test_download_direct_url_success(self, tmp_tools_dir):
        tm = ToolManager(tools_dir=str(tmp_tools_dir))
        zip_content = _make_zip_bytes(["sigcheck64.exe", "sigcheck.exe"])

        mock_response = MagicMock()
        mock_response.content = zip_content
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await tm._download_direct_url("sigcheck")

        assert result is True
        tool = tm.check_tool("sigcheck")
        assert tool.installed is True

    @pytest.mark.asyncio
    async def test_download_direct_url_no_url(self, tmp_tools_dir):
        config = {"tools": {"sigcheck": {"direct_url": None}}}
        tm = ToolManager(tools_dir=str(tmp_tools_dir), config=config)
        # Override to clear the direct_url
        tm._tools["sigcheck"].direct_url = None
        result = await tm._download_direct_url("sigcheck")
        assert result is False

    @pytest.mark.asyncio
    async def test_download_tool_dispatches_direct_url(self, tmp_tools_dir):
        tm = ToolManager(tools_dir=str(tmp_tools_dir))
        zip_content = _make_zip_bytes(["Sysmon64.exe", "Sysmon.exe"])

        mock_response = MagicMock()
        mock_response.content = zip_content
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await tm.download_tool("sysmon")

        assert result is True
        tool = tm.check_tool("sysmon")
        assert tool.installed is True

    @pytest.mark.asyncio
    async def test_bootstrap_all_includes_direct_url_tools(self, tmp_tools_dir):
        tm = ToolManager(tools_dir=str(tmp_tools_dir))

        # Pre-install all tools so bootstrap skips them
        for name, tool in tm._tools.items():
            shared = getattr(tool, "shared_with", None)
            # Shared tools live in the parent's directory
            dir_name = shared if shared else name
            tool_dir = tmp_tools_dir / dir_name
            tool_dir.mkdir(exist_ok=True)
            (tool_dir / tool.exe_name).write_text("fake")

        results = await tm.bootstrap_all(skip_existing=True)
        # All should be True (already installed)
        for name, success in results.items():
            assert success is True, f"{name} should be True (already installed)"

    @pytest.mark.asyncio
    async def test_bootstrap_all_attempts_direct_url(self, tmp_tools_dir):
        tm = ToolManager(tools_dir=str(tmp_tools_dir))

        # Pre-install all tools EXCEPT sigcheck
        for name, tool in tm._tools.items():
            if name == "sigcheck":
                continue
            tool_dir = tmp_tools_dir / name
            tool_dir.mkdir(exist_ok=True)
            (tool_dir / tool.exe_name).write_text("fake")

        zip_content = _make_zip_bytes(["sigcheck64.exe"])

        mock_response = MagicMock()
        mock_response.content = zip_content
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client):
            results = await tm.bootstrap_all(skip_existing=True)

        assert results["sigcheck"] is True


