"""Tests for the ToolManager — path resolution, verification, registry."""

import hashlib
import pytest
from pathlib import Path

from src.security.tool_manager import ToolManager, DEFAULT_TOOLS


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
        tool_dir = tmp_tools_dir / "clamav"
        tool_dir.mkdir()
        exe = tool_dir / "clamscan.exe"
        exe.write_text("fake")

        tm = ToolManager(tools_dir=str(tmp_tools_dir))
        path = tm.get_tool_path("clamav")
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
        assert results["clamav"].installed is False


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
