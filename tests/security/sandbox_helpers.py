"""Shared utilities and fixtures for E2E sandbox testing."""

from pathlib import Path

from src.security.tool_manager import ToolManager

# Project root
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

# Sandbox directory containing test artifacts
SANDBOX_DIR = Path(__file__).resolve().parent / "sandbox"

# Tools directory
TOOLS_DIR = PROJECT_ROOT / "tools"

# YARA test rule directory
YARA_RULES_DIR = SANDBOX_DIR / "test_rules"

# Sample evtx file
SAMPLE_EVTX = SANDBOX_DIR / "sample.evtx"

# Chainsaw mapping file (bundled with chainsaw release)
CHAINSAW_MAPPINGS = TOOLS_DIR / "chainsaw" / "chainsaw" / "mappings"


def get_tool_manager() -> ToolManager:
    """Create a ToolManager pointed at the project's tools/ directory."""
    return ToolManager(tools_dir=str(TOOLS_DIR))


def is_tool_available(tool_name: str) -> bool:
    """Check if a specific tool binary is installed."""
    try:
        tm = get_tool_manager()
        info = tm.check_tool(tool_name)
        return info.installed
    except KeyError:
        return False
