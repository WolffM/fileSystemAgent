"""Security scanning subsystem for FileSystemAgent.

Integrates external security tools (HollowsHunter, YARA-X, ClamAV,
Hayabusa, Chainsaw, Sysmon, Sysinternals) into a managed scanning
pipeline with structured results and monitoring.
"""

from .models import (
    ToolInfo,
    ScanTarget,
    ScanConfig,
    ScanStatus,
    SeverityLevel,
    Finding,
    ScanResult,
    PipelineConfig,
    PipelineResult,
)
from .tool_manager import ToolManager
from .scanner_base import ScannerBase

__all__ = [
    "ToolInfo",
    "ScanTarget",
    "ScanConfig",
    "ScanStatus",
    "SeverityLevel",
    "Finding",
    "ScanResult",
    "PipelineConfig",
    "PipelineResult",
    "ToolManager",
    "ScannerBase",
]
