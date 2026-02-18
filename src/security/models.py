"""Pydantic v2 models for the security scanning subsystem."""

import uuid
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    SKIPPED = "skipped"


class SeverityLevel(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ToolInfo(BaseModel):
    """Metadata and resolved location for an external security tool."""

    name: str
    display_name: str
    exe_name: str
    version: Optional[str] = None
    path: Optional[Path] = None
    expected_hash: Optional[str] = None
    github_repo: Optional[str] = None
    github_asset_pattern: Optional[str] = None
    requires_admin: bool = False
    installed: bool = False
    install_method: str = "github_release"
    license: str = ""

    model_config = ConfigDict(extra="allow")


class ScanTarget(BaseModel):
    """What to scan — a path, process, system, or event logs."""

    target_type: str = "path"  # "path", "process", "system", "eventlog"
    target_value: str = ""
    recursive: bool = True


class ScanConfig(BaseModel):
    """Configuration for a single scan invocation."""

    tool_name: str
    target: ScanTarget = Field(default_factory=ScanTarget)
    timeout: int = 600
    output_dir: str = "./data/security/scans"
    extra_args: Dict[str, Any] = Field(default_factory=dict)
    dry_run: bool = False


class Finding(BaseModel):
    """A single security finding from any tool, normalized to a common schema."""

    finding_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tool_name: str
    severity: SeverityLevel
    category: str
    title: str
    description: str
    target: str
    raw_data: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=datetime.now)
    mitre_attack: Optional[str] = None


class ScanResult(BaseModel):
    """Result of a single tool scan."""

    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tool_name: str
    status: ScanStatus = ScanStatus.PENDING
    config: ScanConfig
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    return_code: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    output_files: List[str] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    error_message: Optional[str] = None

    @property
    def findings_count(self) -> int:
        return len(self.findings)

    @property
    def has_critical(self) -> bool:
        return any(f.severity == SeverityLevel.CRITICAL for f in self.findings)

    @property
    def has_high(self) -> bool:
        return any(f.severity == SeverityLevel.HIGH for f in self.findings)


class PipelineConfig(BaseModel):
    """Configuration for a multi-tool scan pipeline."""

    name: str = "security_scan"
    description: str = ""
    steps: List[ScanConfig] = Field(default_factory=list)
    stop_on_failure: bool = False


class PipelineResult(BaseModel):
    """Aggregated result of a full pipeline execution."""

    pipeline_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    pipeline_name: str
    status: ScanStatus = ScanStatus.PENDING
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    scan_results: List[ScanResult] = Field(default_factory=list)

    @property
    def total_findings(self) -> int:
        return sum(r.findings_count for r in self.scan_results)

    @property
    def critical_findings(self) -> int:
        return sum(
            1
            for r in self.scan_results
            for f in r.findings
            if f.severity == SeverityLevel.CRITICAL
        )

    @property
    def high_findings(self) -> int:
        return sum(
            1
            for r in self.scan_results
            for f in r.findings
            if f.severity == SeverityLevel.HIGH
        )

    @property
    def duration_seconds(self) -> Optional[float]:
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None
