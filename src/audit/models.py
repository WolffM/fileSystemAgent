"""Pydantic v2 models for the audit subsystem."""

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


class FindingDomain(str, Enum):
    SECURITY = "security"
    PERFORMANCE = "performance"
    HYGIENE = "hygiene"


class ToolInfo(BaseModel):
    """Metadata and resolved location for an external audit tool."""

    name: str
    display_name: str
    exe_name: str
    version: Optional[str] = None
    path: Optional[Path] = None
    expected_hash: Optional[str] = None
    github_repo: Optional[str] = None
    github_asset_pattern: Optional[str] = None
    direct_url: Optional[str] = None
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
    output_dir: str = "./data/audit/scans"
    extra_args: Dict[str, Any] = Field(default_factory=dict)
    dry_run: bool = False


class Finding(BaseModel):
    """A single finding from any tool, normalized to a common schema."""

    finding_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tool_name: str
    severity: SeverityLevel
    category: str
    title: str
    description: str
    target: str
    domain: FindingDomain = FindingDomain.SECURITY
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


# ---- Collector data models ----

class ProcessInfo(BaseModel):
    """Snapshot of a single running process."""

    pid: int
    name: str
    path: Optional[str] = None
    command_line: Optional[str] = None
    parent_pid: Optional[int] = None
    user: Optional[str] = None
    cpu_percent: float = 0.0
    ram_mb: float = 0.0
    thread_count: int = 0
    handle_count: int = 0
    created_at: Optional[str] = None
    is_signed: Optional[bool] = None
    signer: Optional[str] = None


class ServiceInfo(BaseModel):
    """Snapshot of a Windows service with vulnerability flags."""

    name: str
    display_name: str
    state: str  # Running, Stopped, etc.
    start_mode: str  # Auto, Manual, Disabled
    binary_path: Optional[str] = None
    account: str = ""  # LocalSystem, LocalService, etc.
    description: Optional[str] = None
    unquoted_path: bool = False
    system_with_writable_binary: bool = False
    non_standard_binary_location: bool = False


class NetworkConnection(BaseModel):
    """Snapshot of a TCP connection."""

    local_address: str
    local_port: int
    remote_address: Optional[str] = None
    remote_port: Optional[int] = None
    state: str  # Established, Listen, TimeWait, etc.
    pid: int
    process_name: Optional[str] = None
    is_outbound_external: bool = False


class ScheduledTaskInfo(BaseModel):
    """Snapshot of a Windows scheduled task."""

    task_name: str
    task_path: str = ""
    state: str = "Unknown"  # Ready, Running, Disabled
    execute: Optional[str] = None
    arguments: Optional[str] = None
    user_id: Optional[str] = None
    run_level: str = "Limited"  # Limited or Highest


class RunKeyEntry(BaseModel):
    """Snapshot of a registry Run key entry."""

    registry_path: str
    name: str
    value: str


class CollectorConfig(BaseModel):
    """Configuration for a single collector invocation."""

    collector_name: str
    timeout: int = 60
    extra_args: Dict[str, Any] = Field(default_factory=dict)


class AnalyzerConfig(BaseModel):
    """Configuration for a single analyzer invocation."""

    analyzer_name: str
    extra_args: Dict[str, Any] = Field(default_factory=dict)


class AnalyzerResult(BaseModel):
    """Result of a single analyzer run."""

    analyzer_name: str
    status: ScanStatus = ScanStatus.PENDING
    data: Dict[str, Any] = Field(default_factory=dict)
    findings: List[Finding] = Field(default_factory=list)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    error_message: Optional[str] = None

    @property
    def findings_count(self) -> int:
        return len(self.findings)


class CollectorResult(BaseModel):
    """Result of a single collector run."""

    collector_name: str
    status: ScanStatus = ScanStatus.PENDING
    data: Dict[str, Any] = Field(default_factory=dict)
    findings: List[Finding] = Field(default_factory=list)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    error_message: Optional[str] = None

    @property
    def findings_count(self) -> int:
        return len(self.findings)


class PipelineConfig(BaseModel):
    """Configuration for a multi-tool scan pipeline."""

    name: str = "audit_scan"
    description: str = ""
    steps: List[ScanConfig] = Field(default_factory=list)
    collectors: List[CollectorConfig] = Field(default_factory=list)
    analyzers: List[AnalyzerConfig] = Field(default_factory=list)
    stop_on_failure: bool = False


class PipelineResult(BaseModel):
    """Aggregated result of a full pipeline execution."""

    pipeline_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    pipeline_name: str
    status: ScanStatus = ScanStatus.PENDING
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    scan_results: List[ScanResult] = Field(default_factory=list)
    collector_results: List[CollectorResult] = Field(default_factory=list)
    analyzer_results: List[AnalyzerResult] = Field(default_factory=list)

    @property
    def _all_findings(self) -> List[Finding]:
        findings: List[Finding] = []
        for r in self.scan_results:
            findings.extend(r.findings)
        for r in self.collector_results:
            findings.extend(r.findings)
        for r in self.analyzer_results:
            findings.extend(r.findings)
        return findings

    @property
    def total_findings(self) -> int:
        return len(self._all_findings)

    @property
    def critical_findings(self) -> int:
        return sum(1 for f in self._all_findings if f.severity == SeverityLevel.CRITICAL)

    @property
    def high_findings(self) -> int:
        return sum(1 for f in self._all_findings if f.severity == SeverityLevel.HIGH)

    @property
    def duration_seconds(self) -> Optional[float]:
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None
