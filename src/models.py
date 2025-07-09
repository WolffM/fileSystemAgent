from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field


class JobStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ETLOperationType(str, Enum):
    EXTRACT = "extract"
    TRANSFORM = "transform"
    LOAD = "load"
    FULL_ETL = "full_etl"


class ScheduleType(str, Enum):
    CRON = "cron"
    INTERVAL = "interval"
    ONCE = "once"


class ETLJob(BaseModel):
    id: str
    name: str
    operation_type: ETLOperationType
    source_path: str
    destination_path: Optional[str] = None
    transform_script: Optional[str] = None
    parameters: Dict[str, Any] = Field(default_factory=dict)
    status: JobStatus = JobStatus.PENDING
    created_at: datetime = Field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    progress: float = 0.0


class ScheduledJob(BaseModel):
    id: str
    name: str
    script_path: str
    schedule_type: ScheduleType
    schedule_expression: str
    enabled: bool = True
    last_run: Optional[datetime] = None
    next_run: Optional[datetime] = None
    parameters: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.now)


class FileSystemEvent(BaseModel):
    event_type: str
    file_path: str
    timestamp: datetime = Field(default_factory=datetime.now)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AgentConfig(BaseModel):
    name: str
    log_level: str
    data_dir: str
    scripts_dir: str
    logs_dir: str
    
    class Config:
        extra = "allow"