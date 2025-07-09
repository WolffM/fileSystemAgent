from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any, Union
from pydantic import BaseModel, Field, validator
from pathlib import Path
import hashlib


class HashAlgorithm(str, Enum):
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    SHA512 = "sha512"


class ConflictResolution(str, Enum):
    SKIP = "skip"           # Skip if destination exists
    OVERWRITE = "overwrite" # Overwrite destination
    RENAME = "rename"       # Rename with suffix
    BACKUP = "backup"       # Backup original, then overwrite
    FAIL = "fail"          # Fail if conflict


class FileOperation(str, Enum):
    COPY = "copy"
    MOVE = "move"
    LINK = "link"          # Hard link
    SYMLINK = "symlink"    # Symbolic link


class IndexingMode(str, Enum):
    NONE = "none"
    BASIC = "basic"        # File path, size, mtime
    FULL = "full"          # Basic + hash, metadata
    CONTENT = "content"    # Full + content analysis


class FileFilter(BaseModel):
    """File filtering configuration"""
    include_patterns: List[str] = Field(default_factory=list, description="Glob patterns to include")
    exclude_patterns: List[str] = Field(default_factory=list, description="Glob patterns to exclude")
    min_size: Optional[int] = Field(None, description="Minimum file size in bytes")
    max_size: Optional[int] = Field(None, description="Maximum file size in bytes")
    min_age: Optional[int] = Field(None, description="Minimum age in seconds")
    max_age: Optional[int] = Field(None, description="Maximum age in seconds")
    file_extensions: List[str] = Field(default_factory=list, description="Allowed file extensions")
    ignore_hidden: bool = Field(True, description="Ignore hidden files/directories")
    ignore_system: bool = Field(True, description="Ignore system files")


class PathMapping(BaseModel):
    """Source to destination path mapping"""
    source_path: str = Field(..., description="Source path (can contain wildcards)")
    destination_path: str = Field(..., description="Destination path template")
    preserve_structure: bool = Field(True, description="Preserve directory structure")
    create_directories: bool = Field(True, description="Create destination directories")
    
    @validator('source_path', 'destination_path')
    def validate_paths(cls, v):
        if not v.strip():
            raise ValueError("Path cannot be empty")
        return v.strip()


class FileMetadata(BaseModel):
    """File metadata structure"""
    file_path: str
    file_name: str
    file_size: int
    created_time: datetime
    modified_time: datetime
    accessed_time: Optional[datetime] = None
    file_hash: Optional[str] = None
    hash_algorithm: Optional[HashAlgorithm] = None
    mime_type: Optional[str] = None
    permissions: Optional[str] = None
    owner: Optional[str] = None
    group: Optional[str] = None
    is_directory: bool = False
    is_symlink: bool = False
    target_path: Optional[str] = None  # For symlinks
    custom_metadata: Dict[str, Any] = Field(default_factory=dict)


class FileIndex(BaseModel):
    """File indexing structure"""
    index_id: str
    index_path: str
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)
    total_files: int = 0
    total_size: int = 0
    hash_algorithm: HashAlgorithm = HashAlgorithm.SHA256
    files: Dict[str, FileMetadata] = Field(default_factory=dict)
    duplicates: Dict[str, List[str]] = Field(default_factory=dict)  # hash -> file_paths


class MigrationProgress(BaseModel):
    """Migration progress tracking"""
    total_files: int = 0
    processed_files: int = 0
    successful_files: int = 0
    failed_files: int = 0
    skipped_files: int = 0
    total_size: int = 0
    processed_size: int = 0
    start_time: datetime = Field(default_factory=datetime.now)
    current_file: Optional[str] = None
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)


class ETLTemplateConfig(BaseModel):
    """Comprehensive ETL template configuration"""
    
    # Basic Configuration
    template_name: str = Field(..., description="Template name")
    template_version: str = Field("1.0", description="Template version")
    description: Optional[str] = Field(None, description="Template description")
    
    # Path Configuration
    path_mappings: List[PathMapping] = Field(..., description="Source to destination mappings")
    working_directory: Optional[str] = Field(None, description="Working directory for relative paths")
    
    # File Operations
    operation: FileOperation = Field(FileOperation.COPY, description="File operation type")
    conflict_resolution: ConflictResolution = Field(ConflictResolution.SKIP, description="Conflict resolution strategy")
    preserve_timestamps: bool = Field(True, description="Preserve file timestamps")
    preserve_permissions: bool = Field(True, description="Preserve file permissions")
    
    # Filtering
    file_filter: FileFilter = Field(default_factory=FileFilter, description="File filtering rules")
    
    # Hashing & Indexing
    indexing_mode: IndexingMode = Field(IndexingMode.BASIC, description="Indexing level")
    hash_algorithm: HashAlgorithm = Field(HashAlgorithm.SHA256, description="Hash algorithm")
    verify_integrity: bool = Field(True, description="Verify file integrity after operations")
    index_output_path: Optional[str] = Field(None, description="Path to save file index")
    
    # Performance
    batch_size: int = Field(1000, description="Files to process in each batch")
    max_workers: int = Field(4, description="Maximum worker threads")
    memory_limit: Optional[int] = Field(None, description="Memory limit in MB")
    
    # Retry & Error Handling
    max_retries: int = Field(3, description="Maximum retry attempts")
    retry_delay: float = Field(1.0, description="Delay between retries in seconds")
    continue_on_error: bool = Field(True, description="Continue processing on individual file errors")
    
    # Monitoring & Logging
    progress_callback: bool = Field(True, description="Enable progress callbacks")
    log_level: str = Field("INFO", description="Logging level")
    detailed_logging: bool = Field(False, description="Enable detailed operation logging")
    
    # Validation
    dry_run: bool = Field(False, description="Perform dry run without actual operations")
    validate_sources: bool = Field(True, description="Validate source paths exist")
    validate_destinations: bool = Field(True, description="Validate destination paths are writable")
    
    # Custom Parameters
    custom_parameters: Dict[str, Any] = Field(default_factory=dict, description="Custom template parameters")
    
    @validator('batch_size', 'max_workers', 'max_retries')
    def validate_positive_integers(cls, v):
        if v <= 0:
            raise ValueError("Value must be positive")
        return v
    
    @validator('retry_delay')
    def validate_retry_delay(cls, v):
        if v < 0:
            raise ValueError("Retry delay cannot be negative")
        return v


class ETLTemplateResult(BaseModel):
    """ETL template execution result"""
    template_name: str
    execution_id: str
    start_time: datetime
    end_time: Optional[datetime] = None
    duration: Optional[float] = None
    status: str = "running"  # running, completed, failed, cancelled
    progress: MigrationProgress = Field(default_factory=MigrationProgress)
    file_index: Optional[FileIndex] = None
    error_message: Optional[str] = None
    summary: Dict[str, Any] = Field(default_factory=dict)
    
    def mark_completed(self):
        """Mark execution as completed"""
        self.end_time = datetime.now()
        self.duration = (self.end_time - self.start_time).total_seconds()
        self.status = "completed"
    
    def mark_failed(self, error: str):
        """Mark execution as failed"""
        self.end_time = datetime.now()
        self.duration = (self.end_time - self.start_time).total_seconds()
        self.status = "failed"
        self.error_message = error


class DuplicateGroup(BaseModel):
    """Group of duplicate files"""
    hash_value: str
    hash_algorithm: HashAlgorithm
    file_size: int
    file_count: int
    files: List[FileMetadata]
    created_at: datetime = Field(default_factory=datetime.now)
    
    @property
    def total_wasted_space(self) -> int:
        """Calculate total wasted space by duplicates"""
        return self.file_size * (self.file_count - 1)


class DuplicateReport(BaseModel):
    """Duplicate detection report"""
    scan_path: str
    scan_time: datetime = Field(default_factory=datetime.now)
    total_files_scanned: int
    total_size_scanned: int
    duplicate_groups: List[DuplicateGroup]
    total_duplicates: int
    total_wasted_space: int
    hash_algorithm: HashAlgorithm
    
    @property
    def duplicate_percentage(self) -> float:
        """Calculate percentage of duplicate files"""
        if self.total_files_scanned == 0:
            return 0.0
        return (self.total_duplicates / self.total_files_scanned) * 100