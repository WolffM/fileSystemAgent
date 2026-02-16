import os
import shutil
import hashlib
import json
import uuid
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable, Iterator
import logging
import mimetypes
import fnmatch

from .template_models import (
    ETLTemplateConfig, ETLTemplateResult, FileMetadata, FileIndex,
    MigrationProgress, DuplicateGroup, DuplicateReport, PathMapping,
    HashAlgorithm, ConflictResolution, FileOperation, IndexingMode
)


class ETLTemplateBase(ABC):
    """Base class for ETL templates"""
    
    def __init__(self, config: ETLTemplateConfig):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.result: Optional[ETLTemplateResult] = None
        self.file_index: Optional[FileIndex] = None
        self.progress_callback: Optional[Callable] = None
        
        # Setup logging
        self._setup_logging()
        
        # Initialize result
        self.result = ETLTemplateResult(
            template_name=config.template_name,
            execution_id=str(uuid.uuid4()),
            start_time=datetime.now()
        )
    
    def _setup_logging(self):
        """Setup logging configuration"""
        log_level = getattr(logging, self.config.log_level.upper())
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(log_level)
    
    def set_progress_callback(self, callback: Callable[[MigrationProgress], None]):
        """Set progress callback function"""
        self.progress_callback = callback
    
    def _update_progress(self, **kwargs):
        """Update progress and call callback if set"""
        for key, value in kwargs.items():
            if hasattr(self.result.progress, key):
                setattr(self.result.progress, key, value)
        
        if self.progress_callback:
            self.progress_callback(self.result.progress)
    
    def _calculate_file_hash(self, file_path: Path, algorithm: HashAlgorithm = HashAlgorithm.SHA256) -> str:
        """Calculate file hash"""
        hash_func = getattr(hashlib, algorithm.value)()
        
        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    hash_func.update(chunk)
            return hash_func.hexdigest()
        except Exception as e:
            self.logger.error(f"Error calculating hash for {file_path}: {e}")
            return ""
    
    def _get_file_metadata(self, file_path: Path, include_hash: bool = True) -> FileMetadata:
        """Get comprehensive file metadata"""
        try:
            stat_info = file_path.stat()
            
            metadata = FileMetadata(
                file_path=str(file_path),
                file_name=file_path.name,
                file_size=stat_info.st_size,
                created_time=datetime.fromtimestamp(stat_info.st_ctime),
                modified_time=datetime.fromtimestamp(stat_info.st_mtime),
                accessed_time=datetime.fromtimestamp(stat_info.st_atime),
                is_directory=file_path.is_dir(),
                is_symlink=file_path.is_symlink(),
                permissions=oct(stat_info.st_mode)[-3:],
            )
            
            # Add hash if requested and not a directory
            if include_hash and not metadata.is_directory:
                metadata.file_hash = self._calculate_file_hash(file_path, self.config.hash_algorithm)
                metadata.hash_algorithm = self.config.hash_algorithm
            
            # Add MIME type
            if not metadata.is_directory:
                metadata.mime_type = mimetypes.guess_type(str(file_path))[0]
            
            # Add symlink target
            if metadata.is_symlink:
                metadata.target_path = str(file_path.readlink())
            
            # Add owner info (Unix only)
            try:
                import pwd, grp
                metadata.owner = pwd.getpwuid(stat_info.st_uid).pw_name
                metadata.group = grp.getgrgid(stat_info.st_gid).gr_name
            except (ImportError, KeyError):
                pass
            
            return metadata
            
        except Exception as e:
            self.logger.error(f"Error getting metadata for {file_path}: {e}")
            raise
    
    def _matches_filter(self, file_path: Path, metadata: FileMetadata) -> bool:
        """Check if file matches filter criteria"""
        filter_config = self.config.file_filter
        
        # Check hidden files
        if filter_config.ignore_hidden and file_path.name.startswith('.'):
            return False
        
        # Check system files (basic check)
        if filter_config.ignore_system and metadata.is_directory:
            system_dirs = {'System Volume Information', '$RECYCLE.BIN', 'pagefile.sys'}
            if file_path.name in system_dirs:
                return False
        
        # Check file size
        if filter_config.min_size and metadata.file_size < filter_config.min_size:
            return False
        if filter_config.max_size and metadata.file_size > filter_config.max_size:
            return False
        
        # Check file age
        file_age = (datetime.now() - metadata.modified_time).total_seconds()
        if filter_config.min_age and file_age < filter_config.min_age:
            return False
        if filter_config.max_age and file_age > filter_config.max_age:
            return False
        
        # Check file extensions
        if filter_config.file_extensions and not metadata.is_directory:
            file_ext = file_path.suffix.lower().lstrip('.')
            if file_ext not in filter_config.file_extensions:
                return False
        
        # Check include patterns
        if filter_config.include_patterns:
            matches_include = any(
                fnmatch.fnmatch(str(file_path), pattern) or
                fnmatch.fnmatch(file_path.name, pattern)
                for pattern in filter_config.include_patterns
            )
            if not matches_include:
                return False
        
        # Check exclude patterns
        if filter_config.exclude_patterns:
            matches_exclude = any(
                fnmatch.fnmatch(str(file_path), pattern) or
                fnmatch.fnmatch(file_path.name, pattern)
                for pattern in filter_config.exclude_patterns
            )
            if matches_exclude:
                return False
        
        return True
    
    def _discover_files(self, mapping: PathMapping) -> Iterator[tuple[Path, Path]]:
        """Discover files for processing based on path mapping"""
        source_path = Path(mapping.source_path)
        
        # Handle different source path types
        if source_path.is_file():
            # Single file
            dest_path = Path(mapping.destination_path)
            yield source_path, dest_path
            
        elif source_path.is_dir():
            # Directory traversal
            for file_path in source_path.rglob('*'):
                if file_path.is_file():
                    metadata = self._get_file_metadata(file_path, include_hash=False)
                    
                    if self._matches_filter(file_path, metadata):
                        # Calculate destination path
                        if mapping.preserve_structure:
                            rel_path = file_path.relative_to(source_path)
                            dest_path = Path(mapping.destination_path) / rel_path
                        else:
                            dest_path = Path(mapping.destination_path) / file_path.name
                        
                        yield file_path, dest_path
        
        else:
            # Pattern matching
            parent_dir = source_path.parent
            pattern = source_path.name
            
            for file_path in parent_dir.rglob(pattern):
                if file_path.is_file():
                    metadata = self._get_file_metadata(file_path, include_hash=False)
                    
                    if self._matches_filter(file_path, metadata):
                        if mapping.preserve_structure:
                            rel_path = file_path.relative_to(parent_dir)
                            dest_path = Path(mapping.destination_path) / rel_path
                        else:
                            dest_path = Path(mapping.destination_path) / file_path.name
                        
                        yield file_path, dest_path
    
    def _resolve_conflict(self, source_path: Path, dest_path: Path) -> Optional[Path]:
        """Resolve file conflicts based on configuration"""
        if not dest_path.exists():
            return dest_path
        
        if self.config.conflict_resolution == ConflictResolution.SKIP:
            self.logger.info(f"Skipping {source_path} - destination exists")
            return None
        
        elif self.config.conflict_resolution == ConflictResolution.OVERWRITE:
            return dest_path
        
        elif self.config.conflict_resolution == ConflictResolution.RENAME:
            # Find available name
            counter = 1
            while True:
                new_name = f"{dest_path.stem}_{counter}{dest_path.suffix}"
                new_path = dest_path.parent / new_name
                if not new_path.exists():
                    return new_path
                counter += 1
        
        elif self.config.conflict_resolution == ConflictResolution.BACKUP:
            # Backup existing file
            backup_path = dest_path.with_suffix(f"{dest_path.suffix}.backup")
            counter = 1
            while backup_path.exists():
                backup_path = dest_path.with_suffix(f"{dest_path.suffix}.backup.{counter}")
                counter += 1
            
            shutil.move(str(dest_path), str(backup_path))
            return dest_path
        
        elif self.config.conflict_resolution == ConflictResolution.FAIL:
            raise FileExistsError(f"Destination exists: {dest_path}")
        
        return dest_path
    
    def _perform_file_operation(self, source_path: Path, dest_path: Path) -> bool:
        """Perform the actual file operation"""
        try:
            # Create destination directory if needed
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Resolve conflicts
            final_dest = self._resolve_conflict(source_path, dest_path)
            if final_dest is None:
                return False  # Skipped
            
            # Hash source before operation if integrity check needed
            source_hash = None
            if self.config.verify_integrity and self.config.operation in [FileOperation.COPY, FileOperation.MOVE]:
                source_hash = self._calculate_file_hash(source_path, self.config.hash_algorithm)

            # Perform operation
            if self.config.operation == FileOperation.COPY:
                shutil.copy2(str(source_path), str(final_dest))
            elif self.config.operation == FileOperation.MOVE:
                shutil.move(str(source_path), str(final_dest))
            elif self.config.operation == FileOperation.LINK:
                os.link(str(source_path), str(final_dest))
            elif self.config.operation == FileOperation.SYMLINK:
                os.symlink(str(source_path), str(final_dest))

            # Preserve timestamps and permissions if requested
            if self.config.preserve_timestamps and self.config.operation == FileOperation.COPY:
                shutil.copystat(str(source_path), str(final_dest))

            # Verify integrity if requested
            if source_hash is not None:
                dest_hash = self._calculate_file_hash(final_dest, self.config.hash_algorithm)
                if source_hash != dest_hash:
                    raise ValueError(f"Integrity check failed for {source_path}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error processing {source_path}: {e}")
            self.result.progress.errors.append(f"{source_path}: {str(e)}")
            return False
    
    def _build_file_index(self, processed_files: List[tuple[Path, Path, bool]]):
        """Build file index from processed files"""
        if self.config.indexing_mode == IndexingMode.NONE:
            return
        
        self.file_index = FileIndex(
            index_id=str(uuid.uuid4()),
            index_path=self.config.index_output_path or f"index_{self.result.execution_id}.json",
            hash_algorithm=self.config.hash_algorithm
        )
        
        # Index source files
        for source_path, dest_path, success in processed_files:
            if success:
                try:
                    # Determine which file to index
                    index_path = dest_path if dest_path.exists() else source_path
                    
                    include_hash = self.config.indexing_mode in [IndexingMode.FULL, IndexingMode.CONTENT]
                    metadata = self._get_file_metadata(index_path, include_hash=include_hash)
                    
                    # Add to index
                    self.file_index.files[str(index_path)] = metadata
                    self.file_index.total_files += 1
                    self.file_index.total_size += metadata.file_size
                    
                    # Track duplicates by hash
                    if metadata.file_hash:
                        if metadata.file_hash in self.file_index.duplicates:
                            self.file_index.duplicates[metadata.file_hash].append(str(index_path))
                        else:
                            self.file_index.duplicates[metadata.file_hash] = [str(index_path)]
                
                except Exception as e:
                    self.logger.error(f"Error indexing {index_path}: {e}")
        
        # Remove non-duplicate entries from duplicates dict
        self.file_index.duplicates = {
            hash_val: paths for hash_val, paths in self.file_index.duplicates.items()
            if len(paths) > 1
        }
        
        # Save index if path specified
        if self.config.index_output_path:
            self._save_index()
    
    def _save_index(self):
        """Save file index to disk"""
        if self.file_index and self.config.index_output_path:
            try:
                index_path = Path(self.config.index_output_path)
                index_path.parent.mkdir(parents=True, exist_ok=True)
                
                with open(index_path, 'w') as f:
                    json.dump(self.file_index.model_dump(), f, indent=2, default=str)
                
                self.logger.info(f"File index saved to {index_path}")
            except Exception as e:
                self.logger.error(f"Error saving index: {e}")
    
    @abstractmethod
    def execute(self) -> ETLTemplateResult:
        """Execute the ETL template"""
        pass
    
    def validate_config(self) -> List[str]:
        """Validate template configuration"""
        errors = []
        
        # Validate paths
        for mapping in self.config.path_mappings:
            source_path = Path(mapping.source_path)
            
            if self.config.validate_sources:
                if not source_path.exists() and '*' not in mapping.source_path:
                    errors.append(f"Source path does not exist: {mapping.source_path}")
            
            if self.config.validate_destinations:
                dest_path = Path(mapping.destination_path)
                if dest_path.exists() and not dest_path.is_dir():
                    errors.append(f"Destination path exists but is not a directory: {mapping.destination_path}")
        
        # Validate filter combinations
        filter_config = self.config.file_filter
        if filter_config.min_size and filter_config.max_size:
            if filter_config.min_size > filter_config.max_size:
                errors.append("min_size cannot be greater than max_size")
        
        if filter_config.min_age and filter_config.max_age:
            if filter_config.min_age > filter_config.max_age:
                errors.append("min_age cannot be greater than max_age")
        
        return errors