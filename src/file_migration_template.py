import time
from typing import List, Tuple
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

from .etl_template_base import ETLTemplateBase
from .template_models import ETLTemplateConfig, ETLTemplateResult


class FileMigrationTemplate(ETLTemplateBase):
    """Template for robust file migration operations"""
    
    def __init__(self, config: ETLTemplateConfig):
        super().__init__(config)
        self._lock = threading.Lock()
    
    def execute(self) -> ETLTemplateResult:
        """Execute file migration with comprehensive error handling and progress tracking"""
        try:
            self.logger.info(f"Starting file migration: {self.config.template_name}")
            
            # Validate configuration
            validation_errors = self.validate_config()
            if validation_errors:
                error_msg = "Configuration validation failed: " + "; ".join(validation_errors)
                self.result.mark_failed(error_msg)
                return self.result
            
            # Discover all files to process
            file_pairs = self._discover_all_files()
            
            if not file_pairs:
                self.logger.warning("No files found to process")
                self.result.mark_completed()
                return self.result
            
            # Initialize progress tracking
            self.result.progress.total_files = len(file_pairs)
            self.result.progress.total_size = sum(
                pair[0].stat().st_size for pair in file_pairs if pair[0].exists()
            )
            
            self.logger.info(f"Found {len(file_pairs)} files to process ({self.result.progress.total_size} bytes)")
            
            # Process files
            if self.config.dry_run:
                self.logger.info("DRY RUN MODE - No actual file operations will be performed")
                processed_files = self._simulate_processing(file_pairs)
            else:
                processed_files = self._process_files(file_pairs)
            
            # Build file index
            self._build_file_index(processed_files)
            
            # Finalize result
            self.result.file_index = self.file_index
            self.result.summary = self._generate_summary()
            self.result.mark_completed()
            
            self.logger.info(f"Migration completed: {self.result.progress.successful_files} successful, "
                           f"{self.result.progress.failed_files} failed, "
                           f"{self.result.progress.skipped_files} skipped")
            
            return self.result
            
        except Exception as e:
            self.logger.error(f"Migration failed: {e}")
            self.result.mark_failed(str(e))
            return self.result
    
    def _discover_all_files(self) -> List[Tuple[Path, Path]]:
        """Discover all files for all path mappings"""
        all_files = []
        
        for mapping in self.config.path_mappings:
            self.logger.info(f"Discovering files for mapping: {mapping.source_path} -> {mapping.destination_path}")
            
            try:
                files = list(self._discover_files(mapping))
                all_files.extend(files)
                self.logger.info(f"Found {len(files)} files in {mapping.source_path}")
            except Exception as e:
                self.logger.error(f"Error discovering files in {mapping.source_path}: {e}")
                self.result.progress.errors.append(f"Discovery error in {mapping.source_path}: {str(e)}")
        
        return all_files
    
    def _process_files(self, file_pairs: List[Tuple[Path, Path]]) -> List[Tuple[Path, Path, bool]]:
        """Process files with threading and retry logic"""
        processed_files = []
        
        # Process in batches to manage memory
        batch_size = self.config.batch_size
        
        for i in range(0, len(file_pairs), batch_size):
            batch = file_pairs[i:i + batch_size]
            
            self.logger.info(f"Processing batch {i//batch_size + 1} ({len(batch)} files)")
            
            # Process batch with threading
            batch_results = self._process_batch(batch)
            processed_files.extend(batch_results)
            
            # Update progress
            self._update_progress(processed_files=len(processed_files))
            
            # Memory management
            if self.config.memory_limit:
                # Basic memory check (could be enhanced with psutil)
                import gc
                gc.collect()
        
        return processed_files
    
    def _process_batch(self, batch: List[Tuple[Path, Path]]) -> List[Tuple[Path, Path, bool]]:
        """Process a batch of files with threading"""
        results = []
        
        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            # Submit all tasks
            future_to_files = {
                executor.submit(self._process_single_file, source, dest): (source, dest)
                for source, dest in batch
            }
            
            # Collect results
            for future in as_completed(future_to_files):
                source, dest = future_to_files[future]
                
                try:
                    success = future.result()
                    results.append((source, dest, success))
                    
                    # Update progress (thread-safe)
                    with self._lock:
                        if success:
                            self.result.progress.successful_files += 1
                            if source.exists():
                                self.result.progress.processed_size += source.stat().st_size
                        else:
                            self.result.progress.skipped_files += 1
                        
                        self.result.progress.processed_files += 1
                        self.result.progress.current_file = str(source)
                        
                        # Call progress callback
                        if self.progress_callback:
                            self.progress_callback(self.result.progress)
                
                except Exception as e:
                    self.logger.error(f"Unexpected error processing {source}: {e}")
                    results.append((source, dest, False))
                    
                    with self._lock:
                        self.result.progress.failed_files += 1
                        self.result.progress.processed_files += 1
                        self.result.progress.errors.append(f"{source}: {str(e)}")
        
        return results
    
    def _process_single_file(self, source_path: Path, dest_path: Path) -> bool:
        """Process a single file with retry logic"""
        for attempt in range(self.config.max_retries + 1):
            try:
                # Perform the file operation
                success = self._perform_file_operation(source_path, dest_path)
                
                if success:
                    self.logger.debug(f"Successfully processed {source_path}")
                    return True
                else:
                    # File was skipped (not an error)
                    return False
                
            except Exception as e:
                self.logger.warning(f"Attempt {attempt + 1} failed for {source_path}: {e}")
                
                if attempt < self.config.max_retries:
                    # Wait before retry
                    time.sleep(self.config.retry_delay * (2 ** attempt))  # Exponential backoff
                    continue
                else:
                    # Final attempt failed
                    if self.config.continue_on_error:
                        self.logger.error(f"All attempts failed for {source_path}: {e}")
                        return False
                    else:
                        raise
        
        return False
    
    def _simulate_processing(self, file_pairs: List[Tuple[Path, Path]]) -> List[Tuple[Path, Path, bool]]:
        """Simulate file processing for dry run"""
        results = []
        
        for source, dest in file_pairs:
            try:
                # Simulate the operation
                self.logger.info(f"DRY RUN: Would process {source} -> {dest}")
                
                # Check if operation would succeed
                if source.exists():
                    # Simulate conflict resolution
                    final_dest = self._resolve_conflict(source, dest)
                    success = final_dest is not None
                else:
                    success = False
                
                results.append((source, dest, success))
                
                # Update progress
                if success:
                    self.result.progress.successful_files += 1
                    self.result.progress.processed_size += source.stat().st_size
                else:
                    self.result.progress.skipped_files += 1
                
                self.result.progress.processed_files += 1
                
            except Exception as e:
                self.logger.error(f"DRY RUN: Error simulating {source}: {e}")
                results.append((source, dest, False))
                self.result.progress.failed_files += 1
                self.result.progress.processed_files += 1
        
        return results
    
    def _generate_summary(self) -> dict:
        """Generate execution summary"""
        progress = self.result.progress
        
        summary = {
            'total_files': progress.total_files,
            'successful_files': progress.successful_files,
            'failed_files': progress.failed_files,
            'skipped_files': progress.skipped_files,
            'total_size': progress.total_size,
            'processed_size': progress.processed_size,
            'success_rate': (progress.successful_files / progress.total_files * 100) if progress.total_files > 0 else 0,
            'error_count': len(progress.errors),
            'warning_count': len(progress.warnings),
            'dry_run': self.config.dry_run,
            'operation_type': self.config.operation.value,
            'conflict_resolution': self.config.conflict_resolution.value
        }
        
        # Add indexing info
        if self.file_index:
            summary['index_info'] = {
                'total_indexed_files': self.file_index.total_files,
                'total_indexed_size': self.file_index.total_size,
                'duplicate_groups': len(self.file_index.duplicates),
                'duplicate_files': sum(len(files) for files in self.file_index.duplicates.values())
            }
        
        return summary
    
    def get_progress(self) -> dict:
        """Get current progress information"""
        if not self.result:
            return {}
        
        progress = self.result.progress
        elapsed = (datetime.now() - self.result.start_time).total_seconds()
        
        progress_info = {
            'total_files': progress.total_files,
            'processed_files': progress.processed_files,
            'successful_files': progress.successful_files,
            'failed_files': progress.failed_files,
            'skipped_files': progress.skipped_files,
            'progress_percentage': (progress.processed_files / progress.total_files * 100) if progress.total_files > 0 else 0,
            'elapsed_time': elapsed,
            'current_file': progress.current_file,
            'errors': len(progress.errors),
            'warnings': len(progress.warnings)
        }
        
        # Calculate ETA
        if progress.processed_files > 0:
            rate = progress.processed_files / elapsed
            remaining = progress.total_files - progress.processed_files
            eta = remaining / rate if rate > 0 else 0
            progress_info['estimated_time_remaining'] = eta
        
        return progress_info
    
    def cancel(self):
        """Cancel the current operation"""
        if self.result and self.result.status == "running":
            self.result.status = "cancelled"
            self.result.end_time = datetime.now()
            self.logger.info("Migration cancelled by user")


# Factory function for easy template creation
def create_file_migration_template(
    source_paths: List[str],
    destination_path: str,
    operation: str = "copy",
    conflict_resolution: str = "skip",
    **kwargs
) -> FileMigrationTemplate:
    """Factory function to create a file migration template with simplified parameters"""
    
    # Create path mappings
    path_mappings = []
    for source in source_paths:
        path_mappings.append({
            "source_path": source,
            "destination_path": destination_path,
            "preserve_structure": kwargs.get("preserve_structure", True),
            "create_directories": kwargs.get("create_directories", True)
        })
    
    # Create configuration
    config_dict = {
        "template_name": kwargs.get("template_name", "File Migration"),
        "path_mappings": path_mappings,
        "operation": operation,
        "conflict_resolution": conflict_resolution,
        "indexing_mode": kwargs.get("indexing_mode", "basic"),
        "hash_algorithm": kwargs.get("hash_algorithm", "sha256"),
        "verify_integrity": kwargs.get("verify_integrity", True),
        "max_workers": kwargs.get("max_workers", 4),
        "batch_size": kwargs.get("batch_size", 1000),
        "dry_run": kwargs.get("dry_run", False)
    }
    
    # Add file filter if provided
    if "file_filter" in kwargs:
        config_dict["file_filter"] = kwargs["file_filter"]
    
    # Create configuration object
    config = ETLTemplateConfig(**config_dict)
    
    return FileMigrationTemplate(config)