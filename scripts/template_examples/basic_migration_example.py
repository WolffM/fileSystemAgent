#!/usr/bin/env python3
"""
Basic File Migration Example using ETL Template System
This script demonstrates how to use the file migration template for simple file operations.
"""

import os
import sys
import yaml
from pathlib import Path

# Ensure project root is on path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from src.file_migration_template import FileMigrationTemplate, create_file_migration_template
from src.template_models import ETLTemplateConfig, FileFilter, PathMapping, ConflictResolution, FileOperation


def main():
    """Example of basic file migration using template system"""
    
    # Method 1: Using the factory function (simpler)
    print("=== Method 1: Using Factory Function ===")
    
    template = create_file_migration_template(
        source_paths=["/path/to/source/documents"],
        destination_path="/path/to/backup/documents",
        operation="copy",
        conflict_resolution="skip",
        template_name="Basic Document Backup",
        verify_integrity=True,
        indexing_mode="basic",
        dry_run=True  # Safety first!
    )
    
    # Execute the template
    result = template.execute()
    
    print(f"Template: {result.template_name}")
    print(f"Status: {result.status}")
    print(f"Duration: {result.duration:.2f} seconds" if result.duration else "N/A")
    print(f"Files processed: {result.progress.processed_files}")
    print(f"Successful: {result.progress.successful_files}")
    print(f"Failed: {result.progress.failed_files}")
    print(f"Skipped: {result.progress.skipped_files}")
    
    # Method 2: Using configuration object (more control)
    print("\n=== Method 2: Using Configuration Object ===")
    
    # Create file filter
    file_filter = FileFilter(
        include_patterns=["*.pdf", "*.docx", "*.xlsx"],
        exclude_patterns=["*.tmp", "*.log"],
        min_size=1024,  # 1KB minimum
        max_size=10485760,  # 10MB maximum
        ignore_hidden=True,
        ignore_system=True
    )
    
    # Create path mapping
    path_mapping = PathMapping(
        source_path="/path/to/source/important",
        destination_path="/path/to/backup/important",
        preserve_structure=True,
        create_directories=True
    )
    
    # Create full configuration
    config = ETLTemplateConfig(
        template_name="Important Files Backup",
        template_version="1.0",
        description="Backup important files with filtering",
        path_mappings=[path_mapping],
        operation=FileOperation.COPY,
        conflict_resolution=ConflictResolution.BACKUP,
        file_filter=file_filter,
        indexing_mode="full",
        hash_algorithm="sha256",
        verify_integrity=True,
        preserve_timestamps=True,
        preserve_permissions=True,
        max_workers=4,
        batch_size=500,
        max_retries=3,
        retry_delay=1.0,
        continue_on_error=True,
        dry_run=True,
        log_level="INFO",
        index_output_path="/path/to/backup/index.json"
    )
    
    # Create and execute template
    template = FileMigrationTemplate(config)
    
    # Set up progress callback
    def progress_callback(progress):
        percent = (progress.processed_files / progress.total_files * 100) if progress.total_files > 0 else 0
        print(f"Progress: {percent:.1f}% ({progress.processed_files}/{progress.total_files}) - {progress.current_file}")
    
    template.set_progress_callback(progress_callback)
    
    # Execute
    result = template.execute()
    
    print(f"\nTemplate: {result.template_name}")
    print(f"Status: {result.status}")
    print(f"Summary: {result.summary}")
    
    # Method 3: Using YAML configuration file
    print("\n=== Method 3: Using YAML Configuration ===")
    
    # Load configuration from YAML file
    config_path = Path(__file__).parent.parent.parent / "templates" / "basic_file_migration.yaml"
    
    if config_path.exists():
        with open(config_path, 'r') as f:
            config_data = yaml.safe_load(f)
        
        # Update paths for actual use
        config_data['path_mappings'][0]['source_path'] = "/actual/source/path"
        config_data['path_mappings'][0]['destination_path'] = "/actual/destination/path"
        config_data['dry_run'] = True  # Keep dry run for safety
        
        # Create configuration object
        config = ETLTemplateConfig(**config_data)
        
        # Create and execute template
        template = FileMigrationTemplate(config)
        result = template.execute()
        
        print(f"YAML Template: {result.template_name}")
        print(f"Status: {result.status}")
        print(f"Files found: {result.progress.total_files}")
        
        # Show duplicate information if available
        if result.file_index and result.file_index.duplicates:
            print(f"Duplicate groups found: {len(result.file_index.duplicates)}")
            for hash_val, file_paths in result.file_index.duplicates.items():
                print(f"  Hash {hash_val[:8]}...: {len(file_paths)} files")
    else:
        print(f"Configuration file not found: {config_path}")


if __name__ == "__main__":
    main()