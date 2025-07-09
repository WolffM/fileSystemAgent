# ETL Template System Documentation

## Overview

The ETL Template System provides a robust, standardized framework for file migration, indexing, and duplicate detection operations. It's designed to be highly configurable, safe, and efficient for large-scale file operations.

## Key Features

### 🔧 **Template-Based Operations**
- **Standardized Configuration**: YAML-based configuration files for reproducible operations
- **Multiple Templates**: Pre-built templates for common use cases
- **Custom Parameters**: Extensible parameter system for specific requirements

### 🛡️ **Safety & Reliability**
- **Dry Run Mode**: Test operations without making changes
- **Conflict Resolution**: Multiple strategies for handling file conflicts
- **Integrity Verification**: Hash-based verification of file operations
- **Retry Logic**: Automatic retry with exponential backoff
- **Comprehensive Logging**: Detailed operation logging and progress tracking

### ⚡ **Performance & Scalability**
- **Multithreaded Processing**: Configurable worker threads for parallel operations
- **Batch Processing**: Memory-efficient batch processing for large datasets
- **SQLite Indexing**: Fast database-backed file indexing
- **Memory Management**: Configurable memory limits and cleanup

### 🔍 **Advanced Features**
- **Duplicate Detection**: Content-based duplicate detection with detailed reporting
- **File Indexing**: Comprehensive file metadata indexing with search capabilities
- **Hash Storage**: Persistent hash storage to avoid recalculation
- **Cross-Platform**: Works on Windows, Linux, and macOS

## Template Structure

### Core Parameters

Every template includes these essential parameters:

```yaml
# Template Identification
template_name: "My File Migration"
template_version: "1.0"
description: "Description of what this template does"

# Path Configuration
path_mappings:
  - source_path: "/path/to/source"
    destination_path: "/path/to/destination"
    preserve_structure: true
    create_directories: true

# Operation Type
operation: "copy"  # copy, move, link, symlink
conflict_resolution: "skip"  # skip, overwrite, rename, backup, fail

# File Filtering
file_filter:
  include_patterns: ["*.pdf", "*.docx"]
  exclude_patterns: ["*.tmp", "*.log"]
  min_size: 1024
  max_size: 104857600
  file_extensions: ["pdf", "docx", "xlsx"]
  ignore_hidden: true

# Indexing & Hashing
indexing_mode: "full"  # none, basic, full, content
hash_algorithm: "sha256"
verify_integrity: true
index_output_path: "/path/to/index.json"

# Performance
batch_size: 1000
max_workers: 4
memory_limit: 2048

# Safety
dry_run: false
max_retries: 3
continue_on_error: true
```

## Available Templates

### 1. Basic File Migration
**File**: `templates/basic_file_migration.yaml`
- Simple file copying with basic filtering
- Integrity verification
- Basic indexing
- Suitable for straightforward backup operations

### 2. Advanced File Migration
**File**: `templates/advanced_file_migration.yaml`
- Complex multi-path mappings
- Comprehensive filtering options
- Full indexing with duplicate detection
- Advanced conflict resolution
- Performance optimizations

### 3. Duplicate Detection
**File**: `templates/duplicate_detection.yaml`
- Focuses on finding and managing duplicates
- Content-based hash comparison
- Detailed duplicate reporting
- Cleanup recommendations
- Safety-first approach with dry run default

## Usage Examples

### Python API Usage

```python
from file_migration_template import create_file_migration_template

# Simple factory method
template = create_file_migration_template(
    source_paths=["/source/documents"],
    destination_path="/backup/documents",
    operation="copy",
    conflict_resolution="skip",
    verify_integrity=True,
    dry_run=True
)

result = template.execute()
print(f"Status: {result.status}")
print(f"Files processed: {result.progress.processed_files}")
```

### YAML Configuration

```python
import yaml
from file_migration_template import FileMigrationTemplate
from template_models import ETLTemplateConfig

# Load from YAML
with open("templates/basic_file_migration.yaml", 'r') as f:
    config_data = yaml.safe_load(f)

config = ETLTemplateConfig(**config_data)
template = FileMigrationTemplate(config)
result = template.execute()
```

### Command Line Integration

```bash
# Via the FileSystem Agent
python main.py etl run --template templates/basic_file_migration.yaml

# As a scheduled job
python main.py schedule add --name "daily_backup" --script template_migration.py --type cron --expression "0 2 * * *"
```

## Configuration Parameters Reference

### Path Mappings
- `source_path`: Source file or directory path (supports wildcards)
- `destination_path`: Destination directory path
- `preserve_structure`: Maintain source directory structure
- `create_directories`: Create destination directories if needed

### File Operations
- `copy`: Copy files (preserves original)
- `move`: Move files (removes original)
- `link`: Create hard links
- `symlink`: Create symbolic links

### Conflict Resolution
- `skip`: Skip files that already exist
- `overwrite`: Replace existing files
- `rename`: Add suffix to avoid conflicts
- `backup`: Backup existing before overwriting
- `fail`: Stop operation on conflicts

### File Filtering
- `include_patterns`: Glob patterns for files to include
- `exclude_patterns`: Glob patterns for files to exclude
- `min_size`/`max_size`: File size limits in bytes
- `min_age`/`max_age`: File age limits in seconds
- `file_extensions`: Allowed file extensions
- `ignore_hidden`: Skip hidden files
- `ignore_system`: Skip system files

### Indexing Modes
- `none`: No indexing
- `basic`: File path, size, timestamps
- `full`: Basic + hash + metadata
- `content`: Full + content analysis

### Hash Algorithms
- `md5`: Fast but less secure
- `sha1`: Balanced speed and security
- `sha256`: Secure and recommended
- `sha512`: Maximum security

## Advanced Features

### Duplicate Detection

The system provides comprehensive duplicate detection:

```python
from file_indexing_system import FileIndexingSystem

indexer = FileIndexingSystem("index.db")
indexer.index_directory("/path/to/scan")
duplicates = indexer.find_duplicates(min_size=1024)
report = indexer.generate_duplicate_report("/path/to/scan")
```

### Progress Tracking

Monitor operation progress in real-time:

```python
def progress_callback(progress):
    percent = (progress.processed_files / progress.total_files * 100)
    print(f"Progress: {percent:.1f}% - {progress.current_file}")

template.set_progress_callback(progress_callback)
```

### File Indexing

Persistent file indexing with SQLite backend:

```python
# Index files
indexer.index_directory("/path/to/index", recursive=True)

# Search indexed files
results = indexer.search_files("*.pdf", "name")
hash_matches = indexer.search_files("abc123...", "hash")

# Export index
indexer.export_index("index.json", "json")
indexer.export_index("index.csv", "csv")
```

## Error Handling

The system includes robust error handling:

### Retry Logic
- Configurable retry attempts with exponential backoff
- Per-file error isolation
- Detailed error logging

### Validation
- Pre-flight configuration validation
- Source path existence checking
- Destination path writability verification
- File filter validation

### Recovery
- Graceful degradation on errors
- Partial operation completion
- Detailed error reporting
- Resume capability for interrupted operations

## Performance Optimization

### Memory Management
- Configurable memory limits
- Batch processing for large datasets
- Garbage collection optimization
- Memory-efficient file streaming

### Disk I/O
- Optimized file reading patterns
- Concurrent file operations
- Efficient hash calculation
- Minimal disk seeks

### Threading
- Configurable worker threads
- I/O bound operation optimization
- CPU-bound task distribution
- Thread-safe progress tracking

## Security Considerations

### File Access
- Path traversal protection
- Permission validation
- Symlink handling
- Hidden file protection

### Data Integrity
- Hash-based verification
- Checksum validation
- Corruption detection
- Backup before operations

### Audit Trail
- Comprehensive operation logging
- File access tracking
- Error documentation
- Configuration recording

## Best Practices

### Configuration
1. Always start with `dry_run: true`
2. Use appropriate conflict resolution
3. Set reasonable batch sizes
4. Configure memory limits
5. Enable integrity verification

### Operations
1. Test templates on small datasets first
2. Monitor system resources during operations
3. Use appropriate hash algorithms
4. Implement proper error handling
5. Keep operation logs

### Maintenance
1. Regular index cleanup
2. Monitor disk space
3. Archive old logs
4. Update configurations
5. Test restore procedures

## Example Workflows

### Daily Backup Workflow
```yaml
# Schedule: 0 2 * * * (daily at 2 AM)
template_name: "Daily Backup"
path_mappings:
  - source_path: "/home/user/documents"
    destination_path: "/backup/daily/documents"
operation: "copy"
conflict_resolution: "backup"
verify_integrity: true
indexing_mode: "full"
```

### Duplicate Cleanup Workflow
```yaml
# Schedule: 0 3 * * 0 (weekly on Sunday at 3 AM)
template_name: "Weekly Duplicate Cleanup"
path_mappings:
  - source_path: "/data/user_files"
    destination_path: "/data/duplicates_quarantine"
operation: "move"
indexing_mode: "full"
file_filter:
  min_size: 4096
dry_run: true  # Manual review required
```

### Archive Migration Workflow
```yaml
# For large-scale migrations
template_name: "Archive Migration"
path_mappings:
  - source_path: "/old_storage/**/*"
    destination_path: "/new_storage"
operation: "move"
conflict_resolution: "rename"
batch_size: 500
max_workers: 8
memory_limit: 4096
```

## Troubleshooting

### Common Issues

1. **Out of Memory**: Reduce batch_size or max_workers
2. **Slow Performance**: Increase max_workers or reduce verification
3. **Permission Errors**: Check file permissions and ownership
4. **Disk Space**: Monitor available space during operations
5. **Hash Conflicts**: Verify file integrity and storage

### Debug Mode
Enable detailed logging:
```yaml
log_level: "DEBUG"
detailed_logging: true
```

### Recovery Procedures
1. Check operation logs for errors
2. Use dry run mode to test fixes
3. Resume from last successful batch
4. Verify data integrity after recovery
5. Update configurations to prevent recurrence

## Integration with FileSystem Agent

The template system integrates seamlessly with the FileSystem Agent:

### Scheduled Operations
```bash
# Add template-based job
python main.py schedule add \
  --name "backup_documents" \
  --script template_runner.py \
  --type cron \
  --expression "0 2 * * *" \
  --params '{"template": "templates/daily_backup.yaml"}'
```

### Monitoring Integration
- Progress tracking via monitoring API
- Error reporting through alert system
- Performance metrics collection
- Resource usage monitoring

### MCP Integration
- Secure file operations through MCP
- Cross-platform compatibility
- Enhanced security controls
- Audit trail logging