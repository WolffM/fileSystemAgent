# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Goals

This repo serves as a **Windows system maintenance and file management agent** with two primary missions:

### Goal 1: Security & Process Hygiene
Active scanning and detection of:
- **Malware**: Suspicious executables, known malware signatures, anomalous behavior
- **Stale processes**: Long-running or zombie processes consuming resources unnecessarily
- **Orphaned daemons**: Services/daemons left running after their parent exited
- **Spyware**: Programs with suspicious network activity, keyloggers, data exfiltration
- **High resource consumption**: Processes hogging CPU, memory, disk I/O, or network

### Goal 2: File Organization & Storage Reclamation
Comprehensive file system management:
- **File organization**: Cataloguing, categorization, and structured storage
- **Duplicate detection**: Content-based deduplication (hash, perceptual, media fingerprint)
- **Compression**: Identifying and compressing compressible files/directories
- **Pruning**: Removing temp files, caches, logs, and other reclaimable space
- **Indexing**: Fast SQLite-backed file metadata and content indexing

### Design Principles
- **Leverage 3rd-party tools** wherever possible (psutil, yara, ClamAV, rkhunter, WinDirStat, etc.) — avoid reinventing the wheel
- **One-time scripts first**: Build standalone diagnostic/cataloguing scripts before integrating into the agent framework
- **Cross-platform awareness**: Developed in WSL, tested on Windows native
- **Safety first**: Dry-run by default, explicit confirmation for destructive operations

### Phase 1: One-Time Diagnostic Scripts
1. **System Catalogue Script**: Enumerate all running processes, installed programs, services, startup items, scheduled tasks, and collect system/application/security logs
2. **File Index Script**: Scan drives for large files, old/stale files, temp files, duplicate candidates, and generate a report of reclaimable space

## Common Commands

### Development Setup
```bash
pip install -r requirements.txt
```

### Important: Cross-Platform Considerations
- File paths use forward slashes in config but may need Windows-style paths in native Windows testing
- Process management and subprocess calls may behave differently between WSL and Windows
- Always commit changes regularly as commits serve as checkpoint/restore system

### Running the Agent
```bash
python main.py start                    # Start the full agent
python main.py --mcp start              # Start with MCP enabled
python main.py --no-mcp start           # Start with MCP disabled
python main.py --help                   # Show all CLI commands
```

### ETL Operations
```bash
python main.py etl run --name "job_name" --type full_etl --source data/input.csv --destination data/output.json
python main.py etl run --name "transform_only" --type transform --source data/input.csv --transform-script scripts/my_transform.py
python main.py etl list                 # List all ETL jobs
python main.py etl status <job_id>      # Check job status
```

### Scheduled Jobs Management
```bash
python main.py schedule add --name "daily_cleanup" --script cleanup.py --type cron --expression "0 2 * * *"
python main.py schedule list            # List scheduled jobs
python main.py schedule enable <job_id>  # Enable job
python main.py schedule disable <job_id> # Disable job
```

### Monitoring
```bash
python main.py monitor status           # Agent status (shows MCP status)
python main.py monitor metrics          # System metrics
python main.py monitor alerts           # Active alerts
curl http://localhost:8080/health        # Health check endpoint
curl http://localhost:8080/metrics       # REST API metrics
```

### MCP Operations
```bash
python -m src.mcp_server                # Run MCP server standalone
python main.py --mcp start              # Start agent with MCP enabled
python main.py --no-mcp start           # Start agent with MCP disabled
```

### Configuration
```bash
python main.py config show              # Show current config
python main.py config set --key "agent.log_level" --value "DEBUG"
```

## Architecture Overview

### Core Components

The FileSystem Agent follows a modular architecture with four main components:

1. **FileSystemAgent** (`src/agent.py`): Main orchestrator that coordinates all components
2. **ETLEngine** (`src/etl.py`): Handles data processing operations
3. **JobScheduler** (`src/scheduler.py`): Manages scheduled automation scripts
4. **MonitoringService** (`src/monitoring.py`): Provides metrics and health monitoring

### Component Interactions

- **Agent → ETL**: Agent submits ETL jobs to engine via thread pool executor
- **Agent → Scheduler**: Agent starts scheduler as async task for cron/interval jobs
- **Agent → Monitoring**: Agent registers jobs with monitoring service for tracking
- **Scheduler → Scripts**: Scheduler executes Python scripts in `scripts/` directory via subprocess
- **ETL → Transform Scripts**: ETL engine executes transform scripts in isolated namespace

### Data Flow

1. **ETL Jobs**: CLI → Agent → ETLEngine → ThreadPoolExecutor → File I/O
2. **Scheduled Jobs**: Scheduler → subprocess → Python script execution
3. **Monitoring**: All components → MonitoringService → FastAPI REST endpoints

### Configuration System

Configuration is managed through a hierarchical system:
- Base config in `config.yaml`
- Environment variables with `FSA_` prefix override config
- ConfigManager handles merging and validation via Pydantic models
- MCP can be enabled/disabled via CLI flags or config file

### MCP Integration

The agent supports Model Context Protocol (MCP) for enhanced security and cross-platform compatibility:
- **MCP Server**: Provides secure file system operations and command execution
- **MCP Client**: Integrates with ETL engine and scheduler for controlled operations
- **Security**: Path restrictions, command allowlists, and file size limits
- **Cross-Platform**: Abstracts WSL/Windows differences through standardized protocol

### Job State Management

All jobs use Pydantic models for type safety:
- **ETLJob**: Has status (pending/running/completed/failed), progress tracking
- **ScheduledJob**: Has enable/disable state, next_run calculation
- **FileSystemEvent**: Tracks file system changes for monitoring

### Error Handling Pattern

Components use consistent error handling:
- Jobs update their status to "failed" and store error messages
- Monitoring service tracks failures and generates alerts
- ThreadPoolExecutor isolates ETL job failures
- Subprocess isolation prevents scheduler job failures from affecting agent

### Transform Script Execution

Transform scripts run in controlled environments:
- Isolated namespace with data, params, pd, json, datetime available
- Must set `result` variable for output
- Located in `scripts/` directory specified in config

### Automation Script Environment

Scheduled scripts receive job context via environment variables:
- `JOB_ID`: Unique job identifier
- `JOB_NAME`: Human-readable job name  
- `JOB_PARAMS`: JSON-encoded job parameters

## Development Environment

### Environment Setup
- **Development**: Code is developed in WSL (Windows Subsystem for Linux) 
- **Testing**: Agent is tested in Windows native environment using Python in terminal
- **Commit Strategy**: Regular commits to GitHub serve as checkpoint/restore system

### Testing Process
- Request execution tests from user to generate log files when needed
- User will run tests in Windows native Python environment
- Log files and test results help validate cross-platform compatibility

### Testing and Development

Currently no test framework is configured. When adding tests, check if pytest or unittest is preferred and update this section with test commands.

## ETL Template System

The agent includes a comprehensive template system for file migration and duplicate detection:

### Template Usage
```bash
# Create migration from template
python -c "
from src.file_migration_template import create_file_migration_template
template = create_file_migration_template(
    source_paths=['/source/path'],
    destination_path='/dest/path',
    operation='copy',
    dry_run=True
)
result = template.execute()
print(f'Status: {result.status}')
"

# Use YAML template
python scripts/template_examples/basic_migration_example.py

# Duplicate detection
python scripts/template_examples/duplicate_detection_example.py
```

### Template Architecture
- **Template Models**: Pydantic models for configuration validation
- **Base Template**: Abstract base class with common functionality
- **File Migration**: Concrete template for file operations
- **Indexing System**: SQLite-backed file indexing with hash storage
- **Duplicate Detection**: Content-based duplicate identification

### Template Components
1. **Configuration**: YAML-based configuration with validation
2. **Path Mappings**: Flexible source-to-destination mapping
3. **File Filtering**: Pattern-based inclusion/exclusion
4. **Operations**: Copy, move, link, symlink operations
5. **Conflict Resolution**: Skip, overwrite, rename, backup strategies
6. **Indexing**: None, basic, full, content indexing modes
7. **Hashing**: MD5, SHA1, SHA256, SHA512 algorithms
8. **Progress Tracking**: Real-time operation progress
9. **Error Handling**: Retry logic with exponential backoff

## Environment Variables

Configuration can be overridden using `FSA_` prefixed environment variables:
```bash
FSA_AGENT_LOG_LEVEL=DEBUG              # Override log level
FSA_MONITORING_METRICS_PORT=9090       # Override monitoring port
FSA_ETL_MAX_WORKERS=8                  # Override ETL worker count
```