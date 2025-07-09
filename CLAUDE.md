# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

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
python main.py monitor status           # Agent status
python main.py monitor metrics          # System metrics
python main.py monitor alerts           # Active alerts
curl http://localhost:8080/health        # Health check endpoint
curl http://localhost:8080/metrics       # REST API metrics
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

## Environment Variables

Configuration can be overridden using `FSA_` prefixed environment variables:
```bash
FSA_AGENT_LOG_LEVEL=DEBUG              # Override log level
FSA_MONITORING_METRICS_PORT=9090       # Override monitoring port
FSA_ETL_MAX_WORKERS=8                  # Override ETL worker count
```