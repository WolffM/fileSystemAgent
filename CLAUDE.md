# CLAUDE.md

## Project Goals

Windows system maintenance and file management agent with two missions:

1. **Security & Process Hygiene**: Malware scanning, stale process detection, orphaned daemons, spyware, resource hogs
2. **File Organization & Storage Reclamation**: Duplicate detection, compression, pruning, indexing

Design principles: leverage 3rd-party tools, one-time scripts first, safety by default.

## Commands

```bash
pip install -r requirements.txt

# Run the agent
python main.py start                # Standard mode
python main.py --mcp start          # With MCP enabled
python main.py --no-mcp start       # Without MCP
python main.py config show          # Show config

# Monitoring (when agent is running)
curl http://localhost:8080/health
curl http://localhost:8080/metrics
curl http://localhost:8080/status
```

## Architecture

- `src/agent.py` - Main orchestrator, coordinates ETL + scheduler + monitoring
- `src/agent_mcp.py` - MCP variant, inherits from FileSystemAgent
- `src/etl.py` / `src/etl_mcp.py` - ETL engine (CSV, JSON, XML, Parquet, Excel)
- `src/scheduler.py` / `src/scheduler_mcp.py` - Cron/interval job scheduler
- `src/monitoring.py` - FastAPI REST API for metrics and health
- `src/config.py` - YAML config with `FSA_` env var overrides
- `src/models.py` - Pydantic data models (ETLJob, ScheduledJob, etc.)
- `src/template_models.py` - File migration/indexing config models
- `src/etl_template_base.py` - Abstract base for file operations
- `src/file_migration_template.py` - Concrete file migration template
- `src/file_indexing_system.py` - SQLite-backed file indexing + duplicate detection
- `src/media_fingerprinting.py` - Perceptual hashing (imagehash, videohash)
- `src/mcp_server.py` / `src/mcp_client.py` - MCP protocol layer
- `src/cli.py` - Click CLI (start, config show)

Key patterns:
- Transform scripts run as **subprocesses** with data passed via env vars (`TRANSFORM_DATA_PATH`, `TRANSFORM_RESULT_PATH`, `TRANSFORM_PARAMS`)
- Scheduled scripts get `JOB_ID`, `JOB_NAME`, `JOB_PARAMS` env vars
- MCP variants extend base classes, not copy-paste
- All models use Pydantic v2 (`model_dump()`, `field_validator`, `ConfigDict`)

## Development

- Developed in WSL, tested on Windows native Python
- No test framework configured yet
- Commits serve as checkpoint/restore system
