# FileSystem Agent

A modular file system agent for ETL operations, scheduled automation, file migration, and duplicate detection on Windows.

## Setup

```bash
pip install -r requirements.txt
```

## Usage

### Start the Agent

```bash
python main.py start              # Standard mode
python main.py --mcp start        # With MCP security layer
python main.py --no-mcp start     # Explicitly without MCP
python main.py config show        # Show current config
```

### Monitoring API

When running, the agent exposes a REST API on port 8080:

- `GET /health` - Health check
- `GET /metrics` - System and job metrics
- `GET /jobs` - ETL and scheduled jobs
- `GET /events` - File system events
- `GET /status` - Agent status and uptime

### File Migration Templates

```python
from src.file_migration_template import create_file_migration_template

template = create_file_migration_template(
    source_paths=["/source/path"],
    destination_path="/dest/path",
    operation="copy",
    dry_run=True
)
result = template.execute()
```

YAML templates are in `templates/` - see `basic_file_migration.yaml`, `advanced_file_migration.yaml`, and `duplicate_detection.yaml`.

### Duplicate Detection

```python
from src.file_indexing_system import FileIndexingSystem

indexer = FileIndexingSystem("index.db")
indexer.index_directory(Path("/path/to/scan"))
duplicates = indexer.find_duplicates(min_size=1024)
report = indexer.generate_duplicate_report("/path/to/scan")
```

### Transform Scripts

Transform scripts run as subprocesses and receive data via environment variables:

```python
# scripts/my_transform.py
import os, json, pandas as pd

data = pd.read_json(os.environ["TRANSFORM_DATA_PATH"])
# ... transform ...
data.to_json(os.environ["TRANSFORM_RESULT_PATH"])
```

### Automation Scripts

Scheduled scripts receive job context via environment variables:

```python
import os, json

job_id = os.environ.get("JOB_ID")
job_name = os.environ.get("JOB_NAME")
job_params = json.loads(os.environ.get("JOB_PARAMS", "{}"))
```

## Architecture

```
src/
  agent.py              Main orchestrator
  agent_mcp.py          MCP-enabled agent (extends agent.py)
  etl.py                ETL engine (CSV, JSON, XML, Parquet, Excel)
  etl_mcp.py            Async MCP ETL engine
  scheduler.py          Cron/interval job scheduler
  scheduler_mcp.py      MCP-enabled scheduler
  monitoring.py         FastAPI metrics + health checks
  config.py             YAML config with env var overrides (FSA_ prefix)
  models.py             Pydantic data models
  template_models.py    File migration config models
  etl_template_base.py  Abstract base for file operations
  file_migration_template.py  Concrete migration template
  file_indexing_system.py     SQLite-backed file indexing
  media_fingerprinting.py     Perceptual hashing (imagehash, videohash)
  mcp_server.py         MCP file system server
  mcp_client.py         MCP client wrapper
  cli.py                Click CLI
```

## Configuration

Edit `config.yaml` or override with `FSA_` environment variables:

```bash
FSA_AGENT_LOG_LEVEL=DEBUG
FSA_MONITORING_METRICS_PORT=9090
```
