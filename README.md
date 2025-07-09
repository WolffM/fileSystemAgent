# FileSystem Agent

A multi-capable file system agent for executing ETL (Extract, Transform, Load) operations and automation scripts on a regular cadence.

## Features

- **ETL Operations**: Support for various file formats (CSV, JSON, XML, Parquet, Excel)
- **Automation Scripts**: Schedule and run automation scripts using cron expressions or intervals
- **Monitoring**: Real-time system metrics and job monitoring via REST API
- **Configuration Management**: YAML-based configuration with environment variable support
- **CLI Interface**: Command-line interface for managing jobs and monitoring

## Quick Start

### Installation

```bash
pip install -r requirements.txt
```

### Configuration

Copy and modify the configuration file:

```bash
cp config.yaml.example config.yaml
```

### Running the Agent

```bash
python main.py start
```

## Usage

### ETL Operations

Run an ETL job:

```bash
python main.py etl run --name "csv_to_json" --type full_etl --source data/input.csv --destination data/output.json
```

### Scheduled Jobs

Add a scheduled job:

```bash
python main.py schedule add --name "daily_cleanup" --script cleanup.py --type cron --expression "0 2 * * *"
```

List scheduled jobs:

```bash
python main.py schedule list
```

### Monitoring

Check agent status:

```bash
python main.py monitor status
```

View system metrics:

```bash
python main.py monitor metrics
```

The monitoring API is available at `http://localhost:8080` with the following endpoints:

- `GET /health` - Health check
- `GET /metrics` - System and job metrics
- `GET /jobs` - List all jobs
- `GET /events` - File system events
- `GET /status` - Agent status

## Configuration

The agent uses a YAML configuration file with the following structure:

```yaml
agent:
  name: "FileSystemAgent"
  log_level: "INFO"
  data_dir: "./data"
  scripts_dir: "./scripts"
  logs_dir: "./logs"

etl:
  max_workers: 4
  chunk_size: 10000
  supported_formats:
    - csv
    - json
    - xml
    - parquet
    - excel

scheduler:
  enabled: true
  check_interval: 60
  max_concurrent_jobs: 2

monitoring:
  enabled: true
  metrics_port: 8080
  health_check_interval: 30
```

### Environment Variables

Configuration can be overridden using environment variables with the `FSA_` prefix:

```bash
export FSA_AGENT_LOG_LEVEL=DEBUG
export FSA_MONITORING_METRICS_PORT=9090
```

## ETL Operations

### Supported File Formats

- **CSV**: Comma-separated values
- **JSON**: JavaScript Object Notation
- **XML**: Extensible Markup Language
- **Parquet**: Columnar storage format
- **Excel**: Microsoft Excel files

### Transform Scripts

Create custom transformation scripts in the `scripts/` directory:

```python
# scripts/my_transform.py
import pandas as pd

# Transform the data
result = data.copy()
result['new_column'] = result['old_column'].apply(lambda x: x.upper())
result = result.dropna()
```

## Automation Scripts

Automation scripts receive job information through environment variables:

```python
import os
import json

job_id = os.environ.get('JOB_ID')
job_name = os.environ.get('JOB_NAME')
job_params = json.loads(os.environ.get('JOB_PARAMS', '{}'))
```

## Directory Structure

```
fileSystemAgent/
├── src/
│   ├── __init__.py
│   ├── agent.py          # Main agent class
│   ├── etl.py           # ETL operations
│   ├── scheduler.py     # Job scheduling
│   ├── monitoring.py    # Monitoring service
│   ├── config.py        # Configuration management
│   ├── models.py        # Data models
│   └── cli.py           # Command-line interface
├── scripts/             # Automation scripts
├── data/               # Data files
├── logs/               # Log files
├── config.yaml         # Configuration file
├── requirements.txt    # Python dependencies
└── main.py            # Entry point
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License.