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

# Audit / security scanning
python main.py audit check          # Show tool availability
python main.py audit setup          # Download tools from GitHub
python main.py audit scan           # Run daily scan pipeline
python main.py audit scan -p forensic  # Run forensic triage
python main.py audit scan --dry-run    # Preview commands
python main.py audit findings       # Show recent findings
python main.py audit baseline       # Manage audit baselines
python main.py audit process-scan   # Run collectors + analyzers pipeline

# Monitoring (when agent is running)
curl http://localhost:8080/health
curl http://localhost:8080/metrics
curl http://localhost:8080/status
curl http://localhost:8080/security/tools
curl http://localhost:8080/security/scans
curl http://localhost:8080/security/findings

# Tests
python -m pytest tests/audit/ -v
```

## Architecture

### Core
- `src/agent.py` - Main orchestrator, coordinates ETL + scheduler + monitoring + audit
- `src/agent_mcp.py` - MCP variant, inherits from FileSystemAgent
- `src/etl.py` / `src/etl_mcp.py` - ETL engine (CSV, JSON, XML, Parquet, Excel)
- `src/scheduler.py` / `src/scheduler_mcp.py` - Cron/interval job scheduler
- `src/monitoring.py` - FastAPI REST API for metrics, health, and security endpoints
- `src/config.py` - YAML config with `FSA_` env var overrides
- `src/models.py` - Pydantic data models (ETLJob, ScheduledJob, etc.)
- `src/cli.py` - Click CLI (start, config show, audit check/setup/scan/findings/baseline/process-scan)

### Audit System (`src/audit/`)

#### Scanning
- `src/audit/models.py` - Pydantic models: ToolInfo, Finding, ScanResult, PipelineResult
- `src/audit/tool_manager.py` - Tool binary discovery, verification, GitHub download
- `src/audit/scanner_base.py` - Abstract base class (template method: build_command + parse_output)
- `src/audit/pipeline.py` - Multi-tool scan orchestration with factory methods
- `src/audit/result_parser.py` - Shared CSV/JSON/text parsing utilities
- `src/audit/monitor.py` - FastAPI routes for /security/* endpoints

#### Scanners (`src/audit/scanners/`)
- `clamav.py` - ClamAV (freshclam + clamscan)
- `hollows_hunter.py` - HollowsHunter process implant scanning
- `yara_scanner.py` - YARA-X pattern matching
- `hayabusa.py` - Hayabusa event log threat hunting
- `chainsaw.py` - Chainsaw forensic triage
- `sysinternals.py` - autorunsc, sigcheck, listdlls
- `sysmon.py` - Sysmon install/config manager

#### Collectors (`src/audit/collectors/`)
- `process_snapshot.py` - Running process enumeration
- `network_mapper.py` - Network connection mapping
- `service_auditor.py` - Windows service auditing
- `persistence_auditor.py` - Persistence mechanism detection

#### Analyzers (`src/audit/analyzers/`)
- `resource_analyzer.py` - CPU/memory/disk resource analysis
- `baseline_differ.py` - Diff current state against saved baselines

#### Reporting (`src/audit/reporting/`)
- `html_report.py` - HTML report generation from scan/audit results

### File Management
- `src/template_models.py` - File migration/indexing config models
- `src/etl_template_base.py` - Abstract base for file operations
- `src/file_migration_template.py` - Concrete file migration template
- `src/file_indexing_system.py` - SQLite-backed file indexing + duplicate detection
- `src/media_fingerprinting.py` - Perceptual hashing (imagehash, videohash)
- `src/mcp_server.py` / `src/mcp_client.py` - MCP protocol layer

### Supporting Files
- `config.yaml` - Full configuration (agent, etl, scheduler, monitoring, audit, mcp)
- `rules/yara/` - YARA rule files
- `rules/sigma/` - Sigma detection rules (for Hayabusa/Chainsaw)
- `rules/sysmon/` - Sysmon XML configs
- `tools/` - Tool binaries (gitignored, populated by `audit setup`)
- `tests/audit/` - pytest suite (438+ tests) with mock fixtures

## Key Patterns

- External tools run as **async subprocesses** via `asyncio.create_subprocess_exec`
- Scanner abstraction: `build_command()` + `parse_output()` per tool, `run()` template method handles lifecycle
- Collector abstraction: `collect()` gathers system state, analyzers compare against baselines
- Tool resolution: config path > `tools/<name>/` dir > system PATH
- All models use Pydantic v2 (`model_dump()`, `field_validator`, `ConfigDict`)
- Transform scripts use env vars (`TRANSFORM_DATA_PATH`, `TRANSFORM_RESULT_PATH`, `TRANSFORM_PARAMS`)
- MCP variants extend base classes, not copy-paste

## Development

- Target platform: Windows (native Python)
- Test framework: pytest + pytest-asyncio (438+ tests)
- Known issue: `test_e2e_collectors.py` hangs under pytest due to Windows asyncio subprocess incompatibility; collectors work correctly from the agent/CLI
