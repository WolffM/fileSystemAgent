# Process Scanning Pipeline — Revised Plan (integrating with existing repo)

## What already exists vs. what's needed

### ✅ HAVE — no work needed
- **Scanner base class** (`scanner_base.py`) — template method pattern, subprocess lifecycle
- **Tool manager** (`tool_manager.py`) — binary discovery, GitHub auto-download, hash verification
- **Pipeline orchestration** (`pipeline.py`) — `daily` and `forensic` factory methods
- **Models** (`models.py`) — `Finding`, `ScanResult`, `SeverityLevel`, etc.
- **Scanner implementations** — HollowsHunter, YARA-X, Sigcheck, ListDLLs already exist
- **CLI and API** — `security scan`, `security findings`, FastAPI routes
- **105 unit tests + 20 E2E tests** — all passing

### 🔧 HAVE BUT NEEDS WORK
- **HollowsHunter** — unit tested with mocks, needs live admin-elevated testing
- **Autorunsc / ListDLLs** — unit tested with mocks, need binary download + admin testing
- **Sysmon** — config manager only, no output parser
- **ClamAV** — needs MSI installation + signature DB
- **Pipeline scheduling** — `daily` cron defined in config.yaml but not wired to scheduler
- **Hayabusa live mode** — only tested against sample .evtx, not live system logs

### ❌ MISSING — new work
1. **Process snapshot collector** — native WMI/CIM process inventory with resource metrics
2. **Service auditor** — service configuration analysis (unquoted paths, SYSTEM + writable, etc.)
3. **Network mapper** — per-process network connections (outbound C2 detection)
4. **Resource analyzer** — rank top consumers, match against bloatware list, startup impact
5. **Baseline diffing** — compare current scan to stored baseline, flag deltas
6. **HTML report generator** — self-contained dashboard with severity ratings
7. **Scheduler wiring** — connect pipeline to Task Scheduler / internal scheduler
8. **Admin elevation handling** — UAC-aware execution for tools that need it

---

## Revised architecture

New components slot into the existing pattern. Process snapshot/service/network collectors
become new scanner-like modules (they follow the same "collect → parse → produce Findings"
pattern even though they call WMI instead of external binaries). The report generator and
baseline differ are new post-pipeline stages.

```
src/security/
├── models.py                  ← extend with new models (below)
├── scanner_base.py            ← existing, no changes needed
├── tool_manager.py            ← existing, no changes needed
├── pipeline.py                ← extend with process_scan pipeline factory
├── result_parser.py           ← existing, may add helpers
├── security_monitor.py        ← add /security/report endpoint
│
├── scanners/                  ← existing scanners (or flat in security/)
│   ├── clamav.py              ✅ exists
│   ├── hollows_hunter.py      ✅ exists
│   ├── yara_scanner.py        ✅ exists
│   ├── hayabusa.py            ✅ exists
│   ├── chainsaw.py            ✅ exists
│   ├── sysinternals.py        ✅ exists (autorunsc, sigcheck, listdlls)
│   └── sysmon.py              ✅ exists
│
├── collectors/                ← NEW: native Windows data collectors
│   ├── __init__.py
│   ├── collector_base.py      ← abstract base (similar to scanner_base but for WMI/CIM)
│   ├── process_snapshot.py    ← WMI process inventory + CPU/RAM/IO sampling
│   ├── service_auditor.py     ← service config analysis + vulnerability checks
│   ├── network_mapper.py      ← TCP/UDP connections mapped to processes
│   └── persistence_auditor.py ← scheduled tasks + WMI subscriptions (supplements autorunsc)
│
├── analyzers/                 ← NEW: post-scan analysis
│   ├── __init__.py
│   ├── resource_analyzer.py   ← rank hogs, match bloatware, startup impact
│   ├── baseline_differ.py     ← JSON diff engine, delta classification
│   └── severity_scorer.py     ← cross-reference findings, compute aggregate severity
│
└── reporting/                 ← NEW: output generation
    ├── __init__.py
    ├── html_report.py         ← Jinja2 or string-template HTML dashboard
    └── report_models.py       ← ReportSection, DashboardData, DiffResult models
```

---

## New models to add to models.py

```python
# --- Process Snapshot ---
class ProcessInfo(BaseModel):
    pid: int
    name: str
    path: str | None
    command_line: str | None
    parent_pid: int | None
    user: str | None
    cpu_percent: float          # sampled over 5s window
    ram_mb: float
    io_bytes_per_sec: float     # sampled over 5s window
    thread_count: int
    handle_count: int
    created_at: datetime | None
    is_signed: bool | None
    signer: str | None

class ServiceInfo(BaseModel):
    name: str
    display_name: str
    state: str                  # Running, Stopped, etc.
    start_mode: str             # Auto, Manual, Disabled
    binary_path: str | None
    account: str                # LocalSystem, NetworkService, etc.
    description: str | None
    # Vulnerability flags
    unquoted_path: bool = False
    system_with_writable_binary: bool = False
    non_standard_binary_location: bool = False

class NetworkConnection(BaseModel):
    local_address: str
    local_port: int
    remote_address: str | None
    remote_port: int | None
    state: str                  # Established, Listen, TimeWait, etc.
    pid: int
    process_name: str | None
    process_path: str | None
    is_outbound_external: bool  # True if remote is non-RFC1918

# --- Resource Analysis ---
class ResourceHog(BaseModel):
    pid: int
    name: str
    path: str | None
    category: str               # "cpu", "ram", "io", "handles", "threads"
    value: float
    threshold: float
    recommendation: str | None

class BloatwareMatch(BaseModel):
    name: str
    service_name: str | None
    category: str               # "telemetry", "consumer", "updater", etc.
    recommendation: str         # "safe to disable", "investigate", etc.

# --- Baseline Diff ---
class DiffEntry(BaseModel):
    category: str               # "process", "service", "autorun", "task", etc.
    change_type: str            # "added", "removed", "modified"
    item_name: str
    details: dict[str, Any]
    severity: SeverityLevel

class BaselineDiff(BaseModel):
    baseline_timestamp: datetime
    current_timestamp: datetime
    entries: list[DiffEntry]
    summary: dict[str, int]     # {"added": 3, "removed": 1, "modified": 2}

# --- Report ---
class ReportSection(BaseModel):
    title: str
    severity: SeverityLevel
    findings_count: int
    content: Any                # typed per section in practice

class DashboardData(BaseModel):
    scan_timestamp: datetime
    machine_name: str
    os_version: str
    scan_duration_seconds: float
    sections: list[ReportSection]
    diff: BaselineDiff | None
    summary: dict[str, int]     # counts by severity level
```

---

## Implementation plan — 7 work items

### WI-1: Collectors (process_snapshot, service_auditor, network_mapper)
**Why first:** These produce the foundational data that Phase 4 analysis and Phase 5 reporting depend on. They also fill a gap — the existing scanners detect malicious activity but don't inventory what's *normal* on the system.

**Implementation:**
- `collector_base.py` — abstract class with `collect() -> list[BaseModel]` method, timing, error handling. Simpler than `scanner_base` since no external binary.
- `process_snapshot.py`:
  - `Get-CimInstance Win32_Process` via PowerShell subprocess (or `wmi` Python package if available)
  - Two-sample CPU measurement: snapshot process times, sleep 5s, snapshot again, compute delta
  - Authenticode signature check via PowerShell `Get-AuthenticodeSignature`
  - Output: `list[ProcessInfo]` → serialized to `snapshot-processes.json`
- `service_auditor.py`:
  - `Get-CimInstance Win32_Service` + vulnerability analysis
  - Unquoted path detection: regex check for spaces in path without quotes
  - Writable binary check: `icacls` on binary path, check for user-writable ACLs
  - Output: `list[ServiceInfo]` → serialized to `snapshot-services.json`
- `network_mapper.py`:
  - `Get-NetTCPConnection` + PID-to-process resolution
  - RFC1918 check for outbound classification
  - Output: `list[NetworkConnection]` → serialized to `snapshot-network.json`

**Tests:** Unit tests with mocked PowerShell output (same pattern as existing scanner tests). E2E tests that actually call CIM (non-admin, limited but validates parsing).

**Estimated effort:** ~400 lines code + ~200 lines tests

---

### WI-2: Persistence auditor (supplements existing autorunsc)
**Why:** Autorunsc is excellent but is a binary that needs admin + download. A native PowerShell collector provides a fallback that works without Sysinternals, and captures details autorunsc doesn't (full scheduled task XML, WMI event subscriptions).

**Implementation:**
- `persistence_auditor.py`:
  - Scheduled tasks: `Get-ScheduledTask | Get-ScheduledTaskInfo` — full XML definition, triggers, actions, creator, last result
  - WMI event subscriptions: `Get-WMIObject -Namespace root\subscription -Class __EventFilter` + consumers + bindings (common persistence for advanced malware)
  - Run keys: direct registry read of common autorun locations
  - Output: JSON per category

**Relationship to existing sysinternals.py autorunsc:** Complementary. If autorunsc binary is available, it runs as primary (more comprehensive). If not, persistence_auditor provides ~80% coverage natively. Pipeline uses both when available, deduplicates findings.

**Tests:** Unit tests with mocked PowerShell output. E2E needs admin for WMI subscriptions.

**Estimated effort:** ~200 lines code + ~100 lines tests

---

### WI-3: Resource analyzer
**Why:** Takes raw process/service data from WI-1 and produces actionable findings — top hogs, bloatware matches, startup impact scores.

**Implementation:**
- `resource_analyzer.py`:
  - Input: `list[ProcessInfo]` + `list[ServiceInfo]` from collectors
  - Top-N ranking by CPU%, RAM, IO, handles, threads with configurable thresholds
  - Bloatware matching against curated YAML/JSON list:
    ```yaml
    bloatware:
      telemetry:
        - service: DiagTrack
          display: "Connected User Experiences and Telemetry"
          recommendation: "Safe to disable for most users"
        - service: dmwappushservice
          display: "WAP Push Message Routing Service"
          recommendation: "Safe to disable"
      consumer:
        - service: XboxGipSvc
          display: "Xbox Accessory Management Service"
          recommendation: "Safe to disable if not using Xbox peripherals"
      # ... etc
    ```
  - Startup impact: cross-reference autoruns entries with process resource data
  - Output: `list[ResourceHog]` + `list[BloatwareMatch]` → `resource-analysis.json`

**Tests:** Unit tests with synthetic process data covering edge cases (idle system, overloaded system, known bloatware present).

**Estimated effort:** ~200 lines code + ~150 lines tests + bloatware list YAML (~100 entries)

---

### WI-4: Baseline differ
**Why:** The diff is the highest-signal section of the report. A clean system that stays clean is boring. A clean system where three new autoruns appeared overnight is alarming.

**Implementation:**
- `baseline_differ.py`:
  - Operates on JSON scan results (not in-memory — must work across runs)
  - First run: copy results to `baseline/` directory, diff section shows "Initial baseline"
  - Subsequent runs: load baseline JSON, load current JSON, compute structural diff
  - Diff categories:
    - Processes: new PIDs/names not in baseline, removed processes, significant resource changes
    - Services: new services, changed start modes, new SYSTEM services
    - Autoruns: any new entry is HIGH signal, removed entries also notable
    - Network: new outbound connections, new listening ports
    - Scheduled tasks: new tasks, modified tasks
  - Each diff entry gets a severity classification:
    - New autorun entry → HIGH
    - New SYSTEM service → HIGH
    - New outbound connection to non-RFC1918 → MEDIUM
    - New process with known name → LOW
    - Resource usage shift > 2x → MEDIUM
  - Output: `BaselineDiff` model → serialized to `baseline-diff.json`

**Tests:** Unit tests with synthetic before/after JSON. Test edge cases: first run (no baseline), identical runs (empty diff), massive changes.

**Estimated effort:** ~250 lines code + ~150 lines tests

---

### WI-5: HTML report generator
**Why:** This is what you actually look at. Everything else is plumbing.

**Implementation:**
- `html_report.py`:
  - Single self-contained HTML file — inline CSS, inline JS, no external deps
  - Uses Python string templates or Jinja2 (Jinja2 preferred if already a dependency, otherwise f-strings to avoid adding deps)
  - Input: `DashboardData` model assembled from all scan results
  - Sections rendered in severity order (critical findings first)
  - Interactive elements (all client-side JS):
    - Collapsible sections
    - Sortable tables (click column header)
    - Severity filter (show/hide by level)
    - Search/filter across all findings
  - Color coding: 🔴 CRITICAL (red), 🟠 HIGH (orange), 🟡 MEDIUM (yellow), 🟢 LOW/CLEAN (green)
  - Executive summary at top: count by severity, baseline diff summary, scan metadata
  - Each finding includes: what was found, where (path/PID/service), why it matters, what to do

**Template structure:**
```html
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Process Scan Report — {timestamp}</title>
  <style>/* ~200 lines inline CSS */</style>
</head>
<body>
  <header><!-- machine info, scan time, duration --></header>
  <section id="summary"><!-- severity counts, diff summary --></section>
  <section id="critical"><!-- critical findings expanded by default --></section>
  <section id="security"><!-- HH, YARA, sigcheck, listdlls results --></section>
  <section id="persistence"><!-- autoruns, tasks, services --></section>
  <section id="performance"><!-- resource hogs, bloatware, startup --></section>
  <section id="diff"><!-- baseline comparison --></section>
  <section id="inventory"><!-- full process/service/network tables --></section>
  <script>/* ~100 lines — sort, filter, collapse */</script>
</body>
</html>
```

**Tests:** Unit test that generates report from synthetic data and validates HTML structure. Visual testing by opening in browser.

**Estimated effort:** ~500 lines code (mostly HTML template) + ~50 lines tests

---

### WI-6: Pipeline integration — `process_scan` factory
**Why:** Wire everything together using the existing pipeline pattern.

**Implementation:**
- Add `process_scan` class method to `pipeline.py` (alongside existing `daily` and `forensic`):
  ```python
  @classmethod
  def process_scan(cls, config: ScanConfig) -> "Pipeline":
      """Full process scanning pipeline: snapshot + security + persistence + analysis + report."""
      pipeline = cls(config)
      
      # Phase 1: Native collectors (no external tools needed)
      pipeline.add_collector(ProcessSnapshotCollector(config))
      pipeline.add_collector(ServiceAuditor(config))
      pipeline.add_collector(NetworkMapper(config))
      
      # Phase 2: Security scanners (external tools, best-effort if missing)
      pipeline.add_scanner(HollowsHunterScanner(config))  # existing
      pipeline.add_scanner(YaraScanner(config))            # existing
      pipeline.add_scanner(SysinternalsScanner(config, tools=["sigcheck", "listdlls"]))  # existing
      
      # Phase 3: Persistence audit
      pipeline.add_scanner(SysinternalsScanner(config, tools=["autorunsc"]))  # existing
      pipeline.add_collector(PersistenceAuditor(config))   # new, supplements autorunsc
      
      # Phase 4: Analysis (runs after collectors and scanners)
      pipeline.add_analyzer(ResourceAnalyzer(config))
      pipeline.add_analyzer(BaselineDiffer(config))
      pipeline.add_analyzer(SeverityScorer(config))
      
      # Phase 5: Reporting
      pipeline.add_reporter(HtmlReportGenerator(config))
      
      return pipeline
  ```
  
- This likely means extending `Pipeline` to support three stage types instead of one:
  - **Collectors** — produce raw data (ProcessInfo, ServiceInfo, etc.)
  - **Scanners** — existing scanner_base subclasses that call external tools
  - **Analyzers** — consume collector + scanner output, produce derived findings
  - **Reporters** — consume everything, produce output files
  
  The existing pipeline already handles scanners. Adding collector/analyzer/reporter stages
  should be additive — don't break the existing `daily` and `forensic` pipelines.

- Add to CLI: `security process-scan` command
- Add to API: `POST /security/process-scan` endpoint
- Add to config.yaml: `process_scan` schedule entry

**Tests:** Integration test that runs the full pipeline with mocked collectors and scanners.

**Estimated effort:** ~200 lines code + ~100 lines tests

---

### WI-7: Scheduler wiring + admin elevation
**Why:** The plan calls for Task Scheduler automation. The config already defines a cron schedule that isn't wired up.

**Implementation:**
- **Option A: Windows Task Scheduler** (recommended for production)
  - PowerShell script to register scheduled task:
    ```powershell
    $action = New-ScheduledTaskAction -Execute "python" -Argument "-m hadoku_agent security process-scan"
    $trigger = New-ScheduledTaskTrigger -Daily -At 2:00AM
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
    Register-ScheduledTask -TaskName "HadokuProcessScan" -Action $action -Trigger $trigger -Principal $principal
    ```
  - Runs as SYSTEM → solves admin elevation for HollowsHunter, autorunsc, listdlls
  - CLI command: `security schedule install` / `security schedule remove`

- **Option B: Internal scheduler** (for when agent runs as a long-lived service)
  - Wire the existing cron config to APScheduler or similar
  - Only works if the agent process itself runs elevated

- **Admin elevation handling:**
  - Detect current privilege level at pipeline start: `ctypes.windll.shell32.IsUserAnAdmin()`
  - If not admin: skip tools requiring elevation, log warning, run what we can
  - If admin: run full pipeline
  - The report should note which tools were skipped due to insufficient privileges

**Tests:** Unit test for privilege detection. Integration test for task registration (mocked).

**Estimated effort:** ~150 lines code + ~50 lines tests

---

## Suggested build order

```
WI-1 (Collectors)           ← foundation, everything depends on this
  ↓
WI-2 (Persistence auditor)  ← small, independent, supplements existing autorunsc
  ↓
WI-3 (Resource analyzer)    ← depends on WI-1 output
  ↓
WI-4 (Baseline differ)      ← depends on WI-1 output format being stable
  ↓
WI-5 (HTML report)          ← depends on all above for data models
  ↓
WI-6 (Pipeline integration) ← wires everything together
  ↓
WI-7 (Scheduler + elevation)← final step, makes it automated
```

Total estimated effort: ~1,900 lines new code + ~800 lines new tests.
Existing code touched: models.py (add new models), pipeline.py (add stages), cli.py (add command), monitoring.py (add endpoint), config.yaml (add schedule).

---