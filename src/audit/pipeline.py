"""Scan pipeline orchestration — runs collectors, scanners, and analyzers in staged order."""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .analyzer_base import AnalyzerBase
from .collector_base import CollectorBase
from .models import (
    AnalyzerConfig,
    AnalyzerResult,
    CollectorConfig,
    CollectorResult,
    Finding,
    PipelineConfig,
    PipelineResult,
    ScanConfig,
    ScanResult,
    ScanStatus,
    ScanTarget,
    SeverityLevel,
)
from .scanner_base import ScannerBase
from .scanners.hollows_hunter import HollowsHunterScanner
from .scanners.yara_scanner import YaraScanner
from .scanners.hayabusa import HayabusaScanner
from .scanners.chainsaw import ChainsawScanner
from .scanners.sysinternals import AutorunscScanner, SigcheckScanner, ListDllsScanner
from .tool_manager import ToolManager

logger = logging.getLogger(__name__)


class ScanPipeline:
    """Orchestrates multi-tool audit pipelines.

    Execution order:
    1. Collectors — native Windows data collection (WMI, PowerShell)
    2. Scanners — external tool-based scanning (YARA, ClamAV, etc.)
    3. Analyzers — post-scan analysis consuming collector/scanner output (future)

    A shared context dict flows through the pipeline, allowing collectors to
    write structured data that analyzers can read.
    """

    def __init__(
        self,
        tool_manager: ToolManager,
        config: Optional[Dict[str, Any]] = None,
    ):
        self.tool_manager = tool_manager
        self.config = config or {}
        self.output_dir = self.config.get("output_dir", "./data/audit/scans")
        self._scanners: Dict[str, ScannerBase] = {}
        self._collectors: Dict[str, CollectorBase] = {}
        self._analyzers: Dict[str, AnalyzerBase] = {}
        self._results: List[PipelineResult] = []
        self._register_scanners()
        self._register_collectors()
        self._register_analyzers()

    def _register_scanners(self) -> None:
        """Instantiate all scanner classes."""
        tools_config = self.config.get("tools", {})
        self._scanners = {
            "hollows_hunter": HollowsHunterScanner(
                self.tool_manager, tools_config.get("hollows_hunter", {})
            ),
            "yara_x": YaraScanner(self.tool_manager, tools_config.get("yara_x", {})),
            "hayabusa": HayabusaScanner(
                self.tool_manager, tools_config.get("hayabusa", {})
            ),
            "chainsaw": ChainsawScanner(
                self.tool_manager, tools_config.get("chainsaw", {})
            ),
            "autorunsc": AutorunscScanner(
                self.tool_manager, tools_config.get("autorunsc", {})
            ),
            "sigcheck": SigcheckScanner(
                self.tool_manager, tools_config.get("sigcheck", {})
            ),
            "listdlls": ListDllsScanner(
                self.tool_manager, tools_config.get("listdlls", {})
            ),
        }

    def _register_collectors(self) -> None:
        """Instantiate all collector classes."""
        from .collectors import (
            ProcessSnapshotCollector,
            ServiceAuditorCollector,
            NetworkMapperCollector,
            PersistenceAuditorCollector,
        )
        self._collectors = {
            "process_snapshot": ProcessSnapshotCollector(),
            "service_auditor": ServiceAuditorCollector(),
            "network_mapper": NetworkMapperCollector(),
            "persistence_auditor": PersistenceAuditorCollector(),
        }

    def _register_analyzers(self) -> None:
        """Instantiate all analyzer classes."""
        from .analyzers import ResourceAnalyzer, BaselineDiffer
        self._analyzers = {
            "resource_analyzer": ResourceAnalyzer(),
            "baseline_differ": BaselineDiffer(),
        }

    def get_scanner(self, tool_name: str) -> Optional[ScannerBase]:
        """Get scanner by tool name."""
        return self._scanners.get(tool_name)

    def get_collector(self, name: str) -> Optional[CollectorBase]:
        """Get collector by name."""
        return self._collectors.get(name)

    def get_analyzer(self, name: str) -> Optional[AnalyzerBase]:
        """Get analyzer by name."""
        return self._analyzers.get(name)

    async def run_pipeline(
        self,
        pipeline_config: PipelineConfig,
        on_step_start: Optional[callable] = None,
        on_step_complete: Optional[callable] = None,
    ) -> PipelineResult:
        """Execute a pipeline in staged order: collectors → scanners → analyzers.

        Runs each stage in order. Within a stage, steps run sequentially.
        If stop_on_failure is True, stops on the first failure.
        Skips tools/collectors that aren't registered.
        Results are persisted to disk after completion.

        Args:
            pipeline_config: The pipeline to execute.
            on_step_start: Optional callback(step_num, total, name) called before each step.
            on_step_complete: Optional callback(step_num, total, name, status, findings, duration)
                              called after each step completes.
        """
        result = PipelineResult(
            pipeline_name=pipeline_config.name,
            status=ScanStatus.RUNNING,
            started_at=datetime.now(),
        )

        total_steps = (
            len(pipeline_config.collectors)
            + len(pipeline_config.steps)
            + len(pipeline_config.analyzers)
        )
        logger.info(
            f"Starting pipeline '{pipeline_config.name}' "
            f"with {total_steps} steps "
            f"({len(pipeline_config.collectors)} collectors, "
            f"{len(pipeline_config.steps)} scanners, "
            f"{len(pipeline_config.analyzers)} analyzers)"
        )

        def _notify_start(step_num: int, name: str) -> None:
            if on_step_start:
                on_step_start(step_num, total_steps, name)

        def _notify_complete(step_num: int, name: str, status: str, findings: int, duration: float) -> None:
            if on_step_complete:
                on_step_complete(step_num, total_steps, name, status, findings, duration)

        # Shared context for data flow between stages
        context: Dict[str, Any] = {}
        step_num = 0
        failed = False

        # Stage 1: Collectors
        for collector_config in pipeline_config.collectors:
            step_num += 1
            collector = self._collectors.get(collector_config.collector_name)
            if not collector:
                logger.warning(
                    f"Step {step_num}: No collector registered for "
                    f"'{collector_config.collector_name}', skipping"
                )
                skip_result = CollectorResult(
                    collector_name=collector_config.collector_name,
                    status=ScanStatus.SKIPPED,
                    error_message=(
                        f"No collector registered for "
                        f"'{collector_config.collector_name}'"
                    ),
                )
                result.collector_results.append(skip_result)
                _notify_complete(step_num, collector_config.collector_name, "skipped", 0, 0)
                continue

            _notify_start(step_num, collector_config.collector_name)
            collector_result = await collector.run(collector_config, context)
            result.collector_results.append(collector_result)

            _notify_complete(
                step_num,
                collector_config.collector_name,
                collector_result.status.value,
                collector_result.findings_count,
                collector_result.duration_seconds or 0,
            )

            if (
                pipeline_config.stop_on_failure
                and collector_result.status == ScanStatus.FAILED
            ):
                failed = True
                break

        # Stage 2: Scanners (existing behavior)
        if not failed:
            for step_config in pipeline_config.steps:
                step_num += 1
                scanner = self._scanners.get(step_config.tool_name)
                if not scanner:
                    logger.warning(
                        f"Step {step_num}: No scanner registered for "
                        f"'{step_config.tool_name}', skipping"
                    )
                    skip_result = ScanResult(
                        tool_name=step_config.tool_name,
                        config=step_config,
                        status=ScanStatus.SKIPPED,
                        error_message=(
                            f"No scanner registered for '{step_config.tool_name}'"
                        ),
                    )
                    result.scan_results.append(skip_result)
                    _notify_complete(step_num, step_config.tool_name, "skipped", 0, 0)
                    continue

                _notify_start(step_num, step_config.tool_name)
                scan_result = await scanner.run(step_config)
                result.scan_results.append(scan_result)

                _notify_complete(
                    step_num,
                    step_config.tool_name,
                    scan_result.status.value,
                    scan_result.findings_count,
                    scan_result.duration_seconds or 0,
                )

                if (
                    pipeline_config.stop_on_failure
                    and scan_result.status == ScanStatus.FAILED
                ):
                    failed = True
                    break

        # Stage 3: Analyzers — consume context data from collectors
        if not failed:
            for analyzer_config in pipeline_config.analyzers:
                step_num += 1
                analyzer = self._analyzers.get(analyzer_config.analyzer_name)
                if not analyzer:
                    logger.warning(
                        f"Step {step_num}: No analyzer registered for "
                        f"'{analyzer_config.analyzer_name}', skipping"
                    )
                    skip_result = AnalyzerResult(
                        analyzer_name=analyzer_config.analyzer_name,
                        status=ScanStatus.SKIPPED,
                        error_message=(
                            f"No analyzer registered for "
                            f"'{analyzer_config.analyzer_name}'"
                        ),
                    )
                    result.analyzer_results.append(skip_result)
                    _notify_complete(step_num, analyzer_config.analyzer_name, "skipped", 0, 0)
                    continue

                _notify_start(step_num, analyzer_config.analyzer_name)
                analyzer_result = await analyzer.run(analyzer_config, context)
                result.analyzer_results.append(analyzer_result)

                _notify_complete(
                    step_num,
                    analyzer_config.analyzer_name,
                    analyzer_result.status.value,
                    analyzer_result.findings_count,
                    analyzer_result.duration_seconds or 0,
                )

                if (
                    pipeline_config.stop_on_failure
                    and analyzer_result.status == ScanStatus.FAILED
                ):
                    failed = True
                    break

        # Finalize
        if failed:
            result.status = ScanStatus.FAILED
            logger.warning(
                f"Pipeline '{pipeline_config.name}' stopped due to failure"
            )
        else:
            result.status = ScanStatus.COMPLETED

        result.completed_at = datetime.now()

        logger.info(
            f"Pipeline '{pipeline_config.name}' {result.status.value}: "
            f"{result.total_findings} total findings "
            f"({result.critical_findings} critical, {result.high_findings} high)"
        )

        self._results.append(result)
        self._save_result(result)
        return result

    # ---- Result persistence ----

    def _save_result(self, result: PipelineResult) -> Optional[Path]:
        """Save a pipeline result to disk as JSON."""
        try:
            scan_dir = Path(self.output_dir)
            scan_dir.mkdir(parents=True, exist_ok=True)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{result.pipeline_name}_{timestamp}.json"
            filepath = scan_dir / filename

            data = result.model_dump(mode="json")
            filepath.write_text(json.dumps(data, indent=2, default=str))
            logger.info(f"Saved pipeline result to {filepath}")
            return filepath
        except Exception as e:
            logger.error(f"Failed to save pipeline result: {e}")
            return None

    @staticmethod
    def load_results(
        scan_dir: str = "./data/audit/scans",
        limit: int = 10,
    ) -> List[PipelineResult]:
        """Load pipeline results from disk, newest first."""
        results_dir = Path(scan_dir)
        if not results_dir.is_dir():
            return []

        json_files = sorted(
            results_dir.glob("*.json"),
            key=lambda f: f.stat().st_mtime,
            reverse=True,
        )

        results = []
        for filepath in json_files[:limit]:
            try:
                data = json.loads(filepath.read_text())
                result = PipelineResult.model_validate(data)
                results.append(result)
            except Exception as e:
                logger.warning(f"Failed to load {filepath}: {e}")
                continue
        return results

    # ---- Query methods ----

    def get_recent_results(self, limit: int = 10) -> List[PipelineResult]:
        """Get the most recent pipeline results (in-memory + disk fallback)."""
        if self._results:
            return self._results[-limit:]
        return self.load_results(self.output_dir, limit)

    _SEVERITY_ORDER = {
        SeverityLevel.CRITICAL: 0,
        SeverityLevel.HIGH: 1,
        SeverityLevel.MEDIUM: 2,
        SeverityLevel.LOW: 3,
        SeverityLevel.INFO: 4,
    }

    def get_all_findings(self, limit: int = 100) -> List[Finding]:
        """Get all findings from recent pipelines, sorted by severity (highest first)."""
        findings: List[Finding] = []
        results = self.get_recent_results(limit)
        for pr in reversed(results):
            for sr in pr.scan_results:
                findings.extend(sr.findings)
            for cr in pr.collector_results:
                findings.extend(cr.findings)
            for ar in pr.analyzer_results:
                findings.extend(ar.findings)
        findings.sort(key=lambda f: self._SEVERITY_ORDER.get(f.severity, 99))
        return findings[:limit]

    # ---- Factory methods ----

    @staticmethod
    def create_daily_pipeline(
        scan_target: str = ".",
        output_dir: str = "./data/audit/scans",
        evtx_path: str = "./data/evtx",
    ) -> PipelineConfig:
        """Create the standard daily scan pipeline.

        Designed to complete in under 5 minutes with no arguments.
        System-wide tools (HollowsHunter, Autoruns, ListDLLs) scan the whole
        system. Hayabusa scans Windows event logs offline (no admin required).
        Path-based tools (YARA, Sigcheck) scan the working directory by
        default — pass scan_target to override.

        Args:
            evtx_path: Directory containing .evtx files for offline Hayabusa
                analysis. Defaults to ./data/evtx (copy logs there once as
                admin, then scan without elevation).
        """
        return PipelineConfig(
            name="daily_scan",
            description="Daily scan: YARA, HollowsHunter, Hayabusa, "
                        "Autoruns, Sigcheck, ListDLLs",
            steps=[
                # 1. YARA pattern scan
                ScanConfig(
                    tool_name="yara_x",
                    target=ScanTarget(target_type="path", target_value=scan_target),
                    output_dir=output_dir,
                    timeout=120,
                ),
                # 2. HollowsHunter process scan
                ScanConfig(
                    tool_name="hollows_hunter",
                    target=ScanTarget(target_type="system", target_value=""),
                    output_dir=output_dir,
                    timeout=120,
                ),
                # 3. Hayabusa event log analysis (offline — no admin required)
                ScanConfig(
                    tool_name="hayabusa",
                    target=ScanTarget(
                        target_type="eventlog",
                        target_value=evtx_path,
                    ),
                    output_dir=output_dir,
                    timeout=120,
                ),
                # 4. Autoruns persistence audit
                ScanConfig(
                    tool_name="autorunsc",
                    target=ScanTarget(target_type="system", target_value=""),
                    output_dir=output_dir,
                    timeout=60,
                ),
                # 5. Sigcheck unsigned binary detection
                ScanConfig(
                    tool_name="sigcheck",
                    target=ScanTarget(
                        target_type="path",
                        target_value=scan_target,
                    ),
                    output_dir=output_dir,
                    timeout=120,
                ),
                # 6. ListDLLs unsigned DLL detection
                ScanConfig(
                    tool_name="listdlls",
                    target=ScanTarget(target_type="system", target_value=""),
                    output_dir=output_dir,
                    timeout=120,
                ),
            ],
        )

    @staticmethod
    def create_process_scan_pipeline(
        output_dir: str = "./data/audit/scans",
        baseline_dir: str = "./data/audit/baselines",
    ) -> PipelineConfig:
        """Create the process scanning pipeline.

        Full system inventory: collectors gather data, analyzers detect
        anomalies and diff against baseline.

        Stages:
        1. Collectors: process snapshot, service audit, network map, persistence
        2. Scanners: HollowsHunter (in-memory process scan)
        3. Analyzers: resource analyzer, baseline differ
        """
        return PipelineConfig(
            name="process_scan",
            description="Process scan: system inventory + anomaly detection + baseline diff",
            collectors=[
                CollectorConfig(collector_name="process_snapshot"),
                CollectorConfig(collector_name="service_auditor"),
                CollectorConfig(collector_name="network_mapper"),
                CollectorConfig(collector_name="persistence_auditor"),
            ],
            steps=[
                ScanConfig(
                    tool_name="hollows_hunter",
                    target=ScanTarget(target_type="system", target_value=""),
                    output_dir=output_dir,
                    timeout=600,
                ),
            ],
            analyzers=[
                AnalyzerConfig(analyzer_name="resource_analyzer"),
                AnalyzerConfig(
                    analyzer_name="baseline_differ",
                    extra_args={"baseline_dir": baseline_dir},
                ),
            ],
        )

    @staticmethod
    def create_forensic_pipeline(
        evtx_path: str = "./data/evtx",
        output_dir: str = "./data/audit/scans",
    ) -> PipelineConfig:
        """Create a Layer 3 forensic triage pipeline.

        Uses Chainsaw for broad artifact analysis + Hayabusa for deep timeline.
        """
        return PipelineConfig(
            name="forensic_triage",
            description="Forensic triage: Chainsaw + Hayabusa deep analysis",
            steps=[
                ScanConfig(
                    tool_name="chainsaw",
                    target=ScanTarget(target_type="path", target_value=evtx_path),
                    output_dir=output_dir,
                    timeout=1800,
                ),
                ScanConfig(
                    tool_name="hayabusa",
                    target=ScanTarget(target_type="eventlog", target_value=evtx_path),
                    output_dir=output_dir,
                    timeout=1800,
                    extra_args={"min_level": "low"},
                ),
            ],
        )
