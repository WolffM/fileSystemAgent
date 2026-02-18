"""Scan pipeline orchestration — runs multiple scanners in sequence and aggregates results."""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from .models import (
    PipelineConfig,
    PipelineResult,
    ScanConfig,
    ScanResult,
    ScanStatus,
    ScanTarget,
)
from .scanner_base import ScannerBase
from .scanners.clamav import ClamAVScanner
from .scanners.hollows_hunter import HollowsHunterScanner
from .scanners.yara_scanner import YaraScanner
from .scanners.hayabusa import HayabusaScanner
from .scanners.chainsaw import ChainsawScanner
from .scanners.sysinternals import AutorunscScanner, SigcheckScanner, ListDllsScanner
from .tool_manager import ToolManager

logger = logging.getLogger(__name__)


class ScanPipeline:
    """Orchestrates multi-tool security scan pipelines."""

    def __init__(
        self,
        tool_manager: ToolManager,
        config: Optional[Dict[str, Any]] = None,
    ):
        self.tool_manager = tool_manager
        self.config = config or {}
        self._scanners: Dict[str, ScannerBase] = {}
        self._results: List[PipelineResult] = []
        self._register_scanners()

    def _register_scanners(self) -> None:
        """Instantiate all scanner classes."""
        tools_config = self.config.get("tools", {})
        self._scanners = {
            "clamav": ClamAVScanner(self.tool_manager, tools_config.get("clamav", {})),
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

    def get_scanner(self, tool_name: str) -> Optional[ScannerBase]:
        """Get scanner by tool name."""
        return self._scanners.get(tool_name)

    async def run_pipeline(self, pipeline_config: PipelineConfig) -> PipelineResult:
        """Execute a pipeline of scans sequentially.

        Runs each step in order. If stop_on_failure is True, stops
        on the first scanner failure. Skips tools that aren't installed.
        """
        result = PipelineResult(
            pipeline_name=pipeline_config.name,
            status=ScanStatus.RUNNING,
            started_at=datetime.now(),
        )

        logger.info(
            f"Starting pipeline '{pipeline_config.name}' "
            f"with {len(pipeline_config.steps)} steps"
        )

        for i, step_config in enumerate(pipeline_config.steps, 1):
            scanner = self._scanners.get(step_config.tool_name)
            if not scanner:
                logger.warning(
                    f"Step {i}: No scanner registered for '{step_config.tool_name}', skipping"
                )
                skip_result = ScanResult(
                    tool_name=step_config.tool_name,
                    config=step_config,
                    status=ScanStatus.SKIPPED,
                    error_message=f"No scanner registered for '{step_config.tool_name}'",
                )
                result.scan_results.append(skip_result)
                continue

            logger.info(
                f"Step {i}/{len(pipeline_config.steps)}: "
                f"Running {step_config.tool_name}..."
            )

            scan_result = await scanner.run(step_config)
            result.scan_results.append(scan_result)

            logger.info(
                f"Step {i}: {step_config.tool_name} -> "
                f"{scan_result.status.value} "
                f"({scan_result.findings_count} findings)"
            )

            if (
                pipeline_config.stop_on_failure
                and scan_result.status == ScanStatus.FAILED
            ):
                logger.warning(
                    f"Pipeline stopped: {step_config.tool_name} failed "
                    f"and stop_on_failure=True"
                )
                result.status = ScanStatus.FAILED
                result.completed_at = datetime.now()
                self._results.append(result)
                return result

        result.status = ScanStatus.COMPLETED
        result.completed_at = datetime.now()

        logger.info(
            f"Pipeline '{pipeline_config.name}' completed: "
            f"{result.total_findings} total findings "
            f"({result.critical_findings} critical, {result.high_findings} high)"
        )

        self._results.append(result)
        return result

    def get_recent_results(self, limit: int = 10) -> List[PipelineResult]:
        """Get the most recent pipeline results."""
        return self._results[-limit:]

    def get_all_findings(self, limit: int = 100):
        """Get all findings from recent pipelines, newest first."""
        findings = []
        for pr in reversed(self._results):
            for sr in pr.scan_results:
                findings.extend(sr.findings)
                if len(findings) >= limit:
                    return findings[:limit]
        return findings

    @staticmethod
    def create_daily_pipeline(
        scan_target: str = "C:\\Users",
        output_dir: str = "./data/security/scans",
    ) -> PipelineConfig:
        """Create the standard daily security scan pipeline.

        Layer 2 from the research doc: the 8-step scheduled scan.
        """
        return PipelineConfig(
            name="daily_security_scan",
            description="Standard daily scan: ClamAV, YARA, HollowsHunter, "
                        "Hayabusa, Autoruns, Sigcheck, ListDLLs",
            steps=[
                # 1. ClamAV signature scan
                ScanConfig(
                    tool_name="clamav",
                    target=ScanTarget(target_type="path", target_value=scan_target),
                    output_dir=output_dir,
                    timeout=1800,  # 30 min for full scan
                ),
                # 2. YARA pattern scan
                ScanConfig(
                    tool_name="yara_x",
                    target=ScanTarget(target_type="path", target_value=scan_target),
                    output_dir=output_dir,
                    timeout=1800,
                ),
                # 3. HollowsHunter process scan
                ScanConfig(
                    tool_name="hollows_hunter",
                    target=ScanTarget(target_type="system", target_value=""),
                    output_dir=output_dir,
                    timeout=600,
                ),
                # 4. Hayabusa live event log analysis
                ScanConfig(
                    tool_name="hayabusa",
                    target=ScanTarget(target_type="eventlog", target_value="live"),
                    output_dir=output_dir,
                    timeout=600,
                ),
                # 5. Autoruns persistence audit
                ScanConfig(
                    tool_name="autorunsc",
                    target=ScanTarget(target_type="system", target_value=""),
                    output_dir=output_dir,
                    timeout=300,
                ),
                # 6. Sigcheck unsigned binary detection
                ScanConfig(
                    tool_name="sigcheck",
                    target=ScanTarget(
                        target_type="path",
                        target_value="C:\\Windows\\System32",
                    ),
                    output_dir=output_dir,
                    timeout=600,
                ),
                # 7. ListDLLs unsigned DLL detection
                ScanConfig(
                    tool_name="listdlls",
                    target=ScanTarget(target_type="system", target_value=""),
                    output_dir=output_dir,
                    timeout=300,
                ),
            ],
        )

    @staticmethod
    def create_forensic_pipeline(
        evtx_path: str = "C:\\Windows\\System32\\winevt\\Logs",
        output_dir: str = "./data/security/scans",
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
