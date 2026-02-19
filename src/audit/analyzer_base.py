"""Abstract base class for pipeline analyzers.

Analyzers consume data from the shared pipeline context dict
(populated by collectors) and produce audit findings. They run
after collectors and scanners in the pipeline execution order.
"""

import logging
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict

from .models import AnalyzerConfig, AnalyzerResult, ScanStatus

logger = logging.getLogger(__name__)


class AnalyzerBase(ABC):
    """Abstract base for pipeline analyzers."""

    @property
    @abstractmethod
    def analyzer_name(self) -> str:
        """Unique identifier for this analyzer."""

    @abstractmethod
    async def analyze(
        self, config: AnalyzerConfig, context: Dict[str, Any]
    ) -> AnalyzerResult:
        """Run the analysis logic.

        Args:
            config: Analyzer configuration.
            context: Shared pipeline context dict populated by collectors.

        Returns:
            AnalyzerResult with findings.
        """

    async def run(
        self, config: AnalyzerConfig, context: Dict[str, Any]
    ) -> AnalyzerResult:
        """Execute the analyzer with timing and error handling."""
        started_at = datetime.now()

        try:
            result = await self.analyze(config, context)
        except Exception as e:
            result = AnalyzerResult(
                analyzer_name=self.analyzer_name,
                status=ScanStatus.FAILED,
                error_message=f"{self.analyzer_name} error: {e}",
            )
            logger.error(result.error_message, exc_info=True)

        result.started_at = started_at
        result.completed_at = datetime.now()
        result.duration_seconds = (
            result.completed_at - result.started_at
        ).total_seconds()

        logger.info(
            f"{self.analyzer_name} {result.status.value}: "
            f"{result.findings_count} findings"
        )
        return result
