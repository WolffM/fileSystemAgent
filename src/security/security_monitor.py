"""FastAPI routes for security scanning status, tools, and findings."""

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query

from .pipeline import ScanPipeline
from .tool_manager import ToolManager

logger = logging.getLogger(__name__)


def create_security_router(
    tool_manager: ToolManager,
    scan_pipeline: ScanPipeline,
) -> APIRouter:
    """Create FastAPI router with security scanning endpoints."""

    router = APIRouter(prefix="/security", tags=["security"])

    @router.get("/tools")
    async def get_tools() -> Dict[str, Any]:
        """Get availability status for all security tools."""
        tools = tool_manager.check_all_tools()
        return {
            "tools": {
                name: {
                    "display_name": info.display_name,
                    "installed": info.installed,
                    "path": str(info.path) if info.path else None,
                    "requires_admin": info.requires_admin,
                    "license": info.license,
                    "install_method": info.install_method,
                }
                for name, info in tools.items()
            },
            "installed_count": sum(1 for t in tools.values() if t.installed),
            "total_count": len(tools),
        }

    @router.get("/scans")
    async def get_scans(limit: int = Query(10, ge=1, le=100)) -> Dict[str, Any]:
        """Get recent pipeline scan results."""
        results = scan_pipeline.get_recent_results(limit)
        return {
            "scans": [
                {
                    "pipeline_id": r.pipeline_id,
                    "pipeline_name": r.pipeline_name,
                    "status": r.status.value,
                    "started_at": r.started_at.isoformat() if r.started_at else None,
                    "completed_at": r.completed_at.isoformat() if r.completed_at else None,
                    "duration_seconds": r.duration_seconds,
                    "total_findings": r.total_findings,
                    "critical_findings": r.critical_findings,
                    "high_findings": r.high_findings,
                    "steps": [
                        {
                            "tool_name": sr.tool_name,
                            "status": sr.status.value,
                            "findings_count": sr.findings_count,
                            "duration_seconds": sr.duration_seconds,
                        }
                        for sr in r.scan_results
                    ],
                }
                for r in results
            ],
            "count": len(results),
        }

    @router.get("/findings")
    async def get_findings(
        limit: int = Query(50, ge=1, le=500),
        severity: Optional[str] = Query(None),
    ) -> Dict[str, Any]:
        """Get recent security findings, optionally filtered by severity."""
        all_findings = scan_pipeline.get_all_findings(limit=limit * 2)

        if severity:
            all_findings = [
                f for f in all_findings if f.severity.value == severity.lower()
            ]

        findings_out = all_findings[:limit]
        return {
            "findings": [
                {
                    "finding_id": f.finding_id,
                    "tool_name": f.tool_name,
                    "severity": f.severity.value,
                    "category": f.category,
                    "title": f.title,
                    "description": f.description,
                    "target": f.target,
                    "timestamp": f.timestamp.isoformat(),
                    "mitre_attack": f.mitre_attack,
                }
                for f in findings_out
            ],
            "count": len(findings_out),
        }

    return router
