"""Self-contained HTML report generator for audit scan results.

Produces a single HTML file with inline CSS — no external dependencies.
"""

import html
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..models import (
    Finding,
    FindingDomain,
    PipelineResult,
    ScanStatus,
    SeverityLevel,
)

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = {
    SeverityLevel.CRITICAL: 0,
    SeverityLevel.HIGH: 1,
    SeverityLevel.MEDIUM: 2,
    SeverityLevel.LOW: 3,
    SeverityLevel.INFO: 4,
}

_SEVERITY_COLORS = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#d97706",
    "low": "#2563eb",
    "info": "#6b7280",
}

_DOMAIN_COLORS = {
    "security": "#1e40af",
    "performance": "#c2410c",
    "hygiene": "#4b5563",
}

_DOMAIN_ORDER = {
    FindingDomain.SECURITY: 0,
    FindingDomain.PERFORMANCE: 1,
    FindingDomain.HYGIENE: 2,
}


class HtmlReportGenerator:
    """Generates a self-contained HTML report from a PipelineResult."""

    def generate(
        self,
        result: PipelineResult,
        output_path: Optional[str] = None,
    ) -> str:
        """Generate HTML report and optionally write to file.

        Returns the HTML string. If output_path is given, also writes to disk.
        """
        html_content = self._build_html(result)

        if output_path:
            path = Path(output_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(html_content, encoding="utf-8")
            logger.info(f"HTML report written to {path}")

        return html_content

    def _build_html(self, result: PipelineResult) -> str:
        """Build the complete HTML document."""
        findings = self._collect_findings(result)

        sections = [
            self._section_executive_summary(result, findings),
            self._section_findings_table(findings),
            self._section_resource_overview(result),
            self._section_pipeline_steps(result),
            self._section_inventory_summary(result),
            self._section_baseline_diff(result),
        ]

        body = "\n".join(s for s in sections if s)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>System Health Report — {_esc(result.pipeline_name)}</title>
{self._css()}
</head>
<body>
<header>
<h1>System Health Report</h1>
<p class="subtitle">{_esc(result.pipeline_name)} &mdash; {_format_dt(result.started_at)}</p>
</header>
<main>
{body}
</main>
<footer>
<p>Generated {_format_dt(datetime.now())} by FileSystem Agent</p>
</footer>
</body>
</html>"""

    # ---- Sections ----

    def _section_executive_summary(
        self, result: PipelineResult, findings: List[Finding]
    ) -> str:
        severity_counts = self._count_by_severity(findings)
        status_class = "pass" if result.status == ScanStatus.COMPLETED else "fail"
        duration = (
            f"{result.duration_seconds:.1f}s"
            if result.duration_seconds is not None
            else "N/A"
        )

        sev_cards = ""
        for sev in ("critical", "high", "medium", "low", "info"):
            count = severity_counts.get(sev, 0)
            color = _SEVERITY_COLORS[sev]
            sev_cards += f"""<div class="card" style="border-left: 4px solid {color}">
<div class="card-value">{count}</div>
<div class="card-label">{sev.upper()}</div>
</div>\n"""

        domain_counts = self._count_by_domain(findings)
        domain_cards = ""
        for dom in ("security", "performance", "hygiene"):
            count = domain_counts.get(dom, 0)
            color = _DOMAIN_COLORS[dom]
            domain_cards += f"""<div class="card" style="border-left: 4px solid {color}">
<div class="card-value">{count}</div>
<div class="card-label">{dom.upper()}</div>
</div>\n"""

        collector_count = len(result.collector_results)
        scanner_count = len(result.scan_results)
        analyzer_count = len(result.analyzer_results)

        return f"""<section id="summary">
<h2>Executive Summary</h2>
<div class="summary-grid">
<div class="card summary-card {status_class}">
<div class="card-value">{result.status.value.upper()}</div>
<div class="card-label">Pipeline Status</div>
</div>
<div class="card">
<div class="card-value">{len(findings)}</div>
<div class="card-label">Total Findings</div>
</div>
<div class="card">
<div class="card-value">{duration}</div>
<div class="card-label">Duration</div>
</div>
<div class="card">
<div class="card-value">{collector_count + scanner_count + analyzer_count}</div>
<div class="card-label">Steps ({collector_count}C/{scanner_count}S/{analyzer_count}A)</div>
</div>
</div>
<h3>Findings by Severity</h3>
<div class="severity-grid">
{sev_cards}</div>
<h3>Findings by Domain</h3>
<div class="severity-grid">
{domain_cards}</div>
</section>"""

    def _section_findings_table(self, findings: List[Finding]) -> str:
        if not findings:
            return """<section id="findings">
<h2>Findings</h2>
<p class="empty">No findings.</p>
</section>"""

        rows = ""
        for f in findings:
            color = _SEVERITY_COLORS.get(f.severity.value, "#6b7280")
            dom_color = _DOMAIN_COLORS.get(f.domain.value, "#4b5563")
            mitre = f.mitre_attack or ""
            rows += f"""<tr>
<td><span class="severity-badge" style="background:{color}">{_esc(f.severity.value.upper())}</span></td>
<td><span class="domain-badge" style="background:{dom_color}">{_esc(f.domain.value.upper())}</span></td>
<td>{_esc(f.title)}</td>
<td>{_esc(f.category)}</td>
<td>{_esc(f.tool_name)}</td>
<td class="desc">{_esc(f.description)}</td>
<td>{_esc(mitre)}</td>
</tr>\n"""

        return f"""<section id="findings">
<h2>Findings ({len(findings)})</h2>
<div class="table-wrap">
<table>
<thead>
<tr><th>Severity</th><th>Domain</th><th>Title</th><th>Category</th><th>Source</th><th>Description</th><th>MITRE</th></tr>
</thead>
<tbody>
{rows}</tbody>
</table>
</div>
</section>"""

    def _section_resource_overview(self, result: PipelineResult) -> str:
        """Build top resource users section from analyzer data."""
        ra_data = None
        for ar in result.analyzer_results:
            if ar.analyzer_name == "resource_analyzer" and ar.data:
                ra_data = ar.data
                break

        if not ra_data or ra_data.get("skipped"):
            return ""

        tables = []

        # Top RAM
        top_ram = ra_data.get("top_ram", [])
        if top_ram:
            rows = ""
            for p in top_ram:
                rows += f"""<tr>
<td>{_esc(str(p.get('name', '')))}</td>
<td>{p.get('pid', '')}</td>
<td>{p.get('ram_mb', 0):.0f} MB</td>
<td class="desc">{_esc(str(p.get('path', '') or ''))}</td>
</tr>\n"""
            tables.append(f"""<h3>Top RAM Users</h3>
<div class="table-wrap">
<table>
<thead><tr><th>Process</th><th>PID</th><th>RAM</th><th>Path</th></tr></thead>
<tbody>{rows}</tbody>
</table></div>""")

        # Top Threads
        top_threads = ra_data.get("top_threads", [])
        if top_threads:
            rows = ""
            for p in top_threads:
                rows += f"""<tr>
<td>{_esc(str(p.get('name', '')))}</td>
<td>{p.get('pid', '')}</td>
<td>{p.get('thread_count', 0)}</td>
<td class="desc">{_esc(str(p.get('path', '') or ''))}</td>
</tr>\n"""
            tables.append(f"""<h3>Top Thread Users</h3>
<div class="table-wrap">
<table>
<thead><tr><th>Process</th><th>PID</th><th>Threads</th><th>Path</th></tr></thead>
<tbody>{rows}</tbody>
</table></div>""")

        # Top Handles
        top_handles = ra_data.get("top_handles", [])
        if top_handles:
            rows = ""
            for p in top_handles:
                rows += f"""<tr>
<td>{_esc(str(p.get('name', '')))}</td>
<td>{p.get('pid', '')}</td>
<td>{p.get('handle_count', 0)}</td>
<td class="desc">{_esc(str(p.get('path', '') or ''))}</td>
</tr>\n"""
            tables.append(f"""<h3>Top Handle Users</h3>
<div class="table-wrap">
<table>
<thead><tr><th>Process</th><th>PID</th><th>Handles</th><th>Path</th></tr></thead>
<tbody>{rows}</tbody>
</table></div>""")

        if not tables:
            return ""

        body = "\n".join(tables)
        return f"""<section id="resources">
<h2>Top Resource Users</h2>
{body}
</section>"""

    def _section_pipeline_steps(self, result: PipelineResult) -> str:
        rows = ""

        for cr in result.collector_results:
            status_cls = _status_class(cr.status)
            duration = (
                f"{cr.duration_seconds:.1f}s"
                if cr.duration_seconds is not None
                else "—"
            )
            rows += f"""<tr>
<td>Collector</td>
<td>{_esc(cr.collector_name)}</td>
<td class="{status_cls}">{_esc(cr.status.value)}</td>
<td>{cr.findings_count}</td>
<td>{duration}</td>
<td>{_esc(cr.error_message or '')}</td>
</tr>\n"""

        for sr in result.scan_results:
            status_cls = _status_class(sr.status)
            duration = (
                f"{sr.duration_seconds:.1f}s"
                if sr.duration_seconds is not None
                else "—"
            )
            rows += f"""<tr>
<td>Scanner</td>
<td>{_esc(sr.tool_name)}</td>
<td class="{status_cls}">{_esc(sr.status.value)}</td>
<td>{sr.findings_count}</td>
<td>{duration}</td>
<td>{_esc(sr.error_message or '')}</td>
</tr>\n"""

        for ar in result.analyzer_results:
            status_cls = _status_class(ar.status)
            duration = (
                f"{ar.duration_seconds:.1f}s"
                if ar.duration_seconds is not None
                else "—"
            )
            rows += f"""<tr>
<td>Analyzer</td>
<td>{_esc(ar.analyzer_name)}</td>
<td class="{status_cls}">{_esc(ar.status.value)}</td>
<td>{ar.findings_count}</td>
<td>{duration}</td>
<td>{_esc(ar.error_message or '')}</td>
</tr>\n"""

        return f"""<section id="steps">
<h2>Pipeline Steps</h2>
<div class="table-wrap">
<table>
<thead>
<tr><th>Type</th><th>Name</th><th>Status</th><th>Findings</th><th>Duration</th><th>Error</th></tr>
</thead>
<tbody>
{rows}</tbody>
</table>
</div>
</section>"""

    def _section_inventory_summary(self, result: PipelineResult) -> str:
        """Build inventory section from collector data."""
        collector_data = {}
        for cr in result.collector_results:
            if cr.data:
                collector_data[cr.collector_name] = cr.data

        if not collector_data:
            return ""

        parts = []

        # Processes
        ps = collector_data.get("process_snapshot", {})
        if ps:
            proc_count = ps.get("count", 0)
            parts.append(
                f'<div class="card"><div class="card-value">{proc_count}'
                f'</div><div class="card-label">Processes</div></div>'
            )

        # Services
        sa = collector_data.get("service_auditor", {})
        if sa:
            svc_count = sa.get("count", 0)
            parts.append(
                f'<div class="card"><div class="card-value">{svc_count}'
                f'</div><div class="card-label">Services</div></div>'
            )

        # Network
        nm = collector_data.get("network_mapper", {})
        if nm:
            conn_count = nm.get("count", 0)
            listen = nm.get("listening", 0)
            estab = nm.get("established", 0)
            parts.append(
                f'<div class="card"><div class="card-value">{conn_count}'
                f'</div><div class="card-label">Connections '
                f'({listen}L/{estab}E)</div></div>'
            )

        # Persistence
        pa = collector_data.get("persistence_auditor", {})
        if pa:
            tasks = pa.get("task_count", 0)
            keys = pa.get("run_key_count", 0)
            parts.append(
                f'<div class="card"><div class="card-value">{tasks + keys}'
                f'</div><div class="card-label">Persistence '
                f'({tasks}T/{keys}K)</div></div>'
            )

        if not parts:
            return ""

        cards = "\n".join(parts)
        return f"""<section id="inventory">
<h2>System Inventory</h2>
<div class="summary-grid">
{cards}
</div>
</section>"""

    def _section_baseline_diff(self, result: PipelineResult) -> str:
        """Build baseline diff section from analyzer data."""
        diff_data = None
        for ar in result.analyzer_results:
            if ar.analyzer_name == "baseline_differ" and ar.data:
                diff_data = ar.data
                break

        if diff_data is None:
            return ""

        if diff_data.get("first_run"):
            return """<section id="baseline">
<h2>Baseline Comparison</h2>
<p>First run &mdash; current scan saved as baseline. Changes will appear on subsequent runs.</p>
</section>"""

        total_changes = diff_data.get("total_changes", 0)
        diff_summary = diff_data.get("diff_summary", {})

        if total_changes == 0:
            return """<section id="baseline">
<h2>Baseline Comparison</h2>
<p class="pass-text">No changes detected since last baseline.</p>
</section>"""

        rows = ""
        for category, stats in diff_summary.items():
            added = stats.get("added", 0)
            removed = stats.get("removed", 0)
            rows += f"""<tr>
<td>{_esc(category.title())}</td>
<td class="added">+{added}</td>
<td class="removed">-{removed}</td>
</tr>\n"""

        return f"""<section id="baseline">
<h2>Baseline Comparison</h2>
<p>{total_changes} change(s) detected since last baseline.</p>
<div class="table-wrap">
<table>
<thead>
<tr><th>Category</th><th>Added</th><th>Removed</th></tr>
</thead>
<tbody>
{rows}</tbody>
</table>
</div>
</section>"""

    # ---- Helpers ----

    @staticmethod
    def _collect_findings(result: PipelineResult) -> List[Finding]:
        """Collect and sort all findings by severity."""
        findings: List[Finding] = []
        for sr in result.scan_results:
            findings.extend(sr.findings)
        for cr in result.collector_results:
            findings.extend(cr.findings)
        for ar in result.analyzer_results:
            findings.extend(ar.findings)
        findings.sort(key=lambda f: (
            _SEVERITY_ORDER.get(f.severity, 99),
            _DOMAIN_ORDER.get(f.domain, 99),
        ))
        return findings

    @staticmethod
    def _count_by_severity(findings: List[Finding]) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for f in findings:
            key = f.severity.value
            counts[key] = counts.get(key, 0) + 1
        return counts

    @staticmethod
    def _count_by_domain(findings: List[Finding]) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for f in findings:
            key = f.domain.value
            counts[key] = counts.get(key, 0) + 1
        return counts

    @staticmethod
    def _css() -> str:
        return """<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
       color: #1f2937; background: #f9fafb; line-height: 1.5; }
header { background: #1e293b; color: #f1f5f9; padding: 1.5rem 2rem; }
header h1 { font-size: 1.5rem; font-weight: 600; }
header .subtitle { color: #94a3b8; margin-top: 0.25rem; font-size: 0.9rem; }
main { max-width: 1200px; margin: 0 auto; padding: 1.5rem 2rem; }
footer { text-align: center; color: #9ca3af; font-size: 0.8rem; padding: 2rem; }
section { margin-bottom: 2rem; }
h2 { font-size: 1.25rem; font-weight: 600; margin-bottom: 1rem;
     padding-bottom: 0.5rem; border-bottom: 2px solid #e5e7eb; }
h3 { font-size: 1rem; font-weight: 600; margin: 1rem 0 0.5rem; }
.summary-grid, .severity-grid {
    display: flex; gap: 1rem; flex-wrap: wrap; }
.card { background: #fff; border: 1px solid #e5e7eb; border-radius: 0.5rem;
        padding: 1rem 1.25rem; min-width: 140px; }
.card-value { font-size: 1.5rem; font-weight: 700; }
.card-label { font-size: 0.8rem; color: #6b7280; margin-top: 0.25rem; }
.summary-card.pass { border-left: 4px solid #16a34a; }
.summary-card.fail { border-left: 4px solid #dc2626; }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: 0.875rem; }
th { background: #f1f5f9; text-align: left; padding: 0.6rem 0.75rem;
     font-weight: 600; border-bottom: 2px solid #e5e7eb; }
td { padding: 0.5rem 0.75rem; border-bottom: 1px solid #f1f5f9; vertical-align: top; }
tr:hover { background: #f8fafc; }
td.desc { max-width: 400px; word-break: break-word; }
.severity-badge, .domain-badge { color: #fff; padding: 0.15rem 0.5rem; border-radius: 0.25rem;
                  font-size: 0.75rem; font-weight: 600; white-space: nowrap; }
.completed, .pass-text { color: #16a34a; }
.failed { color: #dc2626; }
.skipped { color: #d97706; }
.timed_out { color: #dc2626; }
.added { color: #16a34a; font-weight: 600; }
.removed { color: #dc2626; font-weight: 600; }
.empty { color: #9ca3af; font-style: italic; }
</style>"""


# ---- Module-level helpers ----

def _esc(text: str) -> str:
    """HTML-escape text."""
    return html.escape(str(text))


def _format_dt(dt: Optional[datetime]) -> str:
    """Format a datetime for display."""
    if dt is None:
        return "N/A"
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _status_class(status: ScanStatus) -> str:
    """CSS class for a scan status."""
    return status.value
