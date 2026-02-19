import click
import asyncio
from pathlib import Path

from .agent import FileSystemAgent


@click.group()
@click.option('--config', '-c', default='config.yaml', help='Configuration file path')
@click.option('--mcp/--no-mcp', default=None, help='Enable/disable MCP mode')
@click.pass_context
def cli(ctx, config, mcp):
    """FileSystem Agent CLI"""
    ctx.ensure_object(dict)
    ctx.obj['config'] = config
    ctx.obj['mcp'] = mcp


@cli.command()
@click.pass_context
def start(ctx):
    """Start the FileSystem Agent"""
    config_path = ctx.obj['config']
    use_mcp = ctx.obj.get('mcp')

    async def run_agent():
        if use_mcp is True:
            from .agent_mcp import MCPFileSystemAgent
            agent = MCPFileSystemAgent(config_path)
        elif use_mcp is False:
            agent = FileSystemAgent(config_path)
        else:
            from .config import ConfigManager
            config_manager = ConfigManager(config_path)
            mcp_config = config_manager.get_section('mcp')
            if mcp_config.get('enabled', False):
                from .agent_mcp import MCPFileSystemAgent
                agent = MCPFileSystemAgent(config_path)
            else:
                agent = FileSystemAgent(config_path)

        await agent.start()

    asyncio.run(run_agent())


@cli.group()
def config():
    """Configuration management"""
    pass


@config.command()
@click.pass_context
def show(ctx):
    """Show current configuration"""
    config_path = ctx.obj['config']

    if not Path(config_path).exists():
        click.echo(f"Configuration file not found: {config_path}")
        return

    with open(config_path, 'r') as f:
        content = f.read()

    click.echo(f"Configuration ({config_path}):")
    click.echo("=" * 40)
    click.echo(content)


# ---- Audit commands ----

@cli.group()
def audit():
    """System audit commands"""
    pass


@audit.command()
@click.pass_context
def check(ctx):
    """Check which audit tools are installed"""
    from .audit.tool_manager import ToolManager
    from .config import ConfigManager

    config_path = ctx.obj['config']
    config_manager = ConfigManager(config_path)
    audit_config = config_manager.get_section('audit')

    tm = ToolManager(
        tools_dir=audit_config.get('tools_dir', './tools'),
        config=audit_config,
    )
    tools = tm.check_all_tools()

    click.echo("Audit Tool Status")
    click.echo("=" * 60)

    installed_count = 0
    for name, info in sorted(tools.items()):
        status = click.style("INSTALLED", fg="green") if info.installed else click.style("MISSING", fg="red")
        path_str = f" ({info.path})" if info.installed and info.path else ""
        admin = " [admin]" if info.requires_admin else ""
        click.echo(f"  {info.display_name:<20} {status}{path_str}{admin}")
        if info.installed:
            installed_count += 1

    click.echo("=" * 60)
    click.echo(f"  {installed_count}/{len(tools)} tools installed")


@audit.command()
@click.option('--force', is_flag=True, help='Re-download even if already installed')
@click.pass_context
def setup(ctx, force):
    """Download and install audit tools from GitHub releases"""
    from .audit.tool_manager import ToolManager
    from .config import ConfigManager

    config_path = ctx.obj['config']
    config_manager = ConfigManager(config_path)
    audit_config = config_manager.get_section('audit')

    tm = ToolManager(
        tools_dir=audit_config.get('tools_dir', './tools'),
        config=audit_config,
    )

    async def do_setup():
        click.echo("Downloading audit tools...")
        results = await tm.bootstrap_all(skip_existing=not force)
        click.echo("")
        for name, success in results.items():
            info = tm.get_tool_info(name)
            if success:
                click.echo(f"  {info.display_name:<20} " + click.style("OK", fg="green"))
            else:
                click.echo(f"  {info.display_name:<20} " + click.style("FAILED", fg="red"))

    asyncio.run(do_setup())


@audit.command()
@click.option(
    '--pipeline', '-p',
    type=click.Choice(['daily', 'forensic']),
    default='daily',
    help='Pipeline to run',
)
@click.option('--target', '-t', default=None, help='Scan target path')
@click.option('--dry-run', is_flag=True, help='Show commands without executing')
@click.pass_context
def scan(ctx, pipeline, target, dry_run):
    """Run an audit scan pipeline"""
    from .audit.tool_manager import ToolManager
    from .audit.pipeline import ScanPipeline
    from .config import ConfigManager

    config_path = ctx.obj['config']
    config_manager = ConfigManager(config_path)
    audit_config = config_manager.get_section('audit')

    tm = ToolManager(
        tools_dir=audit_config.get('tools_dir', './tools'),
        config=audit_config,
    )
    sp = ScanPipeline(tool_manager=tm, config=audit_config)

    output_dir = audit_config.get('output_dir', './data/audit/scans')

    if pipeline == 'daily':
        config = ScanPipeline.create_daily_pipeline(
            scan_target=target or "C:\\Users",
            output_dir=output_dir,
        )
    else:
        config = ScanPipeline.create_forensic_pipeline(
            evtx_path=target or "C:\\Windows\\System32\\winevt\\Logs",
            output_dir=output_dir,
        )

    if dry_run:
        for step in config.steps:
            step.dry_run = True

    async def do_scan():
        result = await sp.run_pipeline(config)
        click.echo("")
        click.echo(f"Pipeline: {result.pipeline_name}")
        click.echo(f"Status:   {result.status.value}")
        if result.duration_seconds is not None:
            click.echo(f"Duration: {result.duration_seconds:.1f}s")
        click.echo("")

        for sr in result.scan_results:
            status_color = {
                "completed": "green",
                "failed": "red",
                "skipped": "yellow",
                "timed_out": "red",
            }.get(sr.status.value, "white")
            status_str = click.style(sr.status.value, fg=status_color)
            click.echo(
                f"  {sr.tool_name:<20} {status_str}  "
                f"{sr.findings_count} findings"
            )

        click.echo("")
        click.echo(
            f"Total findings: {result.total_findings} "
            f"({result.critical_findings} critical, {result.high_findings} high)"
        )

    asyncio.run(do_scan())


@audit.command()
@click.option('--limit', '-n', default=20, help='Number of findings to show')
@click.option('--severity', '-s', default=None, help='Filter by severity level')
@click.option('--domain', '-d', default=None, help='Filter by domain (security, performance, hygiene)')
@click.pass_context
def findings(ctx, limit, severity, domain):
    """Show recent findings (security, performance, hygiene)"""
    from .audit.tool_manager import ToolManager
    from .audit.pipeline import ScanPipeline
    from .config import ConfigManager

    config_path = ctx.obj['config']
    config_manager = ConfigManager(config_path)
    audit_config = config_manager.get_section('audit')

    tm = ToolManager(
        tools_dir=audit_config.get('tools_dir', './tools'),
        config=audit_config,
    )
    sp = ScanPipeline(tool_manager=tm, config=audit_config)

    all_findings = sp.get_all_findings(limit=limit * 2)
    if severity:
        all_findings = [f for f in all_findings if f.severity.value == severity.lower()]
    if domain:
        all_findings = [f for f in all_findings if f.domain.value == domain.lower()]
    all_findings = all_findings[:limit]

    if not all_findings:
        click.echo("No findings. Run 'python main.py audit scan' first.")
        return

    click.echo(f"Findings ({len(all_findings)})")
    click.echo("=" * 70)
    for f in all_findings:
        sev_colors = {
            "critical": "red",
            "high": "red",
            "medium": "yellow",
            "low": "blue",
            "info": "white",
        }
        dom_colors = {
            "security": "blue",
            "performance": "yellow",
            "hygiene": "white",
        }
        sev = click.style(
            f.severity.value.upper().ljust(8),
            fg=sev_colors.get(f.severity.value, "white"),
        )
        dom = click.style(
            f.domain.value.upper()[:4].ljust(4),
            fg=dom_colors.get(f.domain.value, "white"),
        )
        click.echo(f"  [{sev}] [{dom}] {f.title}")
        click.echo(f"                  {f.description}")
        if f.target:
            click.echo(f"                  Target: {f.target}")
        click.echo("")


@audit.command(name="process-scan")
@click.option('--report', '-r', default=None, help='Output HTML report to this path')
@click.option('--dry-run', is_flag=True, help='Show pipeline steps without executing')
@click.pass_context
def process_scan(ctx, report, dry_run):
    """Run the process scanning pipeline (collectors + analyzers + report)"""
    from .audit.tool_manager import ToolManager
    from .audit.pipeline import ScanPipeline
    from .audit.reporting.html_report import HtmlReportGenerator
    from .config import ConfigManager

    config_path = ctx.obj['config']
    config_manager = ConfigManager(config_path)
    audit_config = config_manager.get_section('audit')

    tm = ToolManager(
        tools_dir=audit_config.get('tools_dir', './tools'),
        config=audit_config,
    )
    sp = ScanPipeline(tool_manager=tm, config=audit_config)

    output_dir = audit_config.get('output_dir', './data/audit/scans')
    baseline_dir = audit_config.get('baseline_dir', './data/audit/baselines')

    pipeline_config = ScanPipeline.create_process_scan_pipeline(
        output_dir=output_dir,
        baseline_dir=baseline_dir,
    )

    if dry_run:
        click.echo(f"Pipeline: {pipeline_config.name}")
        click.echo(f"Description: {pipeline_config.description}")
        click.echo("")
        click.echo("Collectors:")
        for c in pipeline_config.collectors:
            click.echo(f"  - {c.collector_name}")
        click.echo("Scanners:")
        for s in pipeline_config.steps:
            click.echo(f"  - {s.tool_name}")
        click.echo("Analyzers:")
        for a in pipeline_config.analyzers:
            click.echo(f"  - {a.analyzer_name}")
        return

    async def do_scan():
        click.echo(f"Running pipeline: {pipeline_config.name}")
        click.echo(f"  {len(pipeline_config.collectors)} collectors, "
                    f"{len(pipeline_config.steps)} scanners, "
                    f"{len(pipeline_config.analyzers)} analyzers")
        click.echo("")

        result = await sp.run_pipeline(pipeline_config)

        # Print step results
        for cr in result.collector_results:
            _print_step_result("Collector", cr.collector_name, cr.status, cr.findings_count)
        for sr in result.scan_results:
            _print_step_result("Scanner", sr.tool_name, sr.status, sr.findings_count)
        for ar in result.analyzer_results:
            _print_step_result("Analyzer", ar.analyzer_name, ar.status, ar.findings_count)

        click.echo("")
        click.echo(f"Status:   {result.status.value}")
        if result.duration_seconds is not None:
            click.echo(f"Duration: {result.duration_seconds:.1f}s")
        click.echo(
            f"Findings: {result.total_findings} "
            f"({result.critical_findings} critical, {result.high_findings} high)"
        )

        # Generate HTML report
        report_path = report
        if report_path is None:
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_path = f"{output_dir}/report_{timestamp}.html"

        generator = HtmlReportGenerator()
        generator.generate(result, output_path=report_path)
        click.echo("")
        click.echo(click.style(f"HTML report: {report_path}", fg="green"))

    asyncio.run(do_scan())


def _print_step_result(step_type, name, status, findings_count):
    """Print a single pipeline step result line."""
    status_color = {
        "completed": "green",
        "failed": "red",
        "skipped": "yellow",
        "timed_out": "red",
    }.get(status.value, "white")
    status_str = click.style(status.value, fg=status_color)
    click.echo(f"  [{step_type[0]}] {name:<25} {status_str}  {findings_count} findings")


@audit.group()
def baseline():
    """Manage audit baselines"""
    pass


@baseline.command()
@click.option(
    '--baseline-dir', '-d',
    default='./data/audit/baselines',
    help='Directory for baseline files',
)
@click.pass_context
def save(ctx, baseline_dir):
    """Save current system state as a baseline (runs collectors)"""
    from .audit.tool_manager import ToolManager
    from .audit.pipeline import ScanPipeline
    from .audit.models import CollectorConfig
    from .config import ConfigManager

    config_path = ctx.obj['config']
    config_manager = ConfigManager(config_path)
    audit_config = config_manager.get_section('audit')

    tm = ToolManager(
        tools_dir=audit_config.get('tools_dir', './tools'),
        config=audit_config,
    )
    sp = ScanPipeline(tool_manager=tm, config=audit_config)

    async def do_save():
        from .audit.models import PipelineConfig
        # Run collectors to gather current system state
        pipeline_config = PipelineConfig(
            name="baseline_capture",
            collectors=[
                CollectorConfig(collector_name="process_snapshot"),
                CollectorConfig(collector_name="service_auditor"),
                CollectorConfig(collector_name="network_mapper"),
                CollectorConfig(collector_name="persistence_auditor"),
            ],
        )

        click.echo("Running collectors to capture system state...")
        result = await sp.run_pipeline(pipeline_config)

        # Build context from collector results
        context = {}
        for cr in result.collector_results:
            if cr.data:
                context[cr.collector_name] = cr.data

        if not context:
            click.echo(click.style("No data collected. Cannot save baseline.", fg="red"))
            return

        from .audit.analyzers.baseline_differ import BaselineDiffer
        filepath = BaselineDiffer.save_baseline_from_context(context, baseline_dir)
        if filepath:
            click.echo(click.style(f"Baseline saved to {filepath}", fg="green"))
            click.echo(f"Collectors captured: {', '.join(context.keys())}")
        else:
            click.echo(click.style("Failed to save baseline.", fg="red"))

    asyncio.run(do_save())


@baseline.command()
@click.option(
    '--baseline-dir', '-d',
    default='./data/audit/baselines',
    help='Directory for baseline files',
)
def show(baseline_dir):
    """Show info about the current baseline"""
    from .audit.analyzers.baseline_differ import BaselineDiffer

    info = BaselineDiffer.get_baseline_info(baseline_dir)
    if not info:
        click.echo("No baseline found.")
        click.echo("Run 'python main.py audit baseline save' to create one.")
        return

    click.echo("Current Baseline")
    click.echo("=" * 50)
    click.echo(f"  Path:       {info['path']}")
    click.echo(f"  Modified:   {info['modified']}")
    click.echo(f"  Collectors: {', '.join(info['collectors'])}")
    click.echo(f"  Files:      {info['file_count']} baseline(s) on disk")


@baseline.command()
@click.option(
    '--baseline-dir', '-d',
    default='./data/audit/baselines',
    help='Directory for baseline files',
)
@click.option('--yes', '-y', is_flag=True, help='Skip confirmation')
def clear(baseline_dir, yes):
    """Remove all baseline files"""
    from .audit.analyzers.baseline_differ import BaselineDiffer

    info = BaselineDiffer.get_baseline_info(baseline_dir)
    if not info:
        click.echo("No baselines to clear.")
        return

    count = info['file_count']
    if not yes:
        click.confirm(
            f"Delete {count} baseline file(s) from {baseline_dir}?",
            abort=True,
        )

    removed = BaselineDiffer.clear_baselines(baseline_dir)
    click.echo(click.style(f"Removed {removed} baseline file(s).", fg="green"))


if __name__ == '__main__':
    cli()
