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


# ---- Security commands ----

@cli.group()
def security():
    """Security scanning commands"""
    pass


@security.command()
@click.pass_context
def check(ctx):
    """Check which security tools are installed"""
    from .security.tool_manager import ToolManager
    from .config import ConfigManager

    config_path = ctx.obj['config']
    config_manager = ConfigManager(config_path)
    security_config = config_manager.get_section('security')

    tm = ToolManager(
        tools_dir=security_config.get('tools_dir', './tools'),
        config=security_config,
    )
    tools = tm.check_all_tools()

    click.echo("Security Tool Status")
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


@security.command()
@click.option('--force', is_flag=True, help='Re-download even if already installed')
@click.pass_context
def setup(ctx, force):
    """Download and install security tools from GitHub releases"""
    from .security.tool_manager import ToolManager
    from .config import ConfigManager

    config_path = ctx.obj['config']
    config_manager = ConfigManager(config_path)
    security_config = config_manager.get_section('security')

    tm = ToolManager(
        tools_dir=security_config.get('tools_dir', './tools'),
        config=security_config,
    )

    async def do_setup():
        click.echo("Downloading security tools...")
        results = await tm.bootstrap_all(skip_existing=not force)
        click.echo("")
        for name, success in results.items():
            info = tm.get_tool_info(name)
            if success:
                click.echo(f"  {info.display_name:<20} " + click.style("OK", fg="green"))
            else:
                method = info.install_method
                if method != "github_release":
                    click.echo(
                        f"  {info.display_name:<20} "
                        + click.style(f"manual install ({method})", fg="yellow")
                    )
                else:
                    click.echo(f"  {info.display_name:<20} " + click.style("FAILED", fg="red"))

    asyncio.run(do_setup())


@security.command()
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
    """Run a security scan pipeline"""
    from .security.tool_manager import ToolManager
    from .security.pipeline import ScanPipeline
    from .config import ConfigManager

    config_path = ctx.obj['config']
    config_manager = ConfigManager(config_path)
    security_config = config_manager.get_section('security')

    tm = ToolManager(
        tools_dir=security_config.get('tools_dir', './tools'),
        config=security_config,
    )
    sp = ScanPipeline(tool_manager=tm, config=security_config)

    output_dir = security_config.get('output_dir', './data/security/scans')

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


@security.command()
@click.option('--limit', '-n', default=20, help='Number of findings to show')
@click.option('--severity', '-s', default=None, help='Filter by severity level')
@click.pass_context
def findings(ctx, limit, severity):
    """Show recent security findings"""
    from .security.tool_manager import ToolManager
    from .security.pipeline import ScanPipeline
    from .config import ConfigManager

    config_path = ctx.obj['config']
    config_manager = ConfigManager(config_path)
    security_config = config_manager.get_section('security')

    tm = ToolManager(
        tools_dir=security_config.get('tools_dir', './tools'),
        config=security_config,
    )
    sp = ScanPipeline(tool_manager=tm, config=security_config)

    all_findings = sp.get_all_findings(limit=limit * 2)
    if severity:
        all_findings = [f for f in all_findings if f.severity.value == severity.lower()]
    all_findings = all_findings[:limit]

    if not all_findings:
        click.echo("No findings. Run 'python main.py security scan' first.")
        return

    click.echo(f"Security Findings ({len(all_findings)})")
    click.echo("=" * 70)
    for f in all_findings:
        sev_colors = {
            "critical": "red",
            "high": "red",
            "medium": "yellow",
            "low": "blue",
            "info": "white",
        }
        sev = click.style(
            f.severity.value.upper().ljust(8),
            fg=sev_colors.get(f.severity.value, "white"),
        )
        click.echo(f"  [{sev}] {f.title}")
        click.echo(f"           {f.description[:80]}")
        click.echo("")


if __name__ == '__main__':
    cli()
