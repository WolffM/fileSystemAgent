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


if __name__ == '__main__':
    cli()
