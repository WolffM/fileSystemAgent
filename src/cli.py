import click
import json
import uuid
import asyncio
from datetime import datetime
from pathlib import Path
from typing import Optional

from .agent import FileSystemAgent
from .agent_mcp import MCPFileSystemAgent
from .models import ETLJob, ScheduledJob, ETLOperationType, ScheduleType


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
        # Determine which agent to use
        if use_mcp is True:
            agent = MCPFileSystemAgent(config_path)
        elif use_mcp is False:
            agent = FileSystemAgent(config_path)
        else:
            # Check config file for MCP setting
            from .config import ConfigManager
            config_manager = ConfigManager(config_path)
            mcp_config = config_manager.get_section('mcp')
            if mcp_config.get('enabled', False):
                agent = MCPFileSystemAgent(config_path)
            else:
                agent = FileSystemAgent(config_path)
        
        await agent.start()
    
    asyncio.run(run_agent())


@cli.command()
@click.pass_context
def stop(ctx):
    """Stop the FileSystem Agent"""
    click.echo("Stopping FileSystem Agent...")
    # Implementation would depend on how the agent is running


@cli.group()
def etl():
    """ETL operations"""
    pass


@etl.command()
@click.option('--name', '-n', required=True, help='Job name')
@click.option('--type', '-t', 'operation_type', 
              type=click.Choice(['extract', 'transform', 'load', 'full_etl']),
              default='full_etl', help='ETL operation type')
@click.option('--source', '-s', required=True, help='Source file path')
@click.option('--destination', '-d', help='Destination file path')
@click.option('--transform-script', help='Transform script path')
@click.option('--params', '-p', help='JSON parameters')
@click.pass_context
def run(ctx, name, operation_type, source, destination, transform_script, params):
    """Run an ETL job"""
    job_id = str(uuid.uuid4())
    
    # Parse parameters
    parameters = {}
    if params:
        try:
            parameters = json.loads(params)
        except json.JSONDecodeError:
            click.echo("Error: Invalid JSON in parameters")
            return
    
    # Create ETL job
    job = ETLJob(
        id=job_id,
        name=name,
        operation_type=ETLOperationType(operation_type),
        source_path=source,
        destination_path=destination,
        transform_script=transform_script,
        parameters=parameters
    )
    
    click.echo(f"Running ETL job: {name}")
    click.echo(f"Job ID: {job_id}")
    
    # This would need to be integrated with the agent
    # For now, just show the job configuration
    click.echo(f"Job configuration: {job.dict()}")


@etl.command()
def list():
    """List ETL jobs"""
    click.echo("Listing ETL jobs...")
    # Implementation would query the agent for job status


@etl.command()
@click.argument('job_id')
def status(job_id):
    """Get ETL job status"""
    click.echo(f"Getting status for job: {job_id}")
    # Implementation would query the agent for specific job status


@cli.group()
def schedule():
    """Scheduled jobs management"""
    pass


@schedule.command()
@click.option('--name', '-n', required=True, help='Job name')
@click.option('--script', '-s', required=True, help='Script path')
@click.option('--type', '-t', 'schedule_type',
              type=click.Choice(['cron', 'interval', 'once']),
              default='cron', help='Schedule type')
@click.option('--expression', '-e', required=True, help='Schedule expression')
@click.option('--params', '-p', help='JSON parameters')
@click.option('--enabled/--disabled', default=True, help='Enable/disable job')
def add(name, script, schedule_type, expression, params, enabled):
    """Add a scheduled job"""
    job_id = str(uuid.uuid4())
    
    # Parse parameters
    parameters = {}
    if params:
        try:
            parameters = json.loads(params)
        except json.JSONDecodeError:
            click.echo("Error: Invalid JSON in parameters")
            return
    
    # Create scheduled job
    job = ScheduledJob(
        id=job_id,
        name=name,
        script_path=script,
        schedule_type=ScheduleType(schedule_type),
        schedule_expression=expression,
        enabled=enabled,
        parameters=parameters
    )
    
    click.echo(f"Added scheduled job: {name}")
    click.echo(f"Job ID: {job_id}")
    click.echo(f"Schedule: {schedule_type} - {expression}")


@schedule.command()
def list():
    """List scheduled jobs"""
    click.echo("Listing scheduled jobs...")
    # Implementation would query the agent for scheduled jobs


@schedule.command()
@click.argument('job_id')
def enable(job_id):
    """Enable a scheduled job"""
    click.echo(f"Enabling job: {job_id}")
    # Implementation would enable the job in the agent


@schedule.command()
@click.argument('job_id')
def disable(job_id):
    """Disable a scheduled job"""
    click.echo(f"Disabling job: {job_id}")
    # Implementation would disable the job in the agent


@schedule.command()
@click.argument('job_id')
def remove(job_id):
    """Remove a scheduled job"""
    click.echo(f"Removing job: {job_id}")
    # Implementation would remove the job from the agent


@cli.group()
def monitor():
    """Monitoring commands"""
    pass


@monitor.command()
@click.pass_context
def status(ctx):
    """Show agent status"""
    click.echo("Agent Status:")
    click.echo("=============")
    # Implementation would query the monitoring service
    click.echo("Status: Running")
    click.echo("Uptime: 1h 30m")
    click.echo("CPU: 25%")
    click.echo("Memory: 512MB")
    
    # Show MCP status if enabled
    use_mcp = ctx.obj.get('mcp')
    if use_mcp is True:
        click.echo("\nMCP Status:")
        click.echo("MCP: Enabled (CLI override)")
    elif use_mcp is False:
        click.echo("\nMCP Status:")
        click.echo("MCP: Disabled (CLI override)")
    else:
        from .config import ConfigManager
        config_manager = ConfigManager(ctx.obj['config'])
        mcp_config = config_manager.get_section('mcp')
        if mcp_config.get('enabled', False):
            click.echo("\nMCP Status:")
            click.echo("MCP: Enabled (config)")
        else:
            click.echo("\nMCP Status:")
            click.echo("MCP: Disabled (config)")


@monitor.command()
def metrics():
    """Show system metrics"""
    click.echo("System Metrics:")
    click.echo("===============")
    # Implementation would query the monitoring service
    click.echo("CPU Usage: 25%")
    click.echo("Memory Usage: 60%")
    click.echo("Disk Usage: 45%")


@monitor.command()
def alerts():
    """Show active alerts"""
    click.echo("Active Alerts:")
    click.echo("==============")
    # Implementation would query the monitoring service
    click.echo("No active alerts")


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


@config.command()
@click.option('--key', '-k', required=True, help='Configuration key')
@click.option('--value', '-v', required=True, help='Configuration value')
@click.pass_context
def set(ctx, key, value):
    """Set a configuration value"""
    click.echo(f"Setting {key} = {value}")
    # Implementation would update the configuration


@config.command()
@click.option('--key', '-k', required=True, help='Configuration key')
@click.pass_context
def get(ctx, key):
    """Get a configuration value"""
    click.echo(f"Getting value for: {key}")
    # Implementation would retrieve the configuration value


@cli.command()
@click.option('--output', '-o', help='Output file path')
def export_config(output):
    """Export current configuration"""
    if not output:
        output = f"config_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.yaml"
    
    click.echo(f"Exporting configuration to: {output}")
    # Implementation would export the configuration


@cli.command()
@click.argument('config_file')
def import_config(config_file):
    """Import configuration from file"""
    click.echo(f"Importing configuration from: {config_file}")
    # Implementation would import the configuration


if __name__ == '__main__':
    cli()