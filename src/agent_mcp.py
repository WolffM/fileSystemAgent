import asyncio
import logging
from typing import Optional

from .agent import FileSystemAgent
from .config import ConfigManager
from .etl_mcp import MCPETLEngine
from .scheduler_mcp import MCPJobScheduler
from .mcp_server import MCPConfig, FileSystemMCPServer
from .models import ETLJob, FileSystemEvent


class MCPFileSystemAgent(FileSystemAgent):
    """FileSystem Agent with MCP support - extends base agent"""

    def __init__(self, config_path: str = "config.yaml"):
        super().__init__(config_path)

        # Check if MCP is enabled
        mcp_config = self.config_manager.get_section('mcp')
        self.use_mcp = mcp_config.get('enabled', False)

        # Initialize MCP server if enabled
        self.mcp_server: Optional[FileSystemMCPServer] = None
        if self.use_mcp:
            self._setup_mcp_server(mcp_config)

        # Replace base components with MCP variants
        etl_config = self.config_manager.get_section('etl')
        self.etl_engine = MCPETLEngine(
            max_workers=etl_config.get('max_workers', 4),
            chunk_size=etl_config.get('chunk_size', 10000),
            use_mcp=self.use_mcp
        )

        scheduler_config = self.config_manager.get_section('scheduler')
        self.scheduler = MCPJobScheduler(
            scripts_dir=self.config.scripts_dir,
            max_concurrent_jobs=scheduler_config.get('max_concurrent_jobs', 2),
            use_mcp=self.use_mcp
        )

    def _setup_mcp_server(self, mcp_config: dict):
        """Setup MCP server"""
        config = MCPConfig(
            enabled=mcp_config.get('enabled', False),
            allowed_paths=mcp_config.get('allowed_paths', []),
            max_file_size=mcp_config.get('max_file_size', 100 * 1024 * 1024),
            allowed_commands=mcp_config.get('allowed_commands', []),
            security_mode=mcp_config.get('security_mode', 'strict')
        )
        self.mcp_server = FileSystemMCPServer(config)

    async def start(self):
        """Start the FileSystem Agent with MCP support"""
        self.is_running = True
        self.logger.info(f"Starting FileSystem Agent (MCP: {'enabled' if self.use_mcp else 'disabled'})")

        try:
            # Start MCP server if enabled
            if self.use_mcp and self.mcp_server:
                asyncio.create_task(self.mcp_server.run())
                self.logger.info("Started MCP server")

            # Start components with MCP context managers
            await self._start_components()

            # Main event loop
            while self.is_running:
                await asyncio.sleep(1)

        except Exception as e:
            self.logger.error(f"Error in main loop: {e}")
        finally:
            await self.stop()

    async def _start_components(self):
        """Start all components with MCP context managers"""
        # Enter MCP context managers
        await self.etl_engine.__aenter__()
        await self.scheduler.__aenter__()

        # Start scheduler task
        scheduler_config = self.config_manager.get_section('scheduler')
        if scheduler_config.get('enabled', True):
            asyncio.create_task(self.scheduler.start())
            self.logger.info("Started job scheduler")

        # Start monitoring
        monitoring_config = self.config_manager.get_section('monitoring')
        if monitoring_config.get('enabled', True):
            asyncio.create_task(self._start_monitoring())
            self.logger.info("Started monitoring service")

    async def _stop_components(self):
        """Stop all components"""
        self.scheduler.stop()
        await self.scheduler.__aexit__(None, None, None)
        await self.etl_engine.__aexit__(None, None, None)
        self.monitoring.stop_monitoring()

    async def submit_etl_job(self, job: ETLJob) -> str:
        """Submit an ETL job for execution (async MCP variant)"""
        self.logger.info(f"Submitting ETL job: {job.name} (MCP: {self.use_mcp})")
        self.monitoring.add_job(job)
        completed_job = await self.etl_engine.execute_job(job)
        self.monitoring.update_job(completed_job)
        return job.id

    def get_mcp_events(self) -> list[FileSystemEvent]:
        """Get MCP file system events"""
        if self.mcp_server:
            return self.mcp_server.get_events()
        return []

    def get_mcp_status(self) -> dict:
        """Get MCP status information"""
        if not self.use_mcp:
            return {"enabled": False}

        return {
            "enabled": True,
            "server_running": self.mcp_server is not None,
            "events_count": len(self.get_mcp_events()),
            "security_mode": self.mcp_server.config.security_mode if self.mcp_server else "unknown"
        }
