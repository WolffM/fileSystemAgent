import os
import asyncio
import logging
import signal
from typing import Optional
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

from .config import ConfigManager
from .etl import ETLEngine
from .scheduler import JobScheduler
from .monitoring import MonitoringService
from .models import ETLJob, ScheduledJob, FileSystemEvent


class FileSystemAgent:
    def __init__(self, config_path: str = "config.yaml"):
        self.config_manager = ConfigManager(config_path)
        self.config = self.config_manager.get_config()
        
        # Setup logging
        self._setup_logging()
        
        # Create directories
        self.config_manager.create_directories()
        
        # Initialize components
        etl_config = self.config_manager.get_section('etl')
        self.etl_engine = ETLEngine(
            max_workers=etl_config.get('max_workers', 4),
            chunk_size=etl_config.get('chunk_size', 10000)
        )
        
        scheduler_config = self.config_manager.get_section('scheduler')
        self.scheduler = JobScheduler(
            scripts_dir=self.config.scripts_dir,
            max_concurrent_jobs=scheduler_config.get('max_concurrent_jobs', 2)
        )
        
        monitoring_config = self.config_manager.get_section('monitoring')
        self.monitoring = MonitoringService(
            port=monitoring_config.get('metrics_port', 8080),
            health_check_interval=monitoring_config.get('health_check_interval', 30)
        )
        
        # Security scanning (optional — initialized if security.enabled)
        self.tool_manager = None
        self.scan_pipeline = None
        security_config = self.config_manager.get_section('security')
        if security_config.get('enabled', False):
            self._init_security(security_config)
            self.monitoring.register_security_routes(
                self.tool_manager, self.scan_pipeline
            )

        # State management
        self.is_running = False
        self.executor = ThreadPoolExecutor(max_workers=10)

        # Signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        self.logger = logging.getLogger(__name__)
    
    def _setup_logging(self):
        """Setup logging configuration"""
        log_level = getattr(logging, self.config.log_level.upper())
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        
        # Create logs directory
        log_dir = Path(self.config.logs_dir)
        log_dir.mkdir(parents=True, exist_ok=True)
        
        # Configure logging
        logging.basicConfig(
            level=log_level,
            format=log_format,
            handlers=[
                logging.FileHandler(log_dir / 'agent.log'),
                logging.StreamHandler()
            ]
        )
    
    def _signal_handler(self, signum, frame):
        """Handle system signals"""
        self.logger.info(f"Received signal {signum}, shutting down...")
        self.is_running = False
    
    async def start(self):
        """Start the FileSystem Agent"""
        self.is_running = True
        self.logger.info("Starting FileSystem Agent")
        
        try:
            # Start components
            await self._start_components()
            
            # Main event loop
            while self.is_running:
                await asyncio.sleep(1)
                
        except Exception as e:
            self.logger.error(f"Error in main loop: {e}")
        finally:
            await self.stop()
    
    async def stop(self):
        """Stop the FileSystem Agent"""
        if not self.is_running:
            return
        
        self.is_running = False
        self.logger.info("Stopping FileSystem Agent")
        
        # Stop components
        await self._stop_components()
        
        # Shutdown executor
        self.executor.shutdown(wait=True)
    
    async def _start_components(self):
        """Start all components"""
        # Start scheduler
        scheduler_config = self.config_manager.get_section('scheduler')
        if scheduler_config.get('enabled', True):
            self._scheduler_task = asyncio.create_task(self.scheduler.start())
            self.logger.info("Started job scheduler")

        # Start monitoring
        monitoring_config = self.config_manager.get_section('monitoring')
        if monitoring_config.get('enabled', True):
            self._monitoring_task = asyncio.create_task(self._start_monitoring())
            self.logger.info("Started monitoring service")
    
    async def _stop_components(self):
        """Stop all components"""
        # Stop scheduler
        self.scheduler.stop()
        
        # Stop monitoring
        self.monitoring.stop_monitoring()
    
    async def _start_monitoring(self):
        """Start monitoring service in a separate thread"""
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(self.executor, self.monitoring.start_monitoring)
    
    # ETL Operations
    async def submit_etl_job(self, job: ETLJob) -> str:
        """Submit an ETL job for execution"""
        self.logger.info(f"Submitting ETL job: {job.name}")
        
        # Add to monitoring
        self.monitoring.add_job(job)
        
        # Execute job in thread pool
        loop = asyncio.get_event_loop()
        future = loop.run_in_executor(self.executor, self.etl_engine.execute_job, job)
        
        # Update monitoring when job completes
        def update_monitoring(completed_job):
            self.monitoring.update_job(completed_job.result())
        
        future.add_done_callback(update_monitoring)
        
        return job.id
    
    def get_etl_job_status(self, job_id: str) -> Optional[ETLJob]:
        """Get the status of an ETL job"""
        for job in self.monitoring.job_history:
            if job.id == job_id:
                return job
        return None
    
    def get_etl_jobs(self) -> list[ETLJob]:
        """Get all ETL jobs"""
        return self.monitoring.job_history
    
    # Scheduled Jobs
    def add_scheduled_job(self, job: ScheduledJob) -> str:
        """Add a scheduled job"""
        self.logger.info(f"Adding scheduled job: {job.name}")
        
        # Add to scheduler
        self.scheduler.add_job(job)
        
        # Add to monitoring
        self.monitoring.add_scheduled_job(job)
        
        return job.id
    
    def remove_scheduled_job(self, job_id: str) -> bool:
        """Remove a scheduled job"""
        self.logger.info(f"Removing scheduled job: {job_id}")
        
        # Remove from scheduler
        self.scheduler.remove_job(job_id)
        
        # Remove from monitoring
        self.monitoring.remove_scheduled_job(job_id)
        
        return True
    
    def enable_scheduled_job(self, job_id: str) -> bool:
        """Enable a scheduled job"""
        self.scheduler.enable_job(job_id)
        return True
    
    def disable_scheduled_job(self, job_id: str) -> bool:
        """Disable a scheduled job"""
        self.scheduler.disable_job(job_id)
        return True
    
    def get_scheduled_jobs(self) -> list[ScheduledJob]:
        """Get all scheduled jobs"""
        return self.scheduler.get_jobs()
    
    def get_scheduled_job(self, job_id: str) -> Optional[ScheduledJob]:
        """Get a specific scheduled job"""
        return self.scheduler.get_job(job_id)
    
    # File System Events
    def add_file_system_event(self, event: FileSystemEvent):
        """Add a file system event"""
        self.monitoring.add_event(event)
    
    # Configuration
    def update_config(self, updates: dict):
        """Update configuration"""
        self.config_manager.update_config(updates)
        self.config = self.config_manager.get_config()
    
    def get_config(self):
        """Get current configuration"""
        return self.config
    
    # Monitoring
    def get_system_metrics(self):
        """Get system metrics"""
        return self.monitoring.get_system_metrics()
    
    def get_job_metrics(self):
        """Get job metrics"""
        return self.monitoring.get_job_metrics()
    
    def get_alerts(self):
        """Get system alerts"""
        return self.monitoring.get_alerts()
    
    # Security Scanning
    def _init_security(self, security_config: dict):
        """Initialize the security scanning subsystem."""
        from .security.tool_manager import ToolManager
        from .security.pipeline import ScanPipeline

        self.tool_manager = ToolManager(
            tools_dir=security_config.get('tools_dir', './tools'),
            config=security_config,
        )
        self.scan_pipeline = ScanPipeline(
            tool_manager=self.tool_manager,
            config=security_config,
        )

    async def run_security_scan(self, pipeline_name: str = "daily") -> Optional[dict]:
        """Run a security scan pipeline."""
        if not self.scan_pipeline:
            self.logger.warning("Security scanning not enabled")
            return None

        from .security.pipeline import ScanPipeline

        if pipeline_name == "daily":
            config = ScanPipeline.create_daily_pipeline()
        elif pipeline_name == "forensic":
            config = ScanPipeline.create_forensic_pipeline()
        else:
            self.logger.error(f"Unknown pipeline: {pipeline_name}")
            return None

        result = await self.scan_pipeline.run_pipeline(config)
        return result.model_dump()

    def get_security_tools(self) -> Optional[dict]:
        """Get security tool availability status."""
        if not self.tool_manager:
            return None
        tools = self.tool_manager.check_all_tools()
        return {
            name: {"installed": info.installed, "path": str(info.path) if info.path else None}
            for name, info in tools.items()
        }

    def get_security_findings(self, limit: int = 50) -> Optional[list]:
        """Get recent security findings."""
        if not self.scan_pipeline:
            return None
        return [f.model_dump() for f in self.scan_pipeline.get_all_findings(limit)]

    # Health Check
    def is_healthy(self) -> bool:
        """Check if the agent is healthy"""
        return self.is_running and all([
            self.etl_engine is not None,
            self.scheduler is not None,
            self.monitoring is not None
        ])