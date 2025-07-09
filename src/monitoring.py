import logging
import psutil
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
import uvicorn
from pydantic import BaseModel

from .models import ETLJob, ScheduledJob, FileSystemEvent


class SystemMetrics(BaseModel):
    timestamp: datetime
    cpu_percent: float
    memory_percent: float
    disk_usage: Dict[str, float]
    network_io: Dict[str, int]


class JobMetrics(BaseModel):
    total_jobs: int
    running_jobs: int
    completed_jobs: int
    failed_jobs: int
    average_duration: float


class MonitoringService:
    def __init__(self, port: int = 8080, health_check_interval: int = 30):
        self.port = port
        self.health_check_interval = health_check_interval
        self.logger = logging.getLogger(__name__)
        self.app = FastAPI(title="FileSystem Agent Monitoring")
        self.metrics_history: List[SystemMetrics] = []
        self.job_history: List[ETLJob] = []
        self.scheduled_jobs: Dict[str, ScheduledJob] = {}
        self.events: List[FileSystemEvent] = []
        self.is_running = False
        
        self._setup_routes()
    
    def _setup_routes(self):
        """Setup FastAPI routes"""
        
        @self.app.get("/health")
        async def health_check():
            return {"status": "healthy", "timestamp": datetime.now()}
        
        @self.app.get("/metrics")
        async def get_metrics():
            return {
                "system": self.get_system_metrics(),
                "jobs": self.get_job_metrics(),
                "history": self.metrics_history[-100:]  # Last 100 metrics
            }
        
        @self.app.get("/jobs")
        async def get_jobs():
            return {
                "etl_jobs": [job.dict() for job in self.job_history[-50:]],
                "scheduled_jobs": [job.dict() for job in self.scheduled_jobs.values()]
            }
        
        @self.app.get("/events")
        async def get_events():
            return [event.dict() for event in self.events[-100:]]
        
        @self.app.get("/status")
        async def get_status():
            return {
                "agent_status": "running" if self.is_running else "stopped",
                "system_metrics": self.get_system_metrics(),
                "job_metrics": self.get_job_metrics(),
                "uptime": time.time() - self.start_time if hasattr(self, 'start_time') else 0
            }
    
    def get_system_metrics(self) -> SystemMetrics:
        """Get current system metrics"""
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk_usage = {}
        network_io = psutil.net_io_counters()._asdict()
        
        # Get disk usage for all mounted drives
        for disk in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(disk.mountpoint)
                disk_usage[disk.mountpoint] = {
                    'total': usage.total,
                    'used': usage.used,
                    'free': usage.free,
                    'percent': (usage.used / usage.total) * 100
                }
            except PermissionError:
                continue
        
        return SystemMetrics(
            timestamp=datetime.now(),
            cpu_percent=cpu_percent,
            memory_percent=memory.percent,
            disk_usage=disk_usage,
            network_io=network_io
        )
    
    def get_job_metrics(self) -> JobMetrics:
        """Get job metrics"""
        total_jobs = len(self.job_history)
        running_jobs = len([job for job in self.job_history if job.status == "running"])
        completed_jobs = len([job for job in self.job_history if job.status == "completed"])
        failed_jobs = len([job for job in self.job_history if job.status == "failed"])
        
        # Calculate average duration for completed jobs
        completed_job_durations = []
        for job in self.job_history:
            if job.status == "completed" and job.started_at and job.completed_at:
                duration = (job.completed_at - job.started_at).total_seconds()
                completed_job_durations.append(duration)
        
        average_duration = sum(completed_job_durations) / len(completed_job_durations) if completed_job_durations else 0
        
        return JobMetrics(
            total_jobs=total_jobs,
            running_jobs=running_jobs,
            completed_jobs=completed_jobs,
            failed_jobs=failed_jobs,
            average_duration=average_duration
        )
    
    def add_job(self, job: ETLJob):
        """Add a job to monitoring"""
        self.job_history.append(job)
        self.logger.info(f"Added job to monitoring: {job.id}")
    
    def update_job(self, job: ETLJob):
        """Update job status in monitoring"""
        for i, existing_job in enumerate(self.job_history):
            if existing_job.id == job.id:
                self.job_history[i] = job
                break
    
    def add_scheduled_job(self, job: ScheduledJob):
        """Add a scheduled job to monitoring"""
        self.scheduled_jobs[job.id] = job
    
    def remove_scheduled_job(self, job_id: str):
        """Remove a scheduled job from monitoring"""
        if job_id in self.scheduled_jobs:
            del self.scheduled_jobs[job_id]
    
    def add_event(self, event: FileSystemEvent):
        """Add a file system event"""
        self.events.append(event)
        # Keep only last 1000 events
        if len(self.events) > 1000:
            self.events = self.events[-1000:]
    
    def start_monitoring(self):
        """Start the monitoring service"""
        self.is_running = True
        self.start_time = time.time()
        self.logger.info(f"Starting monitoring service on port {self.port}")
        
        # Start collecting metrics
        self._start_metrics_collection()
        
        # Start the FastAPI server
        uvicorn.run(
            self.app,
            host="0.0.0.0",
            port=self.port,
            log_level="info"
        )
    
    def stop_monitoring(self):
        """Stop the monitoring service"""
        self.is_running = False
        self.logger.info("Stopping monitoring service")
    
    def _start_metrics_collection(self):
        """Start collecting system metrics"""
        import threading
        
        def collect_metrics():
            while self.is_running:
                try:
                    metrics = self.get_system_metrics()
                    self.metrics_history.append(metrics)
                    
                    # Keep only last 1000 metrics
                    if len(self.metrics_history) > 1000:
                        self.metrics_history = self.metrics_history[-1000:]
                    
                    time.sleep(self.health_check_interval)
                except Exception as e:
                    self.logger.error(f"Error collecting metrics: {e}")
                    time.sleep(self.health_check_interval)
        
        metrics_thread = threading.Thread(target=collect_metrics, daemon=True)
        metrics_thread.start()
    
    def get_alerts(self) -> List[Dict]:
        """Get system alerts based on thresholds"""
        alerts = []
        current_metrics = self.get_system_metrics()
        
        # CPU alert
        if current_metrics.cpu_percent > 80:
            alerts.append({
                "type": "cpu_high",
                "message": f"High CPU usage: {current_metrics.cpu_percent}%",
                "severity": "warning" if current_metrics.cpu_percent < 90 else "critical"
            })
        
        # Memory alert
        if current_metrics.memory_percent > 80:
            alerts.append({
                "type": "memory_high",
                "message": f"High memory usage: {current_metrics.memory_percent}%",
                "severity": "warning" if current_metrics.memory_percent < 90 else "critical"
            })
        
        # Disk usage alerts
        for mountpoint, usage in current_metrics.disk_usage.items():
            if usage['percent'] > 80:
                alerts.append({
                    "type": "disk_high",
                    "message": f"High disk usage on {mountpoint}: {usage['percent']:.1f}%",
                    "severity": "warning" if usage['percent'] < 90 else "critical"
                })
        
        # Job failure alerts
        job_metrics = self.get_job_metrics()
        if job_metrics.failed_jobs > 0:
            recent_failures = [
                job for job in self.job_history[-10:]
                if job.status == "failed"
            ]
            if recent_failures:
                alerts.append({
                    "type": "job_failures",
                    "message": f"{len(recent_failures)} recent job failures",
                    "severity": "warning"
                })
        
        return alerts