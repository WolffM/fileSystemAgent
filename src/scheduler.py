import os
import json
import asyncio
import logging
import subprocess
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from pathlib import Path
from croniter import croniter

from .models import ScheduledJob, ScheduleType, JobStatus


class JobScheduler:
    def __init__(self, scripts_dir: str, max_concurrent_jobs: int = 2):
        self.scripts_dir = Path(scripts_dir)
        self.max_concurrent_jobs = max_concurrent_jobs
        self.logger = logging.getLogger(__name__)
        self.running_jobs: Dict[str, subprocess.Popen] = {}
        self.scheduled_jobs: Dict[str, ScheduledJob] = {}
        self.is_running = False
        
    def add_job(self, job: ScheduledJob):
        """Add a scheduled job"""
        self.scheduled_jobs[job.id] = job
        self._schedule_job(job)
        self.logger.info(f"Added scheduled job: {job.name}")
    
    def remove_job(self, job_id: str):
        """Remove a scheduled job"""
        if job_id in self.scheduled_jobs:
            del self.scheduled_jobs[job_id]
            self.logger.info(f"Removed scheduled job: {job_id}")
    
    def enable_job(self, job_id: str):
        """Enable a scheduled job"""
        if job_id in self.scheduled_jobs:
            self.scheduled_jobs[job_id].enabled = True
            self._schedule_job(self.scheduled_jobs[job_id])
    
    def disable_job(self, job_id: str):
        """Disable a scheduled job"""
        if job_id in self.scheduled_jobs:
            self.scheduled_jobs[job_id].enabled = False
    
    def get_jobs(self) -> List[ScheduledJob]:
        """Get all scheduled jobs"""
        return list(self.scheduled_jobs.values())
    
    def get_job(self, job_id: str) -> Optional[ScheduledJob]:
        """Get a specific scheduled job"""
        return self.scheduled_jobs.get(job_id)
    
    def _schedule_job(self, job: ScheduledJob):
        """Schedule a job based on its type"""
        if not job.enabled:
            return
        
        if job.schedule_type == ScheduleType.CRON:
            self._schedule_cron_job(job)
        elif job.schedule_type == ScheduleType.INTERVAL:
            self._schedule_interval_job(job)
        elif job.schedule_type == ScheduleType.ONCE:
            self._schedule_once_job(job)
    
    def _schedule_cron_job(self, job: ScheduledJob):
        """Schedule a cron-based job"""
        try:
            cron = croniter(job.schedule_expression, datetime.now())
            job.next_run = cron.get_next(datetime)
        except Exception as e:
            self.logger.error(f"Invalid cron expression for job {job.id}: {e}")
    
    def _schedule_interval_job(self, job: ScheduledJob):
        """Schedule an interval-based job"""
        try:
            interval_seconds = int(job.schedule_expression)
            job.next_run = datetime.now() + timedelta(seconds=interval_seconds)
        except ValueError:
            self.logger.error(f"Invalid interval expression for job {job.id}")
    
    def _schedule_once_job(self, job: ScheduledJob):
        """Schedule a one-time job"""
        try:
            job.next_run = datetime.fromisoformat(job.schedule_expression)
        except ValueError:
            self.logger.error(f"Invalid datetime expression for job {job.id}")
    
    async def start(self):
        """Start the scheduler"""
        self.is_running = True
        self.logger.info("Starting job scheduler")
        
        while self.is_running:
            await self._check_and_run_jobs()
            await asyncio.sleep(1)
    
    def stop(self):
        """Stop the scheduler"""
        self.is_running = False
        self.logger.info("Stopping job scheduler")
        
        # Stop all running jobs
        for job_id, process in self.running_jobs.items():
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                self.logger.info(f"Terminated job: {job_id}")
    
    async def _check_and_run_jobs(self):
        """Check for jobs that need to run and execute them"""
        current_time = datetime.now()
        
        # Clean up completed jobs
        completed_jobs = [
            job_id for job_id, process in self.running_jobs.items()
            if process.poll() is not None
        ]
        
        for job_id in completed_jobs:
            del self.running_jobs[job_id]
        
        # Check if we can run more jobs
        if len(self.running_jobs) >= self.max_concurrent_jobs:
            return
        
        # Find jobs that need to run
        for job in self.scheduled_jobs.values():
            if not job.enabled or job.next_run is None:
                continue
                
            if current_time >= job.next_run and job.id not in self.running_jobs:
                await self._execute_job(job)
                
                # Schedule next run
                self._schedule_next_run(job)
    
    async def _execute_job(self, job: ScheduledJob):
        """Execute a scheduled job"""
        script_path = self.scripts_dir / job.script_path
        
        if not script_path.exists():
            self.logger.error(f"Script not found: {script_path}")
            return
        
        try:
            # Prepare environment variables
            env = {
                **dict(os.environ),
                'JOB_ID': job.id,
                'JOB_NAME': job.name,
                'JOB_PARAMS': json.dumps(job.parameters)
            }
            
            # Execute the script
            process = subprocess.Popen(
                ['python', str(script_path)],
                cwd=str(self.scripts_dir),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            self.running_jobs[job.id] = process
            job.last_run = datetime.now()
            
            self.logger.info(f"Started job: {job.name} (PID: {process.pid})")
            
        except Exception as e:
            self.logger.error(f"Failed to execute job {job.id}: {e}")
    
    def _schedule_next_run(self, job: ScheduledJob):
        """Schedule the next run for a job"""
        if job.schedule_type == ScheduleType.CRON:
            try:
                cron = croniter(job.schedule_expression, job.last_run)
                job.next_run = cron.get_next(datetime)
            except Exception as e:
                self.logger.error(f"Error scheduling next run for job {job.id}: {e}")
                job.enabled = False
                
        elif job.schedule_type == ScheduleType.INTERVAL:
            try:
                interval_seconds = int(job.schedule_expression)
                job.next_run = job.last_run + timedelta(seconds=interval_seconds)
            except ValueError:
                self.logger.error(f"Invalid interval for job {job.id}")
                job.enabled = False
                
        elif job.schedule_type == ScheduleType.ONCE:
            # One-time jobs don't get rescheduled
            job.enabled = False
            job.next_run = None
    
    def get_job_status(self, job_id: str) -> Optional[str]:
        """Get the status of a running job"""
        if job_id in self.running_jobs:
            process = self.running_jobs[job_id]
            if process.poll() is None:
                return "running"
            else:
                return "completed" if process.returncode == 0 else "failed"
        return None
    
    def cancel_job(self, job_id: str) -> bool:
        """Cancel a running job"""
        if job_id in self.running_jobs:
            process = self.running_jobs[job_id]
            if process.poll() is None:
                process.terminate()
                self.logger.info(f"Cancelled job: {job_id}")
                return True
        return False