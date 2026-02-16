import os
import json
import asyncio
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from pathlib import Path
from croniter import croniter

from .models import ScheduledJob, ScheduleType
from .mcp_client import MCPFileSystemClient


class MCPJobScheduler:
    """Job scheduler with MCP command execution support"""

    def __init__(self, scripts_dir: str, max_concurrent_jobs: int = 2, use_mcp: bool = False):
        self.scripts_dir = Path(scripts_dir)
        self.max_concurrent_jobs = max_concurrent_jobs
        self.use_mcp = use_mcp
        self.logger = logging.getLogger(__name__)
        self.running_jobs: Dict[str, asyncio.Task] = {}
        self.scheduled_jobs: Dict[str, ScheduledJob] = {}
        self.is_running = False
        self.mcp_client: Optional[MCPFileSystemClient] = None

    async def __aenter__(self):
        if self.use_mcp:
            self.mcp_client = MCPFileSystemClient()
            await self.mcp_client.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.mcp_client:
            await self.mcp_client.disconnect()
            self.mcp_client = None

    def add_job(self, job: ScheduledJob):
        self.scheduled_jobs[job.id] = job
        self._schedule_job(job)
        self.logger.info(f"Added scheduled job: {job.name}")

    def remove_job(self, job_id: str):
        if job_id in self.scheduled_jobs:
            del self.scheduled_jobs[job_id]
            self.logger.info(f"Removed scheduled job: {job_id}")

    def enable_job(self, job_id: str):
        if job_id in self.scheduled_jobs:
            self.scheduled_jobs[job_id].enabled = True
            self._schedule_job(self.scheduled_jobs[job_id])

    def disable_job(self, job_id: str):
        if job_id in self.scheduled_jobs:
            self.scheduled_jobs[job_id].enabled = False

    def get_jobs(self) -> List[ScheduledJob]:
        return list(self.scheduled_jobs.values())

    def get_job(self, job_id: str) -> Optional[ScheduledJob]:
        return self.scheduled_jobs.get(job_id)

    def _schedule_job(self, job: ScheduledJob):
        if not job.enabled:
            return

        if job.schedule_type == ScheduleType.CRON:
            try:
                cron = croniter(job.schedule_expression, datetime.now())
                job.next_run = cron.get_next(datetime)
            except Exception as e:
                self.logger.error(f"Invalid cron expression for job {job.id}: {e}")
        elif job.schedule_type == ScheduleType.INTERVAL:
            try:
                interval_seconds = int(job.schedule_expression)
                job.next_run = datetime.now() + timedelta(seconds=interval_seconds)
            except ValueError:
                self.logger.error(f"Invalid interval expression for job {job.id}")
        elif job.schedule_type == ScheduleType.ONCE:
            try:
                job.next_run = datetime.fromisoformat(job.schedule_expression)
            except ValueError:
                self.logger.error(f"Invalid datetime expression for job {job.id}")

    async def start(self):
        self.is_running = True
        self.logger.info("Starting MCP job scheduler")

        while self.is_running:
            await self._check_and_run_jobs()
            await asyncio.sleep(1)

    def stop(self):
        self.is_running = False
        self.logger.info("Stopping MCP job scheduler")

        for job_id, task in self.running_jobs.items():
            if not task.done():
                task.cancel()
                self.logger.info(f"Cancelled job: {job_id}")

    async def _check_and_run_jobs(self):
        current_time = datetime.now()

        # Clean up completed jobs
        completed_jobs = [
            job_id for job_id, task in self.running_jobs.items()
            if task.done()
        ]

        for job_id in completed_jobs:
            task = self.running_jobs.pop(job_id)
            try:
                await task
                self.logger.info(f"Job {job_id} completed successfully")
            except Exception as e:
                self.logger.error(f"Job {job_id} failed: {e}")

        if len(self.running_jobs) >= self.max_concurrent_jobs:
            return

        for job in self.scheduled_jobs.values():
            if not job.enabled or job.next_run is None:
                continue

            if current_time >= job.next_run and job.id not in self.running_jobs:
                task = asyncio.create_task(self._execute_job(job))
                self.running_jobs[job.id] = task
                self._schedule_next_run(job)

    async def _execute_job(self, job: ScheduledJob):
        script_path = self.scripts_dir / job.script_path

        # Check if script exists
        if self.use_mcp and self.mcp_client:
            if not await self.mcp_client.file_exists(str(script_path)):
                self.logger.error(f"Script not found: {script_path}")
                return
        else:
            if not script_path.exists():
                self.logger.error(f"Script not found: {script_path}")
                return

        try:
            job.last_run = datetime.now()

            if self.use_mcp and self.mcp_client:
                result = await self._execute_script_mcp(job, script_path)
            else:
                result = await self._execute_script_direct(job, script_path)

            if result["returncode"] == 0:
                self.logger.info(f"Job {job.name} completed successfully")
            else:
                self.logger.error(f"Job {job.name} failed with return code {result['returncode']}")
                self.logger.error(f"stderr: {result['stderr']}")

        except Exception as e:
            self.logger.error(f"Failed to execute job {job.id}: {e}")

    async def _execute_script_mcp(self, job: ScheduledJob, script_path: Path) -> Dict[str, Any]:
        env_vars = {
            'JOB_ID': job.id,
            'JOB_NAME': job.name,
            'JOB_PARAMS': json.dumps(job.parameters)
        }

        original_env = {}
        for key, value in env_vars.items():
            original_env[key] = os.environ.get(key)
            os.environ[key] = value

        try:
            result = await self.mcp_client.execute_command(
                command="python",
                args=[str(script_path)],
                cwd=str(self.scripts_dir)
            )
            return result
        finally:
            for key, value in original_env.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    async def _execute_script_direct(self, job: ScheduledJob, script_path: Path) -> Dict[str, Any]:
        env = {
            **dict(os.environ),
            'JOB_ID': job.id,
            'JOB_NAME': job.name,
            'JOB_PARAMS': json.dumps(job.parameters)
        }

        process = await asyncio.create_subprocess_exec(
            'python', str(script_path),
            cwd=str(self.scripts_dir),
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await process.communicate()

        return {
            "returncode": process.returncode,
            "stdout": stdout.decode(),
            "stderr": stderr.decode()
        }

    def _schedule_next_run(self, job: ScheduledJob):
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
            job.enabled = False
            job.next_run = None
