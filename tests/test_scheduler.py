"""Tests for scheduler job execution."""

import sys

from src.models import ScheduleType, ScheduledJob
from src.scheduler import JobScheduler


class _DummyProcess:
    pid = 1234

    def poll(self):
        return None


async def test_execute_job_uses_absolute_python_executable(tmp_path, monkeypatch):
    script_file = tmp_path / "job_script.py"
    script_file.write_text("print('ok')")

    scheduler = JobScheduler(str(tmp_path))
    job = ScheduledJob(
        id="job-1",
        name="test job",
        script_path=script_file.name,
        schedule_type=ScheduleType.INTERVAL,
        schedule_expression="60",
        parameters={"k": "v"},
    )

    captured = {}

    def fake_popen(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return _DummyProcess()

    monkeypatch.setattr("src.scheduler.subprocess.Popen", fake_popen)

    await scheduler._execute_job(job)

    assert captured["cmd"][0] == sys.executable
    assert captured["cmd"][1] == str(script_file)
