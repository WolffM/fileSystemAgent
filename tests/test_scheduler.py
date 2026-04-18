import sys
from pathlib import Path

from src.models import ScheduleType, ScheduledJob
from src.scheduler import JobScheduler


class _FakeProcess:
    pid = 1234

    def poll(self):
        return None


async def test_execute_job_uses_absolute_python_executable(tmp_path, monkeypatch):
    scripts_dir = tmp_path / "scripts"
    scripts_dir.mkdir()
    (scripts_dir / "job.py").write_text("print('ok')", encoding="utf-8")

    scheduler = JobScheduler(str(scripts_dir))
    job = ScheduledJob(
        id="job-1",
        name="test-job",
        script_path="job.py",
        schedule_type=ScheduleType.ONCE,
        schedule_expression="2026-01-01T00:00:00",
    )

    popen_call = {}

    def fake_popen(args, **kwargs):
        popen_call["args"] = args
        popen_call["kwargs"] = kwargs
        return _FakeProcess()

    monkeypatch.setattr("src.scheduler.subprocess.Popen", fake_popen)

    await scheduler._execute_job(job)

    assert popen_call["args"][0] == sys.executable
    assert Path(popen_call["args"][0]).is_absolute()
