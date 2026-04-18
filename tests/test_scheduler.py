import os
import sys
from unittest.mock import MagicMock, patch

from src.models import ScheduleType, ScheduledJob
from src.scheduler import JobScheduler


class TestJobScheduler:
    async def test_execute_job_uses_absolute_python_executable(self, tmp_path):
        scripts_dir = tmp_path / "scripts"
        scripts_dir.mkdir()
        script_file = scripts_dir / "example.py"
        script_file.write_text("print('ok')\n", encoding="utf-8")

        scheduler = JobScheduler(str(scripts_dir))
        job = ScheduledJob(
            id="job-1",
            name="example",
            script_path="example.py",
            schedule_type=ScheduleType.ONCE,
            schedule_expression="2026-01-01T00:00:00",
        )

        mocked_process = MagicMock()
        mocked_process.pid = 1234

        with patch("src.scheduler.subprocess.Popen", return_value=mocked_process) as mocked_popen:
            await scheduler._execute_job(job)

        assert mocked_popen.called
        command = mocked_popen.call_args.args[0]
        assert command[0] == os.path.abspath(sys.executable)
