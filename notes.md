## Steps to reproduce

1. Install Bandit in the environment (`pip install bandit`) if it is not already available.
2. From the repository root, run `~/.local/bin/bandit -r src/scheduler.py`.
3. Inspect the reported findings for `src/scheduler.py`.
4. Observe the process launch line in `_execute_job`, where the command was previously `['python', str(script_path)]`.

## Observed

Bandit reports `B607: start_process_with_partial_path` on the scheduler subprocess launch. The trace shows the issue at the `subprocess.Popen` call in `src/scheduler.py`, because `python` is a partial executable path and can be influenced by `PATH` search order. This is low severity but valid and reproducible with Bandit output.

## Expected

The scheduler should launch scripts using an explicit executable path so Bandit does not report B607. The command should use the current interpreter absolute path (`sys.executable`, normalized to absolute) rather than a bare `python` token. This keeps behavior consistent while reducing path-hijack risk and satisfying the security lint expectation.
