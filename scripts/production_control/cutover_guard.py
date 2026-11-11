"""Interpreter and process-ancestry guards for irreversible cutover entrypoints."""
import os
from pathlib import Path
import subprocess
import sys


def require_python311():
    if sys.version_info < (3, 11):
        raise SystemExit('Release tooling requires Python 3.11+; use /opt/homebrew/bin/python3')


def process_ancestry(pid=None):
    """Return (pid, ppid, command) from the current process through launchd."""
    pid = os.getpid() if pid is None else pid
    result = []
    seen = set()
    while pid > 0 and pid not in seen:
        seen.add(pid)
        proc = subprocess.run(['ps', '-p', str(pid), '-o', 'ppid=,command='],
                              capture_output=True, text=True, check=True, timeout=10)
        lines = proc.stdout.strip().splitlines()
        if not lines:
            break
        fields = lines[0].strip().split(None, 2)
        ppid = int(fields[0])
        result.append((pid, ppid, fields[2] if len(fields) > 2 else ''))
        pid = ppid
    return result


def require_out_of_process(ancestry=process_ancestry, parent=os.getppid):
    if parent() == 1:
        return
    blocked = ('webui/server.py', 'hermes_cli.main gateway run', 'VerityServiceHost')
    for pid, _ppid, command in ancestry():
        marker = next((item for item in blocked if item in command), None)
        if marker:
            raise RuntimeError(
                f'REFUSED: cutover runs out-of-process; ancestor {pid} is {marker}; '
                'dispatch a launchd job (ppid 1) and read its status instead')
