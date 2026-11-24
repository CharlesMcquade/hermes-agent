"""Import smoke coverage for the real MCP OAuth module."""

import os
import subprocess
import sys
from pathlib import Path


def test_mcp_oauth_imports_in_clean_interpreter(tmp_path):
    project_root = Path(__file__).resolve().parents[2]
    home = tmp_path / "home"
    hermes_home = home / ".hermes"
    temp_dir = tmp_path / "tmp"
    hermes_home.mkdir(parents=True)
    temp_dir.mkdir()

    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            "-c",
            "import sys; sys.path.insert(0, sys.argv[1]); import tools.mcp_oauth",
            str(project_root),
        ],
        cwd=project_root,
        env={
            "HOME": str(home),
            "HERMES_HOME": str(hermes_home),
            "TMPDIR": str(temp_dir),
            "PATH": os.environ.get("PATH", ""),
            "PYTHONDONTWRITEBYTECODE": "1",
        },
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
