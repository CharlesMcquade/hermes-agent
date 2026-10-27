import subprocess, sys
from pathlib import Path

PY = sys.executable
TOOL = Path(__file__).with_name("fire_redeploy.py")


def _run(*args):
    return subprocess.run([PY, "-B", str(TOOL), *args], text=True, capture_output=True)


def test_build_refuses_missing_release_tag():
    r = _run("build", "--session", "s", "--webui-commit", "a" * 40, "--agent-commit", "b" * 40)
    assert r.returncode != 0 and "release-tag" in r.stdout + r.stderr


def test_build_refuses_short_commit():
    r = _run("build", "--session", "s", "--release-tag", "r999", "--webui-commit", "abc", "--agent-commit", "b" * 40)
    assert r.returncode != 0 and "40-char" in r.stdout + r.stderr


def test_phase_without_op_is_a_usage_error():
    r = _run("plan", "--session", "s")
    assert r.returncode == 2 and "requires --op-id" in r.stderr


def test_fire_requires_session():
    r = _run("fire")
    assert r.returncode == 2 and "--session is required" in r.stderr


def test_status_on_missing_op_is_empty_not_crash(tmp_path):
    r = _run("status", "--op-id", "deadbeef", "--day", "19700101")
    assert r.returncode == 0 and "outcome: None" in r.stdout
