import os, subprocess, sys
from pathlib import Path

PY = sys.executable
TOOL = Path(__file__).with_name("fire_redeploy.py")
# Never let a test inherit the calling chat's identity: fire/ship would start a real release.
ENV = {k: v for k, v in os.environ.items() if k != "HERMES_SESSION_ID"}


def _run(*args, timeout=60):
    return subprocess.run([PY, "-B", str(TOOL), *args], text=True, capture_output=True, env=ENV, timeout=timeout)


def test_build_with_unknown_ref_fails_before_creating_anything():
    before = set((Path.home() / ".hermes/releases").iterdir())
    r = _run("build", "--session", "s", "--webui-commit", "fork/no-such-branch-xyz", "--agent-commit", "b" * 40)
    assert r.returncode != 0
    assert set((Path.home() / ".hermes/releases").iterdir()) == before


def test_phase_without_op_is_a_usage_error():
    r = _run("plan", "--session", "s")
    assert r.returncode == 2 and "requires --op-id" in r.stderr


def test_fire_requires_session():
    r = _run("fire")
    assert r.returncode == 2 and "--session is required" in r.stderr


def test_ship_requires_explicit_session_even_inside_a_chat():
    env = dict(ENV, HERMES_SESSION_ID="would-start-a-release")
    r = subprocess.run([PY, "-B", str(TOOL), "ship"], text=True, capture_output=True, env=env, timeout=60)
    assert r.returncode == 2 and "--session is required" in r.stderr


def test_status_on_missing_op_is_empty_not_crash(tmp_path):
    r = _run("status", "--op-id", "deadbeef", "--day", "19700101")
    assert r.returncode == 0 and "outcome: None" in r.stdout
