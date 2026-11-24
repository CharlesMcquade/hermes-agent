import os, subprocess, sys
from pathlib import Path

PY = sys.executable
TOOL = Path(__file__).with_name("fire_redeploy.py")
# Never let a test inherit the calling chat's identity: fire/ship would start a real release.
ENV = {k: v for k, v in os.environ.items() if k != "HERMES_SESSION_ID"}


def _run(*args, timeout=60):
    return subprocess.run([PY, "-B", str(TOOL), *args], text=True, capture_output=True, env=ENV, timeout=timeout)


def test_validation_scope_flags_map_onto_the_gate_config():
    sys.path.insert(0, str(TOOL.parent))
    import argparse, fire_redeploy as fr
    a = argparse.Namespace(agent_discovery_base="a" * 40, webui_discovery_base=None,
                           webui_paired=True, validation_timeout=900)
    cfg = fr.apply_validation_scope({"validation": {"agent": {"tests": ["tests/test_x.py"]}}}, a)
    assert cfg["validation"]["agent"] == {"tests": ["tests/test_x.py"], "test_discovery_base_commit": "a" * 40}
    assert cfg["validation"]["webui"] == {"paired": True}
    assert cfg["validation"]["timeout_seconds"] == 900
    # default: nothing added, production->candidate scope stays the gate default
    none = argparse.Namespace(agent_discovery_base=None, webui_discovery_base=None,
                              webui_paired=False, validation_timeout=None)
    assert fr.apply_validation_scope({"validation": {}}, none) == {"validation": {}}


def test_discovery_base_must_be_40_hex():
    r = _run("build", "--session", "s", "--agent-discovery-base", "fork/main",
             "--webui-commit", "b" * 40, "--agent-commit", "b" * 40)
    assert r.returncode != 0
    assert "40-hex" in r.stderr  # argparse rejects before any op dir or checkout exists


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
