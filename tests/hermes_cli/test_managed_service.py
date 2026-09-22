"""External launchd ownership is preserved across lifecycle operations."""
import plistlib
import subprocess
import sys
from unittest.mock import Mock

import pytest

from hermes_cli import gateway


@pytest.fixture
def service(tmp_path, monkeypatch):
    path = tmp_path / "gateway.plist"
    receipt = tmp_path / "preflight-ran"
    script = tmp_path / "launcher.py"
    script.write_text(
        "import pathlib, sys\n"
        f"pathlib.Path({str(receipt)!r}).write_text('checked')\n"
        "sys.exit(int(sys.argv[1]))\n"
    )
    monkeypatch.setattr(gateway, "get_launchd_plist_path", lambda: path)
    monkeypatch.setattr(gateway, "_launchd_domain", lambda: "gui/test")
    monkeypatch.setattr(gateway, "_clear_launchd_unsupported_marker", lambda: None)
    from gateway import status
    monkeypatch.setattr(status, "get_running_pid", lambda: 12345)
    boundaries = {}
    for name in ("_request_gateway_self_restart", "_escalate_wedged_gateway",
                 "_graceful_restart_via_sigusr1", "_launchd_fallback_to_detached",
                 "generate_launchd_plist", "_launchctl_bootstrap",
                 "_launchctl_kickstart_current"):
        boundaries[name] = Mock(return_value=True)
        monkeypatch.setattr(gateway, name, boundaries[name])
    real_run = subprocess.run
    launchctl = Mock(return_value=subprocess.CompletedProcess([], 0))
    monkeypatch.setattr(subprocess, "run", lambda argv, **kw:
                        launchctl(argv, **kw) if argv[0] == "launchctl" else real_run(argv, **kw))
    boundaries["launchctl"] = launchctl

    def write(marker):
        data = {"Label": "test", "ProgramArguments": ["/external/launcher"]}
        if marker != "absent":
            data["HermesServiceManager"] = marker
        path.write_bytes(plistlib.dumps(data))
        return path.read_bytes()

    marker = {"preflight": [sys.executable, str(script), "0"],
              "description": "Use managed production deployment to change this service"}
    return path, receipt, marker, write, boundaries


@pytest.mark.parametrize("operation", ["install", "force", "refresh", "start", "restart"])
@pytest.mark.parametrize("kind", ["valid", "failed", "malformed", "relative", "empty",
                                  "missing-executable", "string-argv", "typed-arg", "description"])
def test_managed_definition_and_preflight_boundary(service, operation, kind, capsys):
    path, receipt, marker, write, boundaries = service
    argv = marker["preflight"]
    variants = {
        "valid": marker,
        "failed": {**marker, "preflight": [*argv[:-1], "7"]},
        "malformed": False,
        "relative": {**marker, "preflight": ["python3", *argv[1:]]},
        "empty": {**marker, "preflight": []},
        "missing-executable": {**marker, "preflight": [str(path.parent / "missing-python")]},
        "string-argv": {**marker, "preflight": "/bin/true --check"},
        "typed-arg": {**marker, "preflight": [*argv, 1]},
        "description": {**marker, "description": False},
    }
    marker = variants[kind]
    before = write(marker)
    action = {"install": gateway.launchd_install,
              "force": lambda: gateway.launchd_install(force=True),
              "refresh": gateway.refresh_launchd_plist_if_needed,
              "start": gateway.launchd_start, "restart": gateway.launchd_restart}[operation]
    allowed = kind == "valid" and operation in ("start", "restart")
    def after_preflight(*args, **kwargs):
        assert receipt.read_text() == "checked"
        return True
    for name in ("_launchctl_kickstart_current", "_request_gateway_self_restart"):
        boundaries[name].side_effect = after_preflight
    if allowed or operation == "refresh":
        action()
    else:
        with pytest.raises(RuntimeError, match="managed|HermesServiceManager|preflight"):
            action()
    assert path.read_bytes() == before
    boundaries["generate_launchd_plist"].assert_not_called()
    boundaries["_launchd_fallback_to_detached"].assert_not_called()
    if allowed:
        assert receipt.read_text() == "checked"
        expected = "_launchctl_kickstart_current" if operation == "start" else "_request_gateway_self_restart"
        boundaries[expected].assert_called_once()
    else:
        for boundary in boundaries.values():
            boundary.assert_not_called()
    if operation == "refresh":
        assert "managed" in capsys.readouterr().out


@pytest.mark.parametrize("operation", ["start", "restart"])
def test_managed_launchctl_failure_never_degrades(service, operation):
    path, receipt, marker, write, boundaries = service
    before = write(marker)
    error = subprocess.CalledProcessError(125, ["launchctl"])
    boundaries["_request_gateway_self_restart"].return_value = False
    # No running process: exercise bootstrap failure without touching a live PID.
    from gateway import status
    from unittest.mock import patch
    boundaries["_launchctl_kickstart_current"].side_effect = error
    boundaries["_launchctl_bootstrap"].side_effect = error
    boundaries["launchctl"].side_effect = error
    with patch.object(status, "get_running_pid", return_value=None):
        with pytest.raises(subprocess.CalledProcessError):
            getattr(gateway, "launchd_" + operation)()
    assert receipt.exists()
    assert path.read_bytes() == before
    boundaries["_launchd_fallback_to_detached"].assert_not_called()
