"""External launchd ownership is never converted into a CLI-owned service."""
import plistlib
import subprocess
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from hermes_cli import gateway as gw
from hermes_cli import gateway_launchd as ld


@pytest.fixture
def external(monkeypatch, tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    path = tmp_path / "ai.hermes.gateway.plist"
    data = {
        "Label": "ai.hermes.gateway",
        "ProgramArguments": ["/Applications/Example.app/Contents/MacOS/ServiceHost", "agent"],
        "AssociatedBundleIdentifiers": ["org.example.app"],
        "EnvironmentVariables": {"HERMES_HOME": str(home)},
    }
    path.write_bytes(plistlib.dumps(data))
    monkeypatch.setattr(gw, "get_launchd_plist_path", lambda: path)
    monkeypatch.setattr(gw, "get_launchd_label", lambda: data["Label"])
    monkeypatch.setattr(gw, "get_hermes_home", lambda: home)
    monkeypatch.setattr(gw, "_launchd_domain", lambda: "gui/501")
    monkeypatch.setattr(ld.os, "getuid", lambda: 501)
    for name in ("generate_launchd_plist", "_prepare_service_launcher", "_spawn_detached_gateway"):
        monkeypatch.setattr(gw, name, Mock(side_effect=AssertionError(name)))
    calls = []
    def run(cmd, **kwargs):
        calls.append(cmd)
        if cmd[1] == "print":
            if cmd[2].startswith("user/"):
                return SimpleNamespace(returncode=113, stdout="", stderr="")
            return SimpleNamespace(returncode=0, stdout=(
                f"{cmd[2]} = {{\n\tpath = {path}\n"
                f"\tprogram = {data['ProgramArguments'][0]}\n"
                "\targuments = {\n\t\t" + "\n\t\t".join(data['ProgramArguments']) +
                "\n\t}\n\tenvironment = {\n\t\tHERMES_HOME => " +
                data['EnvironmentVariables']['HERMES_HOME'] +
                "\n\t}\n\tpid = 123\n}\n"), stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr="")
    monkeypatch.setattr(ld.subprocess, "run", run)
    monkeypatch.setattr(gw, "_wait_for_launchd_service_pid", Mock(return_value=True))
    return path, data, calls, run


def test_restart_preserves_external_definition_and_domain(external):
    path, _, calls, _ = external
    before = path.read_bytes()
    gw.launchd_restart()
    assert path.read_bytes() == before
    assert [c for c in calls if c[1] != "print"] == [
        ["launchctl", "kickstart", "-k", "gui/501/ai.hermes.gateway"]]
    gw._wait_for_launchd_service_pid.assert_called_once_with(
        "ai.hermes.gateway", 123, timeout=15.0, domain="gui/501")


@pytest.mark.parametrize("fault", ["mismatch", "missing", "duplicate", "inherited_only"])
def test_loaded_profile_home_must_match_before_restart(external, monkeypatch, fault):
    path, data, calls, original = external
    home = data["EnvironmentVariables"]["HERMES_HOME"]
    def run(cmd, **kwargs):
        result = original(cmd, **kwargs)
        if cmd[1] == "print" and result.returncode == 0:
            if fault == "mismatch":
                result.stdout = result.stdout.replace("HERMES_HOME => " + home, "HERMES_HOME => /other/home")
            elif fault == "missing":
                result.stdout = result.stdout.replace("HERMES_HOME =>", "OTHER_HOME =>")
            elif fault == "duplicate":
                result.stdout = result.stdout.replace("HERMES_HOME => " + home,
                    "HERMES_HOME => " + home + "\n\t\tHERMES_HOME => /other/home")
            else:
                result.stdout = result.stdout.replace("\tenvironment = {", "\tinherited environment = {")
        return result
    monkeypatch.setattr(ld.subprocess, "run", run)
    before = path.read_bytes()
    with pytest.raises(SystemExit):
        gw.launchd_restart()
    assert path.read_bytes() == before
    assert all(c[1] == "print" for c in calls)


def test_refresh_is_read_only_for_external_definition(external):
    path, _, calls, _ = external
    before = path.read_bytes()
    assert gw.refresh_launchd_plist_if_needed() is False
    assert path.read_bytes() == before
    assert not calls


@pytest.mark.parametrize("fault", ["home", "label", "unloaded", "duplicate", "program", "arguments", "path", "probe_error"])
def test_ambiguous_external_identity_fails_without_mutation(external, monkeypatch, fault):
    path, data, calls, original = external
    if fault in ("home", "label"):
        if fault == "home":
            data["EnvironmentVariables"]["HERMES_HOME"] += "-other"
        else:
            data["Label"] = "foreign"
            monkeypatch.setattr(gw, "get_launchd_label", lambda: "ai.hermes.gateway")
        path.write_bytes(plistlib.dumps(data))
    def run(cmd, **kwargs):
        result = original(cmd, **kwargs)
        if cmd[1] == "print":
            if fault == "unloaded": result.returncode = 113
            if fault == "probe_error": result.returncode = 5
            if fault == "duplicate":
                result = original([*cmd[:2], "gui/501/ai.hermes.gateway"], **kwargs)
            if fault in ("program", "path", "arguments"):
                result.stdout = result.stdout.replace(f"\t{fault} =", "\twrong =")
        return result
    monkeypatch.setattr(ld.subprocess, "run", run)
    before = path.read_bytes()
    with pytest.raises(SystemExit) as exc:
        gw.launchd_restart()
    assert exc.value.code == 1
    assert path.read_bytes() == before
    assert all(c[1] == "print" for c in calls)


@pytest.mark.parametrize("failure", [3, 5, 125, "timeout", "no_replacement"])
def test_external_restart_failure_never_bootstraps_or_falls_back(external, monkeypatch, failure):
    _, _, calls, original = external
    def run(cmd, **kwargs):
        result = original(cmd, **kwargs)
        if cmd[1] == "kickstart":
            if failure == "timeout": raise subprocess.TimeoutExpired(cmd, 30)
            if isinstance(failure, int): raise subprocess.CalledProcessError(failure, cmd)
        return result
    monkeypatch.setattr(ld.subprocess, "run", run)
    monkeypatch.setattr(gw, "_wait_for_launchd_service_pid", Mock(return_value=False))
    with pytest.raises(SystemExit) as exc:
        gw.launchd_restart()
    assert exc.value.code == 1
    assert all(c[1] in ("print", "kickstart") for c in calls)


@pytest.mark.parametrize("force", [False, True])
def test_install_cannot_take_external_ownership(external, force):
    path, _, calls, _ = external
    before = path.read_bytes()
    with pytest.raises(SystemExit):
        gw.launchd_install(force=force)
    assert path.read_bytes() == before
    assert not calls


@pytest.mark.parametrize("verb", ["start", "stop", "uninstall"])
def test_external_bootstrap_owner_retains_other_lifecycle_actions(external, verb):
    path, _, calls, _ = external
    before = path.read_bytes()
    with pytest.raises(SystemExit):
        getattr(gw, "launchd_" + verb)()
    assert path.read_bytes() == before
    assert not calls


def test_unknown_command_without_app_marker_is_not_rewritten(external):
    path, data, calls, _ = external
    data.pop("AssociatedBundleIdentifiers")
    data["ProgramArguments"] = ["/opt/example/host", "agent"]
    path.write_bytes(plistlib.dumps(data))
    before = path.read_bytes()
    assert gw.refresh_launchd_plist_if_needed() is False
    assert path.read_bytes() == before
    assert not calls


def test_malformed_definition_is_not_repaired(external):
    path, _, calls, _ = external
    path.write_bytes(b"not a plist")
    with pytest.raises(SystemExit):
        gw.launchd_restart()
    assert path.read_bytes() == b"not a plist"
    assert not calls


def test_changed_definition_during_admission_is_rejected(external, monkeypatch):
    path, _, calls, original = external
    def run(cmd, **kwargs):
        result = original(cmd, **kwargs)
        if cmd[2].startswith("user/"):
            path.write_bytes(path.read_bytes() + b"\n")
        return result
    monkeypatch.setattr(ld.subprocess, "run", run)
    with pytest.raises(SystemExit):
        gw.launchd_restart()
    assert all(c[1] == "print" for c in calls)


def test_profile_home_a_b_a_cannot_reuse_admission(external, monkeypatch, tmp_path):
    _, data, calls, _ = external
    from pathlib import Path
    home_a = Path(data["EnvironmentVariables"]["HERMES_HOME"])
    for home in (home_a, tmp_path / "other-profile", home_a):
        monkeypatch.setattr(gw, "get_hermes_home", lambda: home)
        calls.clear()
        if home == home_a:
            gw.launchd_restart()
            assert any(c[1] == "kickstart" for c in calls)
        else:
            with pytest.raises(SystemExit):
                gw.launchd_restart()
            assert not calls
