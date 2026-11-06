"""Opt-in reboot commands use the ordinary dangerous-command approval flow.

The default hardline floor is unchanged. ``approvals.allow_reboot`` is an
operator opt-in for host/router administration, not a second approval bypass:
manual/smart policy and unattended deny modes still apply.
"""

import pytest

import hermes_cli.config as hc
from tools.approval import (
    check_all_command_guards,
    check_dangerous_command,
    disable_session_yolo,
    enable_session_yolo,
)
from tools.approval_context import reset_current_session_key, set_current_session_key
from tools.approval_detection import detect_dangerous_command, detect_hardline_command


_POWER_COMMANDS = [
    "shutdown -h now",
    "reboot",
    "sudo reboot",
    "halt",
    "poweroff",
    "init 0",
    "init 6",
    "telinit 0",
    "systemctl poweroff",
    "systemctl reboot",
    "systemctl halt",
    "systemctl kexec",
    "env FOO=1 reboot",
    "true && (reboot)",
    # The incident's harmless local fixture must not hit an unconditional wall
    # merely because its Python source creates a mock executable named reboot.
    "python3 - <<'PY2'\n"
    "import pathlib\n"
    "mocks={\n"
    "  'reboot':'#!/bin/sh\\\\nprintf called >\\\"$MOCK_STATE/reboot\\\"\\\\n',\n"
    "}\n"
    "PY2",
]


@pytest.fixture
def write_approval_config(tmp_path, monkeypatch):
    """Write real profile config and reload it through the production cache path."""
    home = tmp_path / "hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.delenv("HERMES_INTERACTIVE", raising=False)
    monkeypatch.delenv("HERMES_GATEWAY_SESSION", raising=False)
    monkeypatch.delenv("HERMES_CRON_SESSION", raising=False)
    monkeypatch.delenv("HERMES_EXEC_ASK", raising=False)

    def write(*, allow_reboot=None, mode="manual", cron_mode="deny", deny_reboot=False):
        allow_line = "" if allow_reboot is None else f"  allow_reboot: {str(allow_reboot).lower()}\n"
        deny_block = "  deny:\n    - \"*reboot*\"\n" if deny_reboot else ""
        (home / "config.yaml").write_text(
            "approvals:\n"
            f"  mode: {mode}\n"
            f"{allow_line}"
            f"{deny_block}"
            f"  cron_mode: {cron_mode}\n"
        )
        hc._LOAD_CONFIG_CACHE.clear()

    yield write
    hc._LOAD_CONFIG_CACHE.clear()


@pytest.fixture
def clean_session():
    token = set_current_session_key("allow_reboot_test")
    try:
        disable_session_yolo("allow_reboot_test")
        yield
    finally:
        disable_session_yolo("allow_reboot_test")
        reset_current_session_key(token)


@pytest.mark.parametrize("guard", [check_all_command_guards, check_dangerous_command])
def test_default_power_commands_remain_hardline(write_approval_config, guard):
    write_approval_config()
    result = guard("reboot", "local")
    assert result["approved"] is False
    assert result.get("hardline") is True


@pytest.mark.parametrize("command", _POWER_COMMANDS)
def test_opt_in_mode_off_allows_power_commands(write_approval_config, command):
    write_approval_config(allow_reboot=True, mode="off")

    # Classification remains intact; the execution floor is what changes.
    assert detect_hardline_command(command)[0] is True
    assert detect_dangerous_command(command)[0] is True
    assert check_all_command_guards(command, "local")["approved"] is True
    assert check_dangerous_command(command, "local")["approved"] is True


def test_opt_in_still_requires_manual_approval(write_approval_config, monkeypatch):
    write_approval_config(allow_reboot=True, mode="manual")
    monkeypatch.setenv("HERMES_INTERACTIVE", "1")
    calls = []

    def deny(*args, **kwargs):
        calls.append((args, kwargs))
        return "deny"

    result = check_dangerous_command("reboot", "local", approval_callback=deny)
    assert result["approved"] is False
    assert result.get("hardline") is not True
    assert len(calls) == 1


def test_opt_in_still_denies_headless_cron(write_approval_config, monkeypatch):
    write_approval_config(allow_reboot=True, mode="manual", cron_mode="deny")
    monkeypatch.setenv("HERMES_CRON_SESSION", "1")
    result = check_all_command_guards("reboot", "local")
    assert result["approved"] is False
    assert result.get("hardline") is not True


def test_opt_in_session_yolo_allows_power_commands(write_approval_config, clean_session):
    write_approval_config(allow_reboot=True, mode="manual")
    enable_session_yolo("allow_reboot_test")
    assert check_all_command_guards("reboot", "local")["approved"] is True
    assert check_dangerous_command("reboot", "local")["approved"] is True


@pytest.mark.parametrize("value", [False, "false"])
def test_false_values_preserve_hardline(write_approval_config, value):
    write_approval_config(allow_reboot=value, mode="off")
    result = check_all_command_guards("reboot", "local")
    assert result["approved"] is False
    assert result.get("hardline") is True


def test_opt_in_does_not_weaken_other_hardline_commands(write_approval_config):
    write_approval_config(allow_reboot=True, mode="off")
    result = check_all_command_guards("rm -rf /", "local")
    assert result["approved"] is False
    assert result.get("hardline") is True


def test_user_deny_rule_still_wins_over_opt_in(write_approval_config):
    write_approval_config(allow_reboot=True, mode="off", deny_reboot=True)
    result = check_all_command_guards("reboot", "local")
    assert result["approved"] is False
    assert result.get("user_deny") is True


_COMPOUND_POWER_AND_ROOT_WIPE = [
    "reboot; rm -rf /",
    "reboot && rm -rf /",
    "reboot || rm -rf /",
    'echo "$(reboot; rm -rf /)"',
    'echo "`reboot && rm -rf /`"',
]


@pytest.mark.parametrize("guard", [check_all_command_guards, check_dangerous_command])
@pytest.mark.parametrize("command", _COMPOUND_POWER_AND_ROOT_WIPE)
def test_opt_in_never_hides_non_power_hardline_in_compound(write_approval_config, guard, command):
    """The legacy first match is power; the later unrelated hardline must still win."""
    write_approval_config(allow_reboot=True, mode="off")
    assert detect_hardline_command(command)[0] is True  # classification exercise only
    result = guard(command, "local")
    assert result["approved"] is False
    assert result.get("hardline") is True
    assert "recursive delete of root filesystem" in result["message"]


def test_opt_in_allows_unrelated_non_hardline_compound(write_approval_config):
    write_approval_config(allow_reboot=True, mode="off")
    result = check_all_command_guards("reboot && systemctl restart nginx", "local")
    assert result["approved"] is True
    assert result.get("hardline") is not True


def test_default_config_registers_opt_in_as_disabled():
    from hermes_cli.config_defaults import DEFAULT_CONFIG

    assert DEFAULT_CONFIG["approvals"]["allow_reboot"] is False
