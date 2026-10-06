"""Real script-mode CLI dispatch with a disposable launchctl executable.

No live service is queried or changed. This exercises the same main.py invocation
as the WebUI, under Python -I (no editable-install/PYTHONPATH rescue).
"""
import json
import os
from pathlib import Path
import plistlib
import subprocess
import sys

import pytest


@pytest.mark.spawns_gateway_lookalike  # lifecycle CLI exits; launchctl is our bounded stub
@pytest.mark.skipif(sys.platform != "darwin", reason="launchd CLI dispatch")
def test_script_mode_gateway_restart_private_interpreter(tmp_path):
    root = Path(__file__).resolve().parents[2]
    home = tmp_path / "os-home"
    state = home / ".hermes"
    state.mkdir(parents=True)
    (state / "config.yaml").write_text("gateway:\n  multiplex_profiles: false\n")
    plist = home / "Library/LaunchAgents/ai.hermes.gateway.plist"
    plist.parent.mkdir(parents=True)
    program = "/Applications/Example.app/Contents/MacOS/ServiceHost"
    plist.write_bytes(plistlib.dumps({
        "Label": "ai.hermes.gateway",
        "ProgramArguments": [program, "agent"],
        "AssociatedBundleIdentifiers": ["org.example.app"],
        "EnvironmentVariables": {"HERMES_HOME": str(state)},
    }))
    before = plist.read_bytes()
    bindir = tmp_path / "bin"
    bindir.mkdir()
    calls = tmp_path / "calls.jsonl"
    restarted = tmp_path / "restarted"
    fake = bindir / "launchctl"
    fake.write_text(f'''#!{sys.executable}
import json, pathlib, sys
args = sys.argv[1:]
with open({str(calls)!r}, "a") as out:
    out.write(json.dumps(args) + "\\n")
flag = pathlib.Path({str(restarted)!r})
if args[0] == "print":
    if args[1].startswith("user/"): sys.exit(113)
    pid = 124 if flag.exists() else 123
    print(args[1] + " = {{")
    print("\\tpath = " + {str(plist)!r})
    print("\\tprogram = " + {program!r})
    print("\\targuments = {{\\n\\t\\t" + {program!r} + "\\n\\t\\tagent\\n\\t}}")
    print("\\tpid = " + str(pid) + "\\n}}")
elif args == ["kickstart", "-k", "gui/{os.getuid()}/ai.hermes.gateway"]:
    flag.touch()
else:
    sys.exit(99)
''')
    fake.chmod(0o755)
    env = {
        "HOME": str(home), "HERMES_HOME": str(state), "HERMES_BASE_HOME": str(state),
        "PATH": str(bindir) + os.pathsep + os.defpath,
        "HERMES_DISABLE_LAZY_INSTALLS": "1", "PYTHONDONTWRITEBYTECODE": "1",
        "HERMES_GATEWAY_LOCK_DIR": str(tmp_path / "locks"),
        "HERMES_TEST_ISOLATION": str(state),
        "TMPDIR": str(tmp_path), "LANG": "en_US.UTF-8",
    }
    # launchd paths intentionally use pwd, not HOME (profiles may re-home HOME).
    # Stub that OS account lookup in the child as well as launchctl; no real
    # account plist is even read. run_path keeps the WebUI's script-mode imports.
    script = str(root / "hermes_cli/main.py")
    runner = (
        "import pwd, types, runpy, sys; "
        f"pwd.getpwuid=lambda uid: types.SimpleNamespace(pw_dir={str(home)!r}); "
        f"sys.argv=[{script!r}, 'gateway', 'restart']; "
        f"runpy.run_path({script!r}, run_name='__main__')"
    )
    result = subprocess.run([sys.executable, "-B", "-I", "-c", runner], cwd=tmp_path, env=env,
                            capture_output=True, text=True, timeout=55)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Externally owned service restarted" in result.stdout
    assert plist.read_bytes() == before
    commands = [json.loads(line) for line in calls.read_text().splitlines()]
    assert [c for c in commands if c[0] != "print"] == [
        ["kickstart", "-k", f"gui/{os.getuid()}/ai.hermes.gateway"]]
