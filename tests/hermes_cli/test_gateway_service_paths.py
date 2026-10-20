from pathlib import Path
from unittest.mock import patch

import plistlib


def test_service_path_skips_nonexistent_node_modules(tmp_path):
    """Service PATH should not include node_modules/.bin if it doesn't exist."""
    from hermes_cli.gateway import _build_service_path_dirs
    with patch("hermes_cli.gateway.get_hermes_home", return_value=tmp_path / ".hermes"):
        dirs = _build_service_path_dirs(project_root=tmp_path)
    node_modules_bin = str(tmp_path / "node_modules" / ".bin")
    assert node_modules_bin not in dirs


def test_service_path_includes_node_modules_when_present(tmp_path):
    """Service PATH should include node_modules/.bin when it exists."""
    nm_bin = tmp_path / "node_modules" / ".bin"
    nm_bin.mkdir(parents=True)
    from hermes_cli.gateway import _build_service_path_dirs
    with patch("hermes_cli.gateway.get_hermes_home", return_value=tmp_path / ".hermes"):
        dirs = _build_service_path_dirs(project_root=tmp_path)
    assert str(nm_bin) in dirs


def test_service_path_includes_hermes_home_node_modules(tmp_path):
    """Service PATH should include ~/.hermes/node_modules/.bin when it exists."""
    hermes_nm = tmp_path / ".hermes" / "node_modules" / ".bin"
    hermes_nm.mkdir(parents=True)
    from hermes_cli.gateway import _build_service_path_dirs
    with patch("hermes_cli.gateway.get_hermes_home", return_value=tmp_path / ".hermes"):
        dirs = _build_service_path_dirs(project_root=tmp_path)
    assert str(hermes_nm) in dirs


PM_DIRS = {
    "/opt/homebrew/bin",
    "/opt/homebrew/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/home/linuxbrew/.linuxbrew/bin",
    "/home/linuxbrew/.linuxbrew/sbin",
}


def test_service_path_includes_existing_package_manager_dirs(tmp_path):
    """Homebrew/Linuxbrew/usr-local bin dirs must be on the service PATH when present (#56467).

    launchd's default PATH (/usr/bin:/bin:/usr/sbin:/sbin) and systemd's minimal unit
    PATH both omit these, so CLI tools installed via Homebrew (gh, jq, ffmpeg, ...) are
    invisible to cron job scripts and any subprocess launched from the running gateway
    service, even though the same tools resolve fine in an interactive shell.
    """
    import hermes_cli.gateway as gateway_module

    real_is_dir = Path.is_dir
    existing = {"/opt/homebrew/bin", "/usr/local/bin", "/home/linuxbrew/.linuxbrew/bin"}

    def fake_is_dir(self):
        if str(self) in PM_DIRS:
            return str(self) in existing
        return real_is_dir(self)

    with patch("hermes_cli.gateway.get_hermes_home", return_value=tmp_path / ".hermes"), \
         patch.object(Path, "is_dir", fake_is_dir):
        dirs = gateway_module._build_service_path_dirs(project_root=tmp_path)

    assert "/opt/homebrew/bin" in dirs
    assert "/usr/local/bin" in dirs
    assert "/home/linuxbrew/.linuxbrew/bin" in dirs
    assert "/opt/homebrew/sbin" not in dirs
    assert "/usr/local/sbin" not in dirs
    assert "/home/linuxbrew/.linuxbrew/sbin" not in dirs


def test_service_path_omits_absent_package_manager_dirs(tmp_path):
    """No package-manager dir should be added when none exist on disk."""
    import hermes_cli.gateway as gateway_module

    real_is_dir = Path.is_dir

    def fake_is_dir(self):
        if str(self) in PM_DIRS:
            return False
        return real_is_dir(self)

    with patch("hermes_cli.gateway.get_hermes_home", return_value=tmp_path / ".hermes"), \
         patch.object(Path, "is_dir", fake_is_dir):
        dirs = gateway_module._build_service_path_dirs(project_root=tmp_path)

    assert not (set(dirs) & PM_DIRS)


def _systemd_path_entries(monkeypatch, service_dirs):
    import hermes_cli.gateway as gateway_module

    monkeypatch.setattr(gateway_module, "_build_service_path_dirs", lambda *a, **k: list(service_dirs))
    monkeypatch.setattr(gateway_module, "_build_user_local_paths", lambda home, entries: [])
    monkeypatch.setattr(gateway_module, "_build_wsl_interop_paths", lambda entries: [])
    monkeypatch.setattr(gateway_module, "_append_node_dir_for_service", lambda entries, *a, **k: None)
    monkeypatch.setattr(gateway_module, "_ld_library_path_line", lambda *a, **k: "")
    unit = gateway_module.generate_systemd_unit()
    path_line = next(line for line in unit.splitlines() if line.startswith('Environment="PATH='))
    return path_line.removeprefix('Environment="PATH=').removesuffix('"').split(":")


def test_systemd_path_deduplicates_package_manager_dirs(monkeypatch):
    """A dir present in both the service list and the systemd defaults must appear once."""
    entries = _systemd_path_entries(monkeypatch, ["/usr/local/bin"])
    assert entries.count("/usr/local/bin") == 1
    assert entries.count("/usr/bin") == 1


def test_systemd_path_preserves_service_dir_order(monkeypatch):
    """Custom service dirs keep their position ahead of the systemd fallback dirs."""
    entries = _systemd_path_entries(monkeypatch, ["/opt/homebrew/bin", "/custom/operator/bin"])
    assert entries.index("/opt/homebrew/bin") < entries.index("/usr/bin")
    assert entries.index("/custom/operator/bin") < entries.index("/usr/bin")


def _launchd_plist_path(monkeypatch, shell_path, service_dirs):
    """Generate the launchd plist with a controlled shell PATH; return its PATH entries."""
    import hermes_cli.gateway as gateway_module

    home = Path("/tmp/nonexistent-k03-home")
    monkeypatch.setattr(gateway_module, "get_hermes_home", lambda: home)
    monkeypatch.setattr(gateway_module, "_stable_service_working_dir", lambda: "/tmp")
    monkeypatch.setattr(gateway_module, "_build_service_path_dirs", lambda *a, **k: list(service_dirs))
    monkeypatch.setattr(gateway_module, "_append_node_dir_for_service", lambda entries, *a, **k: None)
    monkeypatch.setattr(gateway_module, "PROJECT_ROOT", home)
    monkeypatch.setenv("PATH", shell_path)

    plist = plistlib.loads(gateway_module.generate_launchd_plist().encode())
    return plist["EnvironmentVariables"]["PATH"].split(":")


def test_launchd_plist_includes_package_manager_dirs_with_dedup(monkeypatch):
    """Generated plist PATH carries package-manager dirs; user PATH order preserved, deduped."""
    entries = _launchd_plist_path(
        monkeypatch,
        shell_path="/usr/local/bin:/usr/bin:/bin:/usr/local/bin",
        service_dirs=["/opt/homebrew/bin", "/usr/local/bin", "/home/linuxbrew/.linuxbrew/bin"],
    )
    for directory in ("/opt/homebrew/bin", "/usr/local/bin", "/home/linuxbrew/.linuxbrew/bin"):
        assert directory in entries
    # User PATH order preserved (priority dirs first), then shell entries in order, deduped.
    assert entries == [
        "/opt/homebrew/bin", "/usr/local/bin", "/home/linuxbrew/.linuxbrew/bin",
        "/usr/bin", "/bin",
    ]


def test_launchd_plist_handles_empty_and_malformed_shell_path(monkeypatch):
    """Empty and malformed (':'-runs, trailing colon) shell PATH must not inject empty entries."""
    for shell_path in ("", "::::", "/usr/bin::/bin:", ":"):
        entries = _launchd_plist_path(monkeypatch, shell_path=shell_path, service_dirs=["/opt/homebrew/bin"])
        assert "" not in entries
        assert "/opt/homebrew/bin" in entries


def test_launchd_path_migration_detects_new_managed_directory():
    """Minimal-PATH plists compare unequal to refreshed ones; ambient drift still ignored."""
    from hermes_cli.gateway import _normalize_launchd_plist_for_comparison

    old = "<key>PATH</key><string>/usr/bin:/bin</string>"
    refreshed = "<key>PATH</key><string>/opt/homebrew/bin:/usr/bin:/bin</string>"
    ambient_only = "<key>PATH</key><string>/some/shell/bin:/usr/bin:/bin</string>"
    assert _normalize_launchd_plist_for_comparison(old) == _normalize_launchd_plist_for_comparison(ambient_only)
    assert _normalize_launchd_plist_for_comparison(old) != _normalize_launchd_plist_for_comparison(refreshed)


def test_launchd_path_migration_is_idempotent_when_current():
    """A plist already carrying the managed dirs normalizes equal to another current variant."""
    from hermes_cli.gateway import _normalize_launchd_plist_for_comparison

    current = "<key>PATH</key><string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin</string>"
    current_reordered = "<key>PATH</key><string>/usr/bin:/bin:/opt/homebrew/bin:/usr/local/bin</string>"
    assert _normalize_launchd_plist_for_comparison(current) == _normalize_launchd_plist_for_comparison(current_reordered)


PLIST_HEAD = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.hermes.gateway</string>
    <key>KeepAlive</key>
    <true/>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>{path}</string>
        <key>HERMES_HOME</key>
        <string>/Users/tester/.hermes</string>
    </dict>
</dict>
</plist>
"""


def _write_fixture_plist(tmp_path, path_value):
    fixture = tmp_path / "com.hermes.gateway.plist"
    fixture.write_text(PLIST_HEAD.format(path=path_value), encoding="utf-8")
    return fixture


def test_fixture_minimal_path_plist_detected_for_migration(tmp_path):
    """Fixture plist on disk: minimal PATH is detected as stale against the refreshed definition."""
    import hermes_cli.gateway as gateway_module

    fixture = _write_fixture_plist(tmp_path, "/usr/bin:/bin")
    installed = fixture.read_text(encoding="utf-8")

    refreshed = PLIST_HEAD.format(path="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin")

    assert gateway_module._normalize_launchd_plist_for_comparison(installed) != \
        gateway_module._normalize_launchd_plist_for_comparison(refreshed)


def test_fixture_current_plist_is_no_op(tmp_path):
    """Fixture plist already carrying the managed dirs is idempotent (no migration needed)."""
    import hermes_cli.gateway as gateway_module

    fixture = _write_fixture_plist(tmp_path, "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin")
    installed = fixture.read_text(encoding="utf-8")

    assert gateway_module._normalize_launchd_plist_for_comparison(installed) == \
        gateway_module._normalize_launchd_plist_for_comparison(installed)


def test_fixture_plist_migration_normalization_preserves_unrelated_keys(tmp_path):
    """The comparison only rewrites the PATH payload; every other key passes through untouched."""
    import hermes_cli.gateway as gateway_module

    fixture = _write_fixture_plist(tmp_path, "/usr/bin:/bin")
    installed = fixture.read_text(encoding="utf-8")
    normalized = gateway_module._normalize_launchd_plist_for_comparison(installed)

    assert "<key>KeepAlive</key>" in normalized
    assert "<true/>" in normalized
    assert "<key>HERMES_HOME</key>" in normalized
    assert "<string>/Users/tester/.hermes</string>" in normalized
    assert "<key>Label</key>" in normalized
    assert "com.hermes.gateway" in normalized


def test_fixture_malformed_plist_is_safe(tmp_path):
    """A fixture plist with no PATH key normalizes without raising."""
    import hermes_cli.gateway as gateway_module

    fixture = tmp_path / "com.hermes.gateway.plist"
    fixture.write_text(PLIST_HEAD.format(path="/usr/bin:/bin").replace(
        "<key>PATH</key>", "<key>OTHER</key>"), encoding="utf-8")
    text = fixture.read_text(encoding="utf-8")
    assert gateway_module._normalize_launchd_plist_for_comparison(text) == \
        gateway_module._normalize_launchd_plist_for_comparison(text)
