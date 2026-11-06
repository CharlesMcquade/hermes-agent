"""Pruned grep must not fold invalid-pattern errors into an empty result."""

import pytest

from tools.environments.local import LocalEnvironment
from tools.file_operations import ShellFileOperations


@pytest.mark.platforms("posix")
def test_pruned_grep_preserves_regex_error_and_literal_root(tmp_path, monkeypatch):
    root = tmp_path / ".hidden [literal] 'scoped'"
    root.mkdir()
    (root / "needle file.txt").write_text("needle here\n")
    ops = ShellFileOperations(LocalEnvironment(cwd=str(root)), cwd=str(root))
    # Force grep and the pruned find lane; the literal directory is exercise for
    # shell quoting as well as the stderr-through-stdout error contract.
    monkeypatch.setattr(ops, "_has_command", lambda command: command == "grep")

    matched = ops.search("needle", path=str(root), target="content")
    assert matched.error is None
    assert [match.path for match in matched.matches] == [str(root / "needle file.txt")]

    failed = ops.search("[", path=str(root), target="content")
    assert failed.error is not None
    assert failed.error.startswith("Search failed: grep: ")
    assert failed.matches == []
    assert failed.total_count == 0
