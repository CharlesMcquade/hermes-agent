"""Title input ignores transport scaffolding without rewriting human prose."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from agent import title_generator as titles


@pytest.mark.parametrize("wrapped, clean", [
    ("[Workspace::v1: /private/project]\nBook Vegas flights", "Book Vegas flights"),
    ("[1 image] [Workspace::v1: /private/project]\nCompare airline fares\n\n"
     "[Attached files: /private/uploads/fare.png]\n[screenshot]", "Compare airline fares"),
    ("[Workspace::v1: /private/project] [2 images] Compare airline fares",
     "Compare airline fares"),
    (r"[Workspace::v1: C:\\work\\plans\]draft] Compare airline fares", "Compare airline fares"),
    ("[Workspace::v1: /" + "long-path/" * 150 + "]\nBook Vegas flights", "Book Vegas flights"),
    ("Compare airline fares\n\n[Attached files: /tmp/fare [extra].png, /tmp/fare2.png]"
     " [screenshot] [screenshot]", "Compare airline fares"),
    ("Compare airline fares\n[screenshot]\n[screenshot]", "Compare airline fares"),
    ("[screenshot]\nCompare airline fares", "Compare airline fares"),
    ("[Workspace::v1: /private/project]\n<command-message>machine</command-message>\n"
     "Book Vegas flights", "Book Vegas flights"),
    ("<command-message>[Workspace::v1: /private/project]\nBook Vegas flights"
     "</command-message>", "Book Vegas flights"),
    ("[Workspace::v1: /private/project]\n"
     '[IMPORTANT: The user has invoked the "travel" skill. '
     'The full skill content is loaded below.]\n# Travel skill\n'
     "The user has provided the following instruction alongside the skill invocation: "
     "Book Vegas flights", "/travel — Book Vegas flights"),
    ("[BG3] Rescue the wolf", "[BG3] Rescue the wolf"),
    ("Explain the literal [screenshot] marker", "Explain the literal [screenshot] marker"),
    ("Explain [screenshot]", "Explain [screenshot]"),
    ("Fix [Workspace::v1: /tmp] parsing", "Fix [Workspace::v1: /tmp] parsing"),
    ("[Workspace: my own note] Book flights", "[Workspace: my own note] Book flights"),
    ("[Workspace::v1: /unfinished\nBook flights", "[Workspace::v1: /unfinished\nBook flights"),
    ("Explain [Attached files: example] syntax", "Explain [Attached files: example] syntax"),
    ("Book Vegas flights\nKeep dates flexible", "Book Vegas flights\nKeep dates flexible"),
    ("[Workspace::v1: /private/project]\n南京市秦淮区天气预报", "南京市秦淮区天气预报"),
])
def test_title_paths_use_same_clean_input(monkeypatch, wrapped, clean):
    response = SimpleNamespace(choices=[SimpleNamespace(
        message=SimpleNamespace(content='{"tag":"Travel","name":"Airline fares"}')
    )])
    call = Mock(return_value=response)
    monkeypatch.setattr(titles, "call_llm", call)

    assert titles.generate_title(wrapped) == "[Travel] Airline fares"
    assert call.call_args.kwargs["messages"][1]["content"] == clean[:titles.MAX_TITLE_INPUT_CHARS]
    assert titles.derive_title(wrapped) == titles.derive_title(clean)
    assert titles.is_titleable_user_message(wrapped)


@pytest.mark.parametrize("message", [
    "[Workspace::v1: /private/project]",
    "[1 image] [Workspace::v1: /private/project]\n\n[Attached files: /tmp/photo.png]\n[screenshot]",
    "[2 images]\n[screenshot]\n[screenshot]",
    "[Attached files: /tmp/report.pdf]",
    "[Workspace::v1: /private/project]\n[CONTEXT COMPACTION — REFERENCE ONLY] old context",
    "[1 image] [Workspace::v1: /private/project]\n[Runtime note: resumed from checkpoint]",
])
def test_metadata_cannot_create_a_title_or_consume_opening_turn(monkeypatch, tmp_path, message):
    from hermes_state import SessionDB

    start = Mock()
    monkeypatch.setattr(titles.threading, "Thread", start)
    with SessionDB(tmp_path / "state.db") as db:
        db.create_session(session_id="metadata-test", source="webui")
        titles.maybe_auto_title(db, "metadata-test", message, [])
        assert not titles.is_titleable_user_message(message)
        assert db.get_session_title("metadata-test") is None
        start.assert_not_called()
        titles.maybe_auto_title(db, "metadata-test", "Book Vegas flights", [
            {"role": "user", "content": message},
            {"role": "user", "content": "Book Vegas flights"},
        ])
        assert db.get_session_title("metadata-test") == "Book Vegas flights"
        start.assert_called_once()
