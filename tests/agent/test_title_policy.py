"""Topic-prefixed model titles stay useful without a closed tag registry."""

import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from agent.title_generator import auto_title_session, generate_title
from hermes_state import SessionDB


def response(content):
    return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=content))])


@pytest.mark.parametrize(
    "opening,raw,expected",
    [
        (
            "Crimson Desert -- where is this recipe in Hernand Inn?",
            '{"title":"[CrimsonDesert] Hernand Inn recipe location"}',
            "[CrimsonDesert] Hernand Inn recipe location",
        ),
        (
            "Conclusion of Texas midterms, across all seats?",
            '{"title":"[Politics] Texas midterm results"}',
            "[Politics] Texas midterm results",
        ),
        (
            "How is OOT Remake recompilation progressing?",
            '{"title":"[OOT] Ocarina recompilation status"}',
            "[OOT] Ocarina recompilation status",
        ),
        (
            "Research the history of regional folk costumes",
            '{"title":"[Research] Regional folk costume history"}',
            "[Research] Regional folk costume history",
        ),
        (
            "Recent session, validate answers for my MSAI quiz",
            '{"tag":"Education","name":"Quiz answer validation"}',
            "[Education] Quiz answer validation",
        ),
        (
            "Fix title tagging",
            '```json\n{"title":"[Hermes] Fix title tagging"}\n```',
            "[Hermes] Fix title tagging",
        ),
        (
            "Fix title tagging",
            'Title: "[Hermes] Fix title tagging."',
            "[Hermes] Fix title tagging",
        ),
        (
            "天气预报",
            '{"title":"[Shop] 小时级天气预报"}',
            "[Shop] 小时级天气预报",
        ),
    ],
)
def test_open_vocabulary_titles_use_single_call(opening, raw, expected):
    with patch("agent.title_generator.call_llm", return_value=response(raw)) as llm:
        assert generate_title(opening) == expected

    assert llm.call_count == 1
    schema = llm.call_args.kwargs["extra_body"]["response_format"]["json_schema"]["schema"]
    assert set(schema["properties"]) == {"title"}
    assert "enum" not in schema["properties"]["title"]


@pytest.mark.parametrize(
    "raw",
    [
        "Untagged title",
        "[Politics]",
        "[Politics][Education] Two categories",
        "[Politics] one two three four five six seven",
        '{"title":"[Politics] Election results"',
        '{"tag":"Politics","name":null}',
        '{"title":"[Politics] Results","name":"Conflict"}',
        '{"title":"[Politics] Results","title":"[Education] Duplicate"}',
        "[Politics] Results\nHere is why I chose this",
        "[Politics] Bad\u0000title",
        "",
    ],
)
def test_invalid_output_ends_after_one_call(raw):
    with patch("agent.title_generator.call_llm", return_value=response(raw)) as llm:
        assert generate_title("Explain the latest election results") is None
    assert llm.call_count == 1


@pytest.mark.parametrize("tag", ["Misc", "Chat", "Question", "Other", "General", "G"])
def test_vague_topic_prefixes_are_rejected(tag):
    from agent.title_policy import normalize_title

    assert normalize_title(f'{{"title":"[{tag}] General discussion"}}') is None


def test_specific_prefix_is_not_rewritten_or_bounded_by_registry():
    from agent.title_policy import normalize_title

    assert normalize_title(
        '{"title":"[Local History] Enclave fiber expansion"}'
    ) == "[Local History] Enclave fiber expansion"


@pytest.mark.parametrize("ending", ["invalid", "error"])
def test_single_attempt_preserves_fallback_and_manual_authority(tmp_path, ending):
    db = SessionDB(tmp_path / "state.db")
    try:
        for session_id in ("auto", "manual"):
            db.create_session(session_id=session_id, source="cli")
        db.set_auto_title("auto", "Fix Hermes tags", source="derived")
        db.set_session_title("manual", "My chosen title")
        invalid = response("No category tag")
        last = RuntimeError("backend unavailable") if ending == "error" else invalid
        failures = []
        with patch("agent.title_generator.call_llm", side_effect=[invalid, last]) as llm:
            auto_title_session(
                db,
                "auto",
                "Fix Hermes tags",
                failure_callback=lambda task, exc: failures.append((task, exc)),
            )
            auto_title_session(db, "manual", "Fix Hermes tags")

        assert llm.call_count == 1
        assert db.get_session_title("auto") == "Fix Hermes tags"
        assert db.get_session_title_source("auto") == "derived"
        assert db.get_session_title("manual") == "My chosen title"
        assert len(failures) == 1
    finally:
        db.close()


def test_runtime_validator_skips_the_only_call_without_recording_failure(tmp_path):
    db = SessionDB(tmp_path / "state.db")
    try:
        db.create_session(session_id="auto", source="cli")
        db.set_auto_title("auto", "Existing provisional title", source="derived")
        failures = []
        with patch("agent.title_generator.call_llm") as llm:
            auto_title_session(
                db,
                "auto",
                "Fix Hermes tags",
                runtime_validator=lambda: False,
                failure_callback=lambda task, exc: failures.append((task, exc)),
            )

        assert llm.call_count == 0
        assert failures == []
        assert db.get_session_title("auto") == "Existing provisional title"
        assert db.get_session_title_source("auto") == "derived"
    finally:
        db.close()


@pytest.mark.parametrize(
    "opening",
    [
        "I voted early today Travis county but I only had candidates on the ballot no propositions",
        "Is Raspberry Pi inaccessible to SSH again?",
        "How much of a PITA is the new E:D community goal?",
        "Please check both fantasy teams and optimize my lineup",
        "Why is the canary ping failing?",
        "Please investigate why 'reply with exactly X' prompts fail",
        "Explain the test input: Reply with exactly X",
    ],
)
def test_real_requests_cannot_be_labeled_as_probe(opening):
    from agent.title_policy import normalize_title

    assert normalize_title('{"title":"[Test] Bare echo acknowledgment"}', opening) is None
    assert normalize_title('{"title":"[Politics] Early voting ballot"}', opening) == (
        "[Politics] Early voting ballot"
    )


@pytest.mark.parametrize(
    "opening",
    [
        "Reply with exactly: CANARY-OK",
        "PPC canary ping - please reply with exactly: CANARY-OK",
        "Acknowledge request",
        "Smoke test from Verity Sidecar. Reply with exactly: sidecar-ok",
    ],
)
def test_explicit_canned_response_probes_keep_test_tag(opening):
    from agent.title_policy import normalize_title

    assert normalize_title('{"title":"[Test] Canned response check"}', opening) == (
        "[Test] Canned response check"
    )


def test_quoted_title_echo_is_rejected_but_the_task_titles():
    from agent.title_policy import normalize_title

    opening = "Recent session, validate answers: [Codex] Async delegation batch result #8"
    assert normalize_title(
        '{"title":"[Codex] Async delegation batch result #8"}', opening
    ) is None
    assert normalize_title(
        '{"title":"[Codex] Async delegation batch result 8"}', opening
    ) is None
    assert normalize_title(
        json.dumps({"title": "[Education] Quiz answer validation"}), opening
    ) == "[Education] Quiz answer validation"
