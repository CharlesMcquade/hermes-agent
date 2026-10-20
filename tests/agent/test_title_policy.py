"""The model cannot expand the taxonomy or persist an invalid upgrade."""

import itertools
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
        ("Gaming news", '[Gaming] Release roundup', '[G] Release roundup'),
        ("Gothic remake news", '[G] Gothic remake news', '[Gothic] Gothic remake news'),
        ("Crimson Desert combat", '[Crimson Desert] Combat guide', '[CrimsonDesert] Combat guide'),
        ("Subnautica 2 release", '[G] Subnautica 2 release', '[Subnautica2] Subnautica 2 release'),
        ("Final Fantasy VII Rebirth builds", '[Final Fantasy VII Rebirth] Party builds', '[FF7Rebirth] Party builds'),
        ("FF7 Rebirth builds", '[G] FF7 Rebirth party builds', '[FF7Rebirth] FF7 Rebirth party builds'),
        ("Tainted Grail shader fix", '[G] Tainted Grail shader fix', '[TGFoA] Tainted Grail shader fix'),
        ("Fall of Avalon build guide", '[G] Fall of Avalon builds', '[TGFoA] Fall of Avalon builds'),
        ("Witcher 3 mod cleanup", '[G] Witcher 3 mod cleanup', '[W3] Witcher 3 mod cleanup'),
        ("Black Flag ending recap", '[G] Black Flag ending recap', '[ACBlackFlag] Black Flag ending recap'),
        ("UT MSAI course schedule", '{"tag":"Education","name":"MSAI course schedule"}', '[Education] MSAI course schedule'),
        ("Trump policy effect research", '{"tag":"Misc","name":"Policy research"}', '[Misc] Policy research'),
        ("Fantasy football waivers", '[FF] Week 2 waivers', '[FF] Week 2 waivers'),
        ("Hermes Gothic title fixtures", '[Hermes] Gothic title fixtures', '[Hermes] Gothic title fixtures'),
        ("Switch performance", '[G] Switch performance', '[G] Switch performance'),
        ("Marvel news", '[G] Marvel news', '[G] Marvel news'),
        ("Compare Starfield and Skyrim", '[G] Skyrim mod comparisons', '[G] Skyrim mod comparisons'),
        ("Fix titles", '{"tag":"Tech","tag":"Hermes","name":"Fix titles"}', None),
        ("Fix titles", '{"tag":"Hermes","name":"Wrong","name":"Fix titles"}', None),
        ("Family reminders", '{"title":"[Family] School reminders"}', '[Fam] School reminders'),
        ("Book Vegas bachelor party hotels", '{"tag":"Travel","name":"Vegas bachelor party booking"}', '[Travel] Vegas bachelor party booking'),
        ("Fix ImprovedCameraSF for Starfield", '[Gaming] ImprovedCameraSF fix', '[Starfield] ImprovedCameraSF fix'),
        ("Starfield mod help", '[Starfield] Camera mod setup', '[Starfield] Camera mod setup'),
        ("Fix ImprovedCameraSF", '[Skyrim] ImprovedCameraSF repair', '[Starfield] ImprovedCameraSF repair'),
        ("Fix Hermes tagging for ImprovedCameraSF", '[Hermes] ImprovedCameraSF title tagging', '[Hermes] ImprovedCameraSF title tagging'),
        ("Research models; I played Skyrim yesterday", '[LLM] Model research', '[LLM] Model research'),
        ("BOTW performance on Switch", '[Breath of the Wild] Switch performance', '[BOTW] Switch performance'),
        ("Marvel Wolverine PS5 impressions", '[Marvel’s Wolverine] PS5 impressions', '[Wolverine] PS5 impressions'),
        ("WARDOGS game hype", '[War Dogs] Game hype', '[WARDOGS] Game hype'),
        ("War Dogs hype", '[Gaming] War Dogs hype', '[WARDOGS] War Dogs hype'),
        ("BOTW performance on Switch", '[G] BOTW Switch performance', '[BOTW] BOTW Switch performance'),
        ("Skyrim mod setup", '[Skyrim] Camera mod setup', '[Skyrim] Camera mod setup'),
        ("Fix Hermes title tagging for Starfield", '[Hermes] Starfield title tagging', '[Hermes] Starfield title tagging'),
        ("Research an LLM with a Wolverine codename", '[LLM] Wolverine benchmark research', '[LLM] Wolverine benchmark research'),
        ("Compare Starfield and Skyrim mods", '[G] Starfield and Skyrim mods', '[G] Starfield and Skyrim mods'),
        ("GPU performance; I played BOTW yesterday", '[Tech] GPU performance comparison', '[Tech] GPU performance comparison'),
        ("Unknown game news", '[G] Unknown game news', '[G] Unknown game news'),
        ("Fix Hermes", '```json\n{"tag":"hermes","name":"Fix title tagging"}\n```', '[Hermes] Fix title tagging'),
        ("Fix Hermes", '<think>Private thoughts</think>[Hermes] Fix title tagging', '[Hermes] Fix title tagging'),
        ("Fix Hermes", 'Title: "[Hermes] Fix title tagging."', '[Hermes] Fix title tagging'),
        ("天气预报", '{"tag":"Shop","name":"小时级天气预报"}', '[Shop] 小时级天气预报'),
        ("Fix titles", 'Untagged title', None),
        ("Fix titles", '[Invented] Coined category', None),
        ("Fix titles", '[Hermes]', None),
        ("Fix titles", '[Hermes][Tech] Two categories', None),
        ("Fix titles", '[Hermes] one two three four five six seven', None),
        ("Fix titles", '[Hermes] ' + 'A' * 81, None),
        ("Fix titles", '{"title":"[Hermes] Fix titles"', None),
        ("Fix titles", '{"tag":"Hermes","name":null}', None),
        ("Fix titles", '{"tag":"Hermes","name":"[Tech] Wrong tag"}', None),
        ("Fix titles", '{"tag":"Hermes","name":"Fix titles","title":"[Tech] Conflict"}', None),
        ("Fix titles", '[Hermes] Fix titles\nHere is why I chose this', None),
        ("Fix titles", '[Hermes] Fix\u0000 titles', None),
        ("Fix titles", '', None),
    ],
)
def test_only_canonical_short_titles_can_be_upgraded(opening, raw, expected):
    with patch('agent.title_generator.call_llm', return_value=response(raw)) as llm:
        assert generate_title(opening) == expected
    assert llm.call_count == (1 if expected else 2)
    from agent.title_policy import CANONICAL_TAGS

    for call in llm.call_args_list:
        schema = call.kwargs['extra_body']['response_format']['json_schema']['schema']
        assert set(schema['properties']['tag']['enum']) == set(CANONICAL_TAGS)
        roles = [message['role'] for message in call.kwargs['messages']]
        assert all(a != b for a, b in itertools.pairwise(roles))


@pytest.mark.parametrize('ending', ['valid', 'invalid', 'error', 'stale'])
def test_bounded_repair_preserves_fallback_and_manual_authority(tmp_path, ending):
    db = SessionDB(tmp_path / 'state.db')
    try:
        for session_id in ('auto', 'manual'):
            db.create_session(session_id=session_id, source='cli')
        db.set_auto_title('auto', 'Fix Hermes tags', source='derived')
        db.set_session_title('manual', 'My chosen title')
        invalid = response('No category tag')
        last = {
            'valid': response(json.dumps({'tag': 'Hermes', 'name': 'Fix category tags'})),
            'invalid': invalid,
            'error': RuntimeError('backend unavailable'),
            'stale': invalid,
        }[ending]
        failures = []
        validator = iter([True, ending != 'stale'])
        with patch('agent.title_generator.call_llm', side_effect=[invalid, last]) as llm:
            auto_title_session(
                db, 'auto', 'Fix Hermes tags',
                runtime_validator=lambda: next(validator),
                failure_callback=lambda task, exc: failures.append((task, exc)),
            )
            auto_title_session(db, 'manual', 'Fix Hermes tags')
        assert llm.call_count == (1 if ending == 'stale' else 2)
        assert db.get_session_title('manual') == 'My chosen title'
        if ending == 'valid':
            assert db.get_session_title('auto') == '[Hermes] Fix category tags'
            assert db.get_session_title_source('auto') == 'llm'
        else:
            assert db.get_session_title('auto') == 'Fix Hermes tags'
            assert db.get_session_title_source('auto') == 'derived'
        assert len(failures) == (1 if ending in ('invalid', 'error') else 0)
    finally:
        db.close()


@pytest.mark.parametrize("opening", [
    "I voted early today Travis county but I only had candidates on the ballot no propositions",
    "Is Raspberry Pi inaccessible to SSH again?",
    "How much of a PITA is the new E:D community goal?",
    "Please check both fantasy teams and optimize my lineup",
    "Why is the canary ping failing?",
    "Please investigate why 'reply with exactly X' prompts fail",
    "Explain the test input: Reply with exactly X",
])
def test_real_requests_cannot_be_labeled_as_probe(opening):
    from agent.title_policy import normalize_title

    assert normalize_title('{"tag":"Test","name":"Bare echo acknowledgment"}', opening) is None
    assert normalize_title('{"tag":"Misc","name":"Early voting ballot"}', opening) == "[Misc] Early voting ballot"


@pytest.mark.parametrize("opening", [
    "Reply with exactly: CANARY-OK",
    "PPC canary ping - please reply with exactly: CANARY-OK",
    "Acknowledge request",
    "Smoke test from Verity Sidecar. Reply with exactly: sidecar-ok",
])
def test_explicit_canned_response_probes_keep_test_tag(opening):
    from agent.title_policy import normalize_title

    assert normalize_title('{"tag":"Test","name":"Canned response check"}', opening) == "[Test] Canned response check"


def test_repair_repeats_original_request_not_the_feedback():
    opener = "I voted early today Travis county but I only had candidates on the ballot no propositions"
    outputs = [response('{"tag":"Election","name":"Early voting ballot"}'),
               response('{"tag":"Misc","name":"Early voting ballot"}')]
    with patch('agent.title_generator.call_llm', side_effect=outputs) as llm:
        assert generate_title(opener) == "[Misc] Early voting ballot"
    repair_messages = llm.call_args_list[1].kwargs['messages']
    assert repair_messages[-1]['role'] == 'user'
    assert opener in repair_messages[-1]['content']
    assert "not this correction" in repair_messages[-1]['content'].lower()
    assert "never real questions" in repair_messages[-1]['content'].lower()


def test_prompt_routes_human_greetings_away_from_test():
    """A human greeting is small talk ([Fam]); [Test] is machine probes only.

    Regression: 'ayyy, what's good?' was titled '[Test] Bare echo
    acknowledgment probe' because the Test rule ('no real question or work')
    also matched taskless greetings, and the model parroted the registry
    description as the name.
    """
    from agent.title_policy import TAG_DESCRIPTIONS, title_prompt

    prompt = title_prompt()
    assert "machine/scripted probe" in prompt
    assert "human greeting or small talk with no task is Fam, NOT Test" in prompt
    assert "'ayyy, what's good?' -> Fam" in prompt
    assert "bare human greetings and small talk" in TAG_DESCRIPTIONS["Fam"]
    assert "never a human greeting or small talk" in TAG_DESCRIPTIONS["Test"]


def test_prompt_rejects_quoted_session_title_echo():
    """A bracketed '[Tag] Name' span inside the message quotes ANOTHER session.
    Regression: opening with 'Recent session, validate answers: [Codex] Async
    delegation batch result #8' got the quiz session retitled '[Codex] Async
    delegation batch result 8' although its real work was MSAI quiz validation."""
    from agent.title_policy import title_prompt

    prompt = title_prompt()
    assert "Never copy or echo a quoted bracketed title" in prompt
    assert "Async delegation batch result" in prompt


def test_quoted_title_echo_is_rejected_but_the_task_titles():
    """The validator backstops the prompt: a title copied from a bracketed span
    in the message is rejected (whitespace/case/'#'-tolerant), while a title
    naming the actual task passes."""
    from agent.title_policy import normalize_title

    opening = "Recent session, validate answers: [Codex] Async delegation batch result #8"
    # Verbatim echo of the quoted span.
    assert normalize_title('{"tag":"Codex","name":"Async delegation batch result #8"}', opening) is None
    # The '#'-tolerant echo the model actually produced.
    assert normalize_title('{"tag":"Codex","name":"Async delegation batch result 8"}', opening) is None
    # The actual task still titles normally.
    assert normalize_title(
        '{"tag":"Education","name":"Quiz answer validation"}', opening
    ) == "[Education] Quiz answer validation"
