"""The model cannot expand the taxonomy or persist an invalid upgrade."""

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
        assert all(a != b for a, b in zip(roles, roles[1:]))


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
