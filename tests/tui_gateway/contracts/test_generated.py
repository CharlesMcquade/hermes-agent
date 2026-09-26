"""The committed TypeScript + OpenRPC contract files are exactly what ``tui_gateway/contracts``
renders, and the contract catalog covers the whole wire.

Regenerate with ``.venv/bin/python scripts/gen_gateway_contracts.py`` when a model changes. The
two files are listed in ``scripts/ci/classify_changes.py::_PY_RELEVANT_CONTRACT_FILES`` so a
TS-only PR that edits them still runs this test.
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
GEN = REPO / "scripts" / "gen_gateway_contracts.py"


@pytest.fixture(scope="module")
def gen():
    spec = importlib.util.spec_from_file_location("gen_gateway_contracts", GEN)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_generated_files_are_current(gen):
    """Both committed artefacts equal an in-memory regeneration (byte-for-byte)."""
    stale = [path.relative_to(REPO) for path, text in gen.render_all().items()
             if (path.read_text(encoding="utf-8") if path.exists() else None) != text]
    assert not stale, f"stale generated contract files {stale}: run scripts/gen_gateway_contracts.py"


# The emitter inventory the old gateway-events.json scan used, kept as the completeness oracle:
# names must come from CODE the gateway runs, never from the contract tables themselves.
_EMIT_HELPERS = ("_emit", "_broadcast_global_event", "_voice_emit", "_pet_emit", "_emit_tool_lifecycle")
_LITERAL_EMIT = re.compile(r"\b(?:%s)\(\s*\"([a-z_][a-z0-9_.]*)\"" % "|".join(_EMIT_HELPERS))
_REQUEST_HELPERS = ("server_requests\\.send", "server_requests\\.send_async", "_ask", "_read_block")
_LITERAL_REQUEST = re.compile(r"\b(?:%s)\(\s*\"([a-z_][a-z0-9_.]*)\"" % "|".join(_REQUEST_HELPERS))
_LITERAL_FRAME = re.compile(r"\"method\":\s*\"event\".{0,120}?\"type\":\s*\"([a-z_][a-z0-9_.]*)\"", re.S)
_SIDE_AGENT = re.compile(r"_spawn_side_agent\((?:[^()]|\([^()]*\))*?\"([a-z_][a-z0-9_.]*\.complete)\"", re.S)
_SUBAGENT_RELAY = re.compile(r"\"(subagent\.[a-z_]+)\"")
_DESKTOP_UI_EMIT = re.compile(r"desktop_ui\.(?:emit|emit_or_error)\(\s*\"([a-z_][a-z0-9_.]*)\"")
_BROKER_FRAME = re.compile(r"^FRAME_[A-Z_]+ = \"(browser\.controller\.[a-z_]+)\"", re.M)
_SETUP_READY = re.compile(r"^SETUP_READY_EVENT = \"([a-z_.]+)\"", re.M)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def emitted_event_names() -> set[str]:
    names: set[str] = set()
    for src in (REPO / "tui_gateway").glob("*.py"):
        text = _read(src)
        names.update(_LITERAL_EMIT.findall(text))
        names.update(_LITERAL_FRAME.findall(text))
        names.update(_SIDE_AGENT.findall(text))
    from tui_gateway.agent_callbacks import _CHILD_DELTA_EVENTS
    from tui_gateway.change_watcher import _CHANGE_WATCHES

    names.update(_CHANGE_WATCHES)
    names.update(_CHILD_DELTA_EVENTS.values())
    for src in (REPO / "tools").glob("delegate_tool*.py"):
        names.update(_SUBAGENT_RELAY.findall(_read(src)))
    names.discard("subagent.text")  # mirrored into the watch window as message.delta, never emitted
    from tools.registry import _tool_module_candidates

    for src in _tool_module_candidates(REPO / "tools"):
        names.update(_DESKTOP_UI_EMIT.findall(_read(src)))
    names.update(_BROKER_FRAME.findall(_read(REPO / "gateway" / "browser_control_broker.py")))
    names.update(_SETUP_READY.findall(_read(REPO / "hermes_cli" / "free_tier_bootstrap.py")))
    return names


def sent_server_requests() -> set[str]:
    names: set[str] = set()
    for src in (REPO / "tui_gateway").glob("*.py"):
        names.update(_LITERAL_REQUEST.findall(_read(src)))
    return names


def test_cdp_relay_contract_matches_registry_rows_and_rejects_unknown_params():
    from tui_gateway.cdp_relay import CdpRelayRegistry
    from tui_gateway.contracts import METHODS, registry

    transport = object()
    relays = CdpRelayRegistry()
    relay_id = relays.register(transport, peer="extension")
    registered = METHODS["cdp.register"]
    listed = METHODS["cdp.listRelays"]
    registry.check_params_accepted(registered, {})
    registry.check_params_accepted(listed, {})
    assert registry.validate_params(registered, {"relay_id": relay_id})[1] is not None
    assert registry.validate_params(listed, {"peer": "extension"})[1] is not None
    registry.check_result(registered, {"relay_id": relay_id, "status": "registered"})
    registry.check_result(listed, {"relays": relays.list_relays()})
    assert listed.result.model_validate({"relays": relays.list_relays()}).model_dump()["relays"][0]["relay_id"] == relay_id


def test_catalog_covers_the_whole_wire():
    """Every registered method, every emitted event and every sent server request has a contract,
    and no contract is orphaned (a deleted handler must take its contract with it)."""
    from tui_gateway import server
    from tui_gateway.contracts import registry

    registry.assert_complete(server._methods, emitted_event_names(), sent_server_requests())
