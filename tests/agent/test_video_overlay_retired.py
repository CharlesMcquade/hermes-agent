"""R07 — dedicated auxiliary-video overlay retirement invariants.

The fork overlay (commit 6cdf140137, "aux video path") added a dedicated
``auxiliary.video`` task/auto-enrichment path on top of upstream's native
``video_analyze`` tool. Per plan §9 R07 + §18.3, the overlay is removed while
upstream's native video understanding (the ``video_analyze`` tool, toolset
``video``, ``_configured_aux_model(("video", "vision"), ...)`` env fallback
AUXILIARY_VIDEO_MODEL→AUXILIARY_VISION_MODEL, and the shared vision chain with
task="vision") is preserved.

These tests assert the negative (no dedicated video-task registration or
execution path) and the positive (upstream native video_analyze still
resolves; legacy ``auxiliary.video`` / ``agent.video_input_mode`` config keys
are read-compatible — inert, not a crash).
"""

import inspect
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]


# ---------------------------------------------------------------------------
# Negative: no dedicated video-task dispatch / registration path
# ---------------------------------------------------------------------------

def test_no_multimodal_video_task_set_in_auxiliary_client():
    """The overlay's _MULTIMODAL_AUX_TASKS {vision, video} task-set is gone.

    Upstream resolves video analysis through the shared vision chain
    (task="vision"); there is no dedicated auxiliary.video task identity.
    """
    import agent.auxiliary_client as ac

    assert not hasattr(ac, "_MULTIMODAL_AUX_TASKS")
    sig = inspect.signature(ac.resolve_vision_provider_client)
    assert "task" not in sig.parameters, (
        "resolve_vision_provider_client must not take an aux-task parameter "
        "(upstream hardcodes the vision chain)"
    )


def test_video_analyze_dispatches_via_vision_task_not_dedicated_video_task():
    """video_analyze must borrow the vision aux chain, not dispatch task="video"."""
    import tools.vision_tools as vt

    sig = inspect.signature(vt._aux_call_kwargs)
    assert "task" not in sig.parameters and "aux_task" not in sig.parameters
    v_sig = inspect.signature(vt.video_analyze_tool)
    assert "aux_task" not in v_sig.parameters

    # The shared vision chain is what video_analyze rides on.
    src = inspect.getsource(vt._aux_call_kwargs)
    assert '"task": "vision"' in src


def test_no_gateway_video_enrichment_hooks():
    """The run_inbound auto-enrichment methods and run_turn hook are removed."""
    import gateway.run_inbound as ri

    runner_cls = None
    for name in dir(ri):
        obj = getattr(ri, name)
        if inspect.isclass(obj) and any(
            hasattr(obj, attr)
            for attr in ("_enrich_inbound_videos", "_decide_video_enrichment_mode")
        ):
            runner_cls = obj
    assert runner_cls is None, (
        "gateway inbound video auto-enrichment overlay must be removed"
    )
    for method in ("_enrich_inbound_videos", "_enrich_message_with_video",
                   "_decide_video_enrichment_mode"):
        assert not hasattr(ri, method)

    run_turn_src = (PROJECT_ROOT / "gateway" / "run_turn.py").read_text()
    assert "_enrich_message_with_video" not in run_turn_src, (
        "run_turn background-task video enrichment hook must be removed"
    )
    inbound_src = (PROJECT_ROOT / "gateway" / "run_inbound.py").read_text()
    assert "video_input_mode" not in inbound_src


def test_video_input_mode_default_removed():
    """The overlay's agent.video_input_mode default is gone from DEFAULT_CONFIG."""
    from hermes_cli.config_defaults import DEFAULT_CONFIG

    assert "video_input_mode" not in DEFAULT_CONFIG.get("agent", {})


def test_no_source_consumer_of_legacy_video_overlay_config_keys():
    """No runtime source reads auxiliary.video or agent.video_input_mode.

    Source-scan non-reintroduction guard (shared-safety assertion replacing the
    retired overlay tests): a fork re-entry of the dedicated video task would
    re-add a consumer here.
    """
    legacy_tokens = ("video_input_mode", '"video"', "'video'")
    forbidden_aux_video = ('_cfg_auxiliary("video"', '"auxiliary", "video"')
    scan_roots = ["gateway", "agent", "tools", "hermes_cli"]
    for root in scan_roots:
        for path in (PROJECT_ROOT / root).rglob("*.py"):
            text = path.read_text(errors="replace")
            for token in forbidden_aux_video:
                assert token not in text, f"{path} reads auxiliary.video ({token})"
            if "video_gen" in path.name or "video_gen" in str(path):
                continue  # unrelated upstream video-generation tools
            if "video_input_mode" in text:
                raise AssertionError(
                    f"{path} consumes overlay key agent.video_input_mode"
                )
            for token in ('"video"', "'video'"):
                if token in text and ("auxiliary" in text and "task" in text):
                    # possible dedicated-task reference; require explicit
                    # dispatch evidence rather than a blanket ban
                    if "task=\"video\"" in text or "task='video'" in text:
                        raise AssertionError(
                            f"{path} dispatches a dedicated task=\"video\" aux call"
                        )


# ---------------------------------------------------------------------------
# Positive: upstream native video_analyze preserved
# ---------------------------------------------------------------------------

def test_upstream_native_video_analyze_tool_registration_preserved():
    from tools.registry import registry

    entry = registry.get_entry("video_analyze")
    assert entry is not None
    assert entry.toolset == "video"
    assert entry.is_async is True


def test_upstream_video_model_env_fallback_preserved():
    """_configured_aux_model(("video","vision"), AUXILIARY_VIDEO_MODEL→AUXILIARY_VISION_MODEL)."""
    import tools.vision_tools as vt

    src = inspect.getsource(vt.video_analyze_tool) + inspect.getsource(vt)
    assert '("video", "vision")' in src
    assert "AUXILIARY_VIDEO_MODEL" in src
    assert "AUXILIARY_VISION_MODEL" in src


def test_check_video_requirements_still_probes_vision_chain():
    """The vision-chain probe (upstream semantics) resolves without the overlay."""
    import tools.vision_tools as vt

    sig = inspect.signature(vt.check_video_requirements)
    assert sig.parameters == {}
    # Must not raise regardless of provider config; returns a bool.
    result = vt.check_video_requirements()
    assert isinstance(result, bool)


# ---------------------------------------------------------------------------
# Config read-compatibility: legacy keys are inert, not a crash
# ---------------------------------------------------------------------------

def test_legacy_aux_video_config_merges_without_error_and_is_inert():
    """An existing auxiliary.video / agent.video_input_mode config still loads.

    Read-compat contract: unknown/legacy overlay keys merge into the effective
    config without crashing, are simply carried through, and no default is
    re-introduced for them. No live config is written by this test.
    """
    from copy import deepcopy

    from hermes_cli.config import _deep_merge
    from hermes_cli.config_defaults import DEFAULT_CONFIG

    legacy = {
        "auxiliary": {
            "video": {
                "provider": "custom",
                "model": "legacy-video-model",
                "base_url": "http://localhost:1234/v1",
                "api_key": "legacy-key",
            }
        },
        "agent": {"video_input_mode": "text"},
    }
    merged = _deep_merge(deepcopy(DEFAULT_CONFIG), deepcopy(legacy))

    # Legacy values are preserved (readable for reporting), not dropped.
    assert merged["auxiliary"]["video"]["model"] == "legacy-video-model"
    assert merged["agent"]["video_input_mode"] == "text"
    # But the overlay default is gone: fresh installs don't get the key.
    assert "video_input_mode" not in DEFAULT_CONFIG["agent"]
