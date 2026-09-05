"""Sibling-site coverage for the reasoning-effort wire-vocabulary class (#89503).

The chat-completions chokepoint fix (ultra → max for every model) is covered
by tests/agent/test_reasoning_effort_wire_translation.py. These tests pin the
sibling sites fixed in the same sweep:

- Kimi/Moonshot top-level ``reasoning_effort``: K3 accepts low/high/max only
  (docs: default high); K2-era models accept low/medium/high. Previously the
  transport forwarded only {low,medium,high} and silently dropped everything
  else to "medium", so K3 400'd on "medium" requests and ultra resolved
  WEAKER than an explicit high (ladder inversion).
- Tencent TokenHub: accepts low/medium/high; upper-ladder levels previously
  dropped to the "high" default (accidentally right) but "minimal" also
  dropped to high — asked for the least, got the most.
- Codex/Responses transport: ultra → max for EVERY model, not just gpt-5.6.
"""

from agent.transports import get_transport
import agent.transports.chat_completions  # noqa: F401
import agent.transports.codex  # noqa: F401


def _cc():
    return get_transport("chat_completions")


def _kimi_kwargs(model, reasoning_config):
    return _cc().build_kwargs(
        model=model,
        messages=[{"role": "user", "content": "hi"}],
        is_kimi=True,
        reasoning_config=reasoning_config,
    )


class TestKimiEffortVocabulary:
    def test_k3_maps_full_hermes_ladder(self):
        expected = {
            "minimal": "low",
            "low": "low",
            "medium": "high",
            "high": "high",
            "xhigh": "max",
            "max": "max",
            "ultra": "max",
        }
        for hermes_level, wire_level in expected.items():
            kw = _kimi_kwargs(
                "kimi-k3", {"enabled": True, "effort": hermes_level}
            )
            assert kw["reasoning_effort"] == wire_level, hermes_level

    def test_k3_default_is_high(self):
        kw = _kimi_kwargs("kimi-k3", None)
        assert kw["reasoning_effort"] == "high"

    def test_k2_upper_ladder_caps_at_high_not_medium(self):
        """Pre-fix, ultra/max/xhigh on K2-era models silently dropped to the
        'medium' default — the strongest ask resolved weaker than an explicit
        high (ladder inversion, same class as #74295)."""
        for level in ("xhigh", "max", "ultra"):
            kw = _kimi_kwargs(
                "moonshotai/kimi-k2.6", {"enabled": True, "effort": level}
            )
            assert kw["reasoning_effort"] == "high", level

    def test_k2_native_levels_pass_through(self):
        for level in ("low", "medium", "high"):
            kw = _kimi_kwargs(
                "moonshotai/kimi-k2.6", {"enabled": True, "effort": level}
            )
            assert kw["reasoning_effort"] == level

    def test_k2_minimal_maps_to_low(self):
        kw = _kimi_kwargs(
            "moonshotai/kimi-k2.6", {"enabled": True, "effort": "minimal"}
        )
        assert kw["reasoning_effort"] == "low"

    def test_disabled_omits_effort(self):
        kw = _kimi_kwargs("kimi-k3", {"enabled": False})
        assert "reasoning_effort" not in kw


class TestTokenHubEffortVocabulary:
    def _kwargs(self, reasoning_config):
        return _cc().build_kwargs(
            model="hunyuan-t2",
            messages=[{"role": "user", "content": "hi"}],
            is_tokenhub=True,
            reasoning_config=reasoning_config,
        )

    def test_upper_ladder_caps_at_high(self):
        for level in ("xhigh", "max", "ultra"):
            kw = self._kwargs({"enabled": True, "effort": level})
            assert kw["reasoning_effort"] == "high", level

    def test_minimal_maps_to_low_not_high(self):
        """Pre-fix, 'minimal' fell through to the 'high' default — asked for
        the least reasoning, got the most."""
        kw = self._kwargs({"enabled": True, "effort": "minimal"})
        assert kw["reasoning_effort"] == "low"

    def test_native_levels_pass_through(self):
        for level in ("low", "medium", "high"):
            kw = self._kwargs({"enabled": True, "effort": level})
            assert kw["reasoning_effort"] == level


class TestCodexUltraForEveryModel:
    def test_ultra_never_leaks_and_respects_per_model_ceiling(self):
        """'ultra' must never reach the Codex wire. Live-verified vocabulary
        (#68365): gpt-5.6 accepts max (its ceiling), gpt-5.5/o5 do not —
        their ceiling is xhigh."""
        transport = get_transport("codex_responses")
        expected = {
            "gpt-5.6-codex": "max",
            "o5-pro": "xhigh",
            "gpt-5.5": "xhigh",
            "some-responses-model": "xhigh",
        }
        for model, wire in expected.items():
            kw = transport.build_kwargs(
                model=model,
                messages=[{"role": "user", "content": "hi"}],
                tools=[],
                reasoning_config={"enabled": True, "effort": "ultra"},
            )
            assert kw["reasoning"]["effort"] == wire, model


class TestGithubResponsesEffortVocabulary:
    """GitHub Models (Copilot) codex_responses: catalog-declared effort sets
    are advisory, not authoritative.

    The GitHub model catalog advertises ``minimal`` for gpt-5.6-sol
    (verified 2026-09-04) but the live backend rejects it with HTTP 400
    "unsupported value: 'minimal' is not supported with the
    'gpt-5.6-sol-2026-07-09' model" — while ``xhigh``/``max``, absent from
    the catalog, ARE accepted. Pre-fix, the transport forwarded the
    catalog-declared dict verbatim, so a session configured with
    ``reasoning_effort: minimal`` 400'd on its first request and dragged the
    fallback chain onto the next model, and a session configured with
    ``xhigh`` was silently downgraded to ``medium`` (nearest catalog entry).

    Fix: clamp the catalog-sourced effort against the same live-verified
    per-model vocabulary (``codex_supported_efforts``) every other branch on
    this wire uses. Catalog remains the source for *whether* reasoning is
    configured at all; the shared clamp owns the *level*.
    """

    def _kwargs(self, model, reasoning_config, github_extra):
        return get_transport("codex_responses").build_kwargs(
            model=model,
            messages=[{"role": "user", "content": "hi"}],
            tools=[],
            is_github_responses=True,
            reasoning_config=reasoning_config,
            github_reasoning_extra=github_extra,
        )

    def test_minimal_from_catalog_clamps_to_low(self):
        """Regression: catalog advertises minimal for gpt-5.6-sol, endpoint
        rejects it. Must clamp to the nearest weaker supported level."""
        kw = self._kwargs(
            "gpt-5.6-sol",
            {"enabled": True, "effort": "minimal"},
            {"effort": "minimal"},
        )
        assert kw["reasoning"]["effort"] == "low"

    def test_xhigh_not_in_catalog_survives_via_shared_clamp(self):
        """Regression (silent downgrade): catalog for gpt-5.6-sol lacks
        xhigh, but the endpoint accepts it. The shared vocabulary must win
        over the catalog's shorter list."""
        kw = self._kwargs(
            "gpt-5.6-sol",
            {"enabled": True, "effort": "xhigh"},
            {"effort": "medium"},
        )
        assert kw["reasoning"]["effort"] == "xhigh"

    def test_max_gpt56_passes_through(self):
        kw = self._kwargs(
            "gpt-5.6-sol",
            {"enabled": True, "effort": "max"},
            {"effort": "high"},
        )
        assert kw["reasoning"]["effort"] == "max"

    def test_ultra_never_reaches_github_wire(self):
        kw = self._kwargs(
            "gpt-5.6-sol",
            {"enabled": True, "effort": "ultra"},
            {"effort": "medium"},
        )
        assert kw["reasoning"]["effort"] == "max"

    def test_legacy_model_caps_at_xhigh(self):
        """Non-5.6 GitHub Models models keep the legacy vocabulary."""
        kw = self._kwargs(
            "gpt-5.5",
            {"enabled": True, "effort": "max"},
            {"effort": "max"},
        )
        assert kw["reasoning"]["effort"] == "xhigh"

    def test_none_effort_preserved(self):
        """Explicit disable must not be re-enabled by clamping."""
        kw = self._kwargs(
            "gpt-5.6-sol",
            {"enabled": True, "effort": "none"},
            {"effort": "none"},
        )
        assert kw["reasoning"]["effort"] == "none"

    def test_missing_github_extra_omits_reasoning_fail_closed(self):
        """Catalog-silent model (no reasoning_effort data at all): the
        ``reasoning`` key is omitted entirely. Fail-closed — without catalog
        evidence the endpoint supports the parameter, sending it risks a
        400 on non-reasoning GitHub Models. Unset stays unset; the shared
        clamp never invents a request (agent/reasoning_effort.py rule 2)."""
        kw = self._kwargs(
            "gpt-5.6-sol",
            {"enabled": True, "effort": "minimal"},
            None,
        )
        assert "reasoning" not in kw
