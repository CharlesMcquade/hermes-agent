"""W2-K06 — #61170 residual: @provider:model billing-input validation and
custom-endpoint org/model identity preservation in resolve_billing_route.

Synthetic only: no network, no real providers. models.dev / endpoint-metadata
lookups are stubbed so the only behaviors under test are the resolver's own.
"""

import pytest

import agent.usage_pricing as up
from agent.usage_pricing import (
    CanonicalUsage,
    BillingRoute,
    estimate_usage_cost,
    get_pricing_entry,
    resolve_billing_route,
)


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    """Keep every pricing lookup offline: bundled snapshot only."""
    monkeypatch.setattr("agent.models_dev.get_model_info", lambda *a, **k: None)
    monkeypatch.setattr(up, "fetch_endpoint_model_metadata", lambda *a, **k: {})


# ---------------------------------------------------------------- routed tokens

def test_routed_openai_token_matches_explicit_provider():
    routed = resolve_billing_route("@openai:gpt-4.1")
    explicit = resolve_billing_route("gpt-4.1", provider="openai")
    assert routed == explicit
    assert routed.billing_mode == "official_docs_snapshot"
    assert routed.provider == "openai"


def test_routed_openai_api_alias_supported():
    route = resolve_billing_route("@openai-api:gpt-4.1")
    assert route.provider == "openai"
    assert route.billing_mode == "official_docs_snapshot"


def test_routed_token_embedded_org_path_collapses_per_snapshot_semantics():
    """Named snapshot providers key on the last path segment (current resolver
    semantics); org/ prefixes are not model identity under a KNOWN provider."""
    route = resolve_billing_route("@openai:org/example/gpt-4.1")
    assert route.provider == "openai"
    assert route.model == "gpt-4.1"


def test_routed_custom_endpoint_preserves_org_model_identity():
    bare = resolve_billing_route("org/team/model:revision", provider="custom:example",
                                 base_url="https://proxy.example/v1")
    routed = resolve_billing_route("@custom:example:org/team/model:revision",
                                   base_url="https://proxy.example/v1")
    assert routed == bare
    assert routed.provider == "custom:example"
    assert routed.model == "org/team/model:revision"
    assert routed.billing_mode == "unknown"


def test_routed_custom_endpoint_matches_explicit_custom_named_provider():
    routed = resolve_billing_route("@custom:wandb:glm-5.2")
    explicit = resolve_billing_route("glm-5.2", provider="custom:wandb")
    assert routed == explicit


def test_routed_custom_bare_endpoint_keeps_custom_provider():
    routed = resolve_billing_route("@custom:glm-5.2")
    assert routed.provider == "custom"
    assert routed.model == "glm-5.2"
    assert routed.billing_mode == "unknown"


def test_routed_custom_full_path_not_collapsed():
    route = resolve_billing_route("@custom:example:org/x/y")
    assert route.provider == "custom:example"
    assert route.model == "org/x/y"


# ---------------------------------------------------------------- malformed tokens

@pytest.mark.parametrize("token", [
    "@openai",              # missing colon
    "@:gpt-4.1",            # empty provider
    "@openai:",             # empty model
    "@: :",                 # empty everything (colon only)
    "@openai:@gpt-4.1",     # second embedded '@' (conflicting embedded provider token)
    "@custom:a:@b",         # second embedded '@' inside a custom route
])
def test_malformed_tokens_stay_unknown_and_unrepaired(token):
    route = resolve_billing_route(token)
    assert route == BillingRoute(provider="unknown", model=token, base_url="", billing_mode="unknown")


def test_malformed_token_conflicting_explicit_provider_stays_unknown():
    route = resolve_billing_route("@openai:gpt-4.1", provider="anthropic")
    assert route.provider == "unknown"
    assert route.billing_mode == "unknown"
    assert route.model == "@openai:gpt-4.1"


def test_malformed_conflicting_custom_endpoint_stays_unknown():
    route = resolve_billing_route("@custom:other:model", provider="custom:wandb")
    assert route.provider == "unknown"
    assert route.billing_mode == "unknown"


def test_malformed_token_estimates_to_unknown_cost_not_invented_price():
    result = estimate_usage_cost("@openai:", CanonicalUsage(input_tokens=1000, output_tokens=1000))
    assert result.status == "unknown"
    assert result.amount_usd is None


def test_malformed_token_get_pricing_entry_is_none():
    assert get_pricing_entry("@:gpt-4.1") is None


# ---------------------------------------------------------------- explicit/implicit precedence

def test_explicit_provider_agreeing_with_token_wins_and_strips_prefix():
    route = resolve_billing_route("@openai:gpt-4.1", provider="openai")
    assert route.provider == "openai"
    assert route.model == "gpt-4.1"
    assert route.billing_mode == "official_docs_snapshot"


def test_bare_custom_declaration_compatible_with_named_custom_provider():
    route = resolve_billing_route("@custom:gpt-x", provider="custom:example")
    assert route.provider == "custom:example"
    assert route.model == "gpt-x"
    assert route.billing_mode == "unknown"


# ---------------------------------------------------------------- non-routed passthrough

def test_plain_model_name_unaffected():
    route = resolve_billing_route("gpt-4.1", provider="openai")
    assert route.provider == "openai"
    assert route.model == "gpt-4.1"


def test_slash_qualified_inference_unchanged():
    route = resolve_billing_route("anthropic/claude-sonnet-4")
    assert route.provider == "anthropic"
    assert route.model == "claude-sonnet-4"


def test_unknown_provider_slash_path_not_collapsed_to_known_provider():
    """org/model under an unresolvable provider must NOT be repaired into a
    known provider's model (no conflation of identically named models)."""
    route = resolve_billing_route("unknownorg/gpt-4.1")
    assert route.provider == "unknown"
    assert route.model == "unknownorg/gpt-4.1"


def test_custom_endpoint_slash_path_preserved_end_to_end():
    entry = get_pricing_entry("org/model", provider="custom:example", base_url="https://proxy.example/v1")
    assert entry is None  # unknown rate stays unknown; no invented price


# ---------------------------------------------------------------- cost accounting sanity

def test_known_pricing_still_estimates_after_validation_change():
    result = estimate_usage_cost("gpt-4.1", CanonicalUsage(input_tokens=1_000_000, output_tokens=0), provider="openai")
    assert result.status == "estimated"
    assert result.amount_usd is not None
    assert result.amount_usd > 0


def test_zero_usage_costs_zero_no_double_counting():
    result = estimate_usage_cost("@openai:gpt-4.1", CanonicalUsage(), provider="openai")
    assert result.status == "estimated"
    assert result.amount_usd == 0


# ---------------------------------------------------------------- insights consumer

def test_insights_estimate_cost_invokes_resolver_for_routed_token():
    from agent.insights import _estimate_cost
    estimated, status = _estimate_cost("@openai:gpt-4.1", 1_000_000, 0)
    assert status == "estimated"
    assert estimated > 0


def test_insights_estimate_cost_malformed_token_is_unknown():
    from agent.insights import _estimate_cost
    estimated, status = _estimate_cost("@openai:", 1_000_000, 1_000_000)
    assert status == "unknown"
    assert estimated == 0.0


def test_insights_stored_row_custom_endpoint_preserves_identity(tmp_path):
    """Controlled stored-Insights row: a custom:endpoint session row flows
    through the real lookup path with its full model id (no collapse, no
    invented price) and does not double count."""
    from hermes_state import SessionDB
    session_db = SessionDB(db_path=tmp_path / "k06.db")
    try:
        session_db.create_session(session_id="k06", source="cli", model="org/team/model:revision", user_id="u1")
        session_db.end_session("k06", end_reason="user_exit")
        # billing_* columns are written by the billing layer, not create_session.
        session_db._conn.execute(
            "UPDATE sessions SET billing_provider = 'custom:example', billing_base_url = 'https://proxy.example/v1' WHERE id = 'k06'"
        )
        session_db._conn.commit()
        stored = session_db._conn.execute(
            "SELECT model, billing_provider, billing_base_url FROM sessions WHERE id = 'k06'"
        ).fetchone()
        assert stored[1] == "custom:example" and stored[2] == "https://proxy.example/v1"
        from agent.insights import _estimate_cost
        estimated, status = _estimate_cost(stored[0], provider=stored[1], base_url=stored[2])
        assert status == "unknown"
        assert estimated == 0.0
        # Aggregation over the same row twice must not double count an unknown.
        totals = [_estimate_cost(stored[0], provider=stored[1], base_url=stored[2])[0] for _ in range(2)]
        assert totals == [0.0, 0.0]
    finally:
        session_db.close()
