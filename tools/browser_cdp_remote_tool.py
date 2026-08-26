#!/usr/bin/env python3
"""
Remote Chrome DevTools Protocol (CDP) passthrough tool.

Exposes ``browser_cdp_remote``, a variant of ``browser_cdp`` that accepts an
explicit ``endpoint`` parameter (HTTP or WS URL) instead of reading from
config.  Defaults to the PPC Chrome CDP endpoint so the agent can drive PPC's
browser without changing the local ``browser.cdp_url`` config.

This lets the agent control TWO browsers simultaneously:
- ``browser_cdp`` / ``browser_navigate`` etc. → local Mac Chrome (config endpoint)
- ``browser_cdp_remote`` → PPC Chrome (or any remote CDP endpoint)
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Dict, Optional

from tools.registry import registry, tool_error

logger = logging.getLogger(__name__)

CDP_DOCS_URL = "https://chromedevtools.github.io/devtools-protocol/"

# Default endpoint: PPC Chrome via Tailscale portproxy
DEFAULT_REMOTE_ENDPOINT = "http://100.119.168.29:9223"

# ``websockets`` is a direct hermes-agent dependency.
try:
    import websockets
    from websockets.exceptions import WebSocketException

    _WS_AVAILABLE = True
except ImportError:
    websockets = None  # type: ignore[assignment]
    WebSocketException = Exception  # type: ignore[assignment,misc]
    _WS_AVAILABLE = False


# ---------------------------------------------------------------------------
# Endpoint resolution (HTTP → WebSocket)
# ---------------------------------------------------------------------------


def _resolve_remote_endpoint(endpoint: str) -> str:
    """Normalize an HTTP or WS endpoint into a concrete WebSocket URL.

    Reuses the same logic as ``tools.browser_tool._resolve_cdp_override``:
    fetches ``/json/version`` from HTTP endpoints and extracts the
    ``webSocketDebuggerUrl``.
    """
    raw = (endpoint or "").strip()
    if not raw:
        return ""

    lowered = raw.lower()

    # Already a full websocket browser endpoint
    if "/devtools/browser/" in lowered:
        return raw

    # Already a ws:// or wss:// endpoint (but not a bare host:port)
    if lowered.startswith(("ws://", "wss://")):
        if raw.count(":") == 2 and raw.rstrip("/").rsplit(":", 1)[-1].isdigit() and "/" not in raw.split("://", 2)[-1]:
            # Bare ws://host:port — convert to HTTP for discovery
            discovery_url = ("http://" if lowered.startswith("ws://") else "https://") + raw.split("://", 1)[1]
        else:
            return raw
    else:
        discovery_url = raw

    # Fetch /json/version to get the WebSocket URL
    if discovery_url.lower().endswith("/json/version"):
        version_url = discovery_url
    else:
        version_url = discovery_url.rstrip("/") + "/json/version"

    try:
        import requests

        response = requests.get(version_url, timeout=10)
        response.raise_for_status()
        payload = response.json()
    except Exception as exc:
        logger.warning(
            "browser_cdp_remote: failed to resolve endpoint %s via %s: %s",
            raw,
            version_url,
            exc,
        )
        return ""

    ws_url = str(payload.get("webSocketDebuggerUrl") or "").strip()
    if ws_url:
        logger.info("browser_cdp_remote: resolved %s -> %s", raw, ws_url)
        return ws_url

    logger.warning("browser_cdp_remote: /json/version at %s had no webSocketDebuggerUrl", version_url)
    return ""


# ---------------------------------------------------------------------------
# Async-from-sync bridge (same pattern as browser_cdp_tool.py)
# ---------------------------------------------------------------------------


def _run_async(coro):
    """Run an async coroutine from a sync handler."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(asyncio.run, coro)
            return future.result()
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Redaction (reuse from browser_cdp_tool)
# ---------------------------------------------------------------------------


def _redact_cdp_output(value: Any) -> Any:
    """Redact browser-originated CDP result data before returning it."""
    from agent.redact import redact_sensitive_text

    if isinstance(value, str):
        return redact_sensitive_text(value, force=True)
    if isinstance(value, list):
        return [_redact_cdp_output(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact_cdp_output(item) for item in value)
    if isinstance(value, dict):
        return {key: _redact_cdp_output(item) for key, item in value.items()}
    return value


# ---------------------------------------------------------------------------
# Core CDP call (same logic as browser_cdp_tool._cdp_call)
# ---------------------------------------------------------------------------


async def _cdp_call(
    ws_url: str,
    method: str,
    params: Dict[str, Any],
    target_id: Optional[str],
    timeout: float,
) -> Dict[str, Any]:
    """Make a single CDP call, optionally attaching to a target first."""
    assert websockets is not None

    async with websockets.connect(
        ws_url,
        max_size=None,
        open_timeout=timeout,
        close_timeout=5,
        ping_interval=None,
    ) as ws:
        next_id = 1
        session_id: Optional[str] = None

        if target_id:
            attach_id = next_id
            next_id += 1
            await ws.send(
                json.dumps(
                    {
                        "id": attach_id,
                        "method": "Target.attachToTarget",
                        "params": {"targetId": target_id, "flatten": True},
                    }
                )
            )
            deadline = asyncio.get_running_loop().time() + timeout
            while True:
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    raise TimeoutError(f"Timed out attaching to target {target_id}")
                raw = await asyncio.wait_for(ws.recv(), timeout=remaining)
                msg = json.loads(raw)
                if msg.get("id") == attach_id:
                    if "error" in msg:
                        raise RuntimeError(f"Target.attachToTarget failed: {msg['error']}")
                    session_id = msg.get("result", {}).get("sessionId")
                    if not session_id:
                        raise RuntimeError("Target.attachToTarget did not return a sessionId")
                    break

        call_id = next_id
        next_id += 1
        req: Dict[str, Any] = {
            "id": call_id,
            "method": method,
            "params": params or {},
        }
        if session_id:
            req["sessionId"] = session_id
        await ws.send(json.dumps(req))

        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise TimeoutError(f"Timed out waiting for response to {method}")
            raw = await asyncio.wait_for(ws.recv(), timeout=remaining)
            msg = json.loads(raw)
            if msg.get("id") == call_id:
                if "error" in msg:
                    raise RuntimeError(f"CDP error: {msg['error']}")
                return msg.get("result", {})


# ---------------------------------------------------------------------------
# Public tool function
# ---------------------------------------------------------------------------


def browser_cdp_remote(
    method: str,
    params: Optional[Dict[str, Any]] = None,
    target_id: Optional[str] = None,
    endpoint: Optional[str] = None,
    timeout: float = 30.0,
) -> str:
    """Send a raw CDP command to a remote browser endpoint.

    Args:
        method: CDP method name, e.g. ``"Target.getTargets"``.
        params: Method-specific parameters; defaults to ``{}``.
        target_id: Optional target/tab ID for page-level methods.
        endpoint: CDP endpoint URL (HTTP or WS). Defaults to PPC Chrome.
        timeout: Seconds to wait for the call to complete.

    Returns:
        JSON string on success, or error JSON on failure.
    """
    if not method or not isinstance(method, str):
        return tool_error(
            "'method' is required (e.g. 'Target.getTargets')",
            cdp_docs=CDP_DOCS_URL,
        )

    if not _WS_AVAILABLE:
        return tool_error(
            "The 'websockets' Python package is required but not installed. "
            "Install it with: pip install websockets"
        )

    # Resolve endpoint (default to PPC, convert HTTP → WS)
    raw_endpoint = (endpoint or DEFAULT_REMOTE_ENDPOINT).strip()
    ws_endpoint = _resolve_remote_endpoint(raw_endpoint)
    if not ws_endpoint:
        return tool_error(
            f"Could not resolve CDP endpoint at {raw_endpoint}. "
            "The remote browser may be offline or not listening. "
            "Verify the endpoint is reachable (e.g. curl the /json/version URL).",
            cdp_docs=CDP_DOCS_URL,
        )

    if not ws_endpoint.startswith(("ws://", "wss://")):
        return tool_error(
            f"Resolved endpoint is not a WebSocket URL: {ws_endpoint!r}.",
            cdp_docs=CDP_DOCS_URL,
        )

    call_params: Dict[str, Any] = params or {}
    if not isinstance(call_params, dict):
        return tool_error(
            f"'params' must be an object/dict, got {type(call_params).__name__}"
        )

    try:
        safe_timeout = float(timeout) if timeout else 30.0
    except (TypeError, ValueError):
        safe_timeout = 30.0
    safe_timeout = max(1.0, min(safe_timeout, 300.0))

    try:
        result = _run_async(
            _cdp_call(ws_endpoint, method, call_params, target_id, safe_timeout)
        )
    except asyncio.TimeoutError as exc:
        return tool_error(
            f"CDP call timed out after {safe_timeout}s: {exc}",
            method=method,
        )
    except TimeoutError as exc:
        return tool_error(str(exc), method=method)
    except RuntimeError as exc:
        return tool_error(str(exc), method=method)
    except WebSocketException as exc:
        return tool_error(
            f"WebSocket error talking to CDP at endpoint: {exc}. "
            "The remote browser may have disconnected.",
            method=method,
        )
    except Exception as exc:
        logger.exception("browser_cdp_remote unexpected error")
        return tool_error(
            f"Unexpected error: {type(exc).__name__}: {exc}",
            method=method,
        )

    payload: Dict[str, Any] = {
        "success": True,
        "method": method,
        "result": _redact_cdp_output(result),
    }
    if target_id:
        payload["target_id"] = target_id
    return json.dumps(payload, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


BROWSER_CDP_REMOTE_SCHEMA: Dict[str, Any] = {
    "name": "browser_cdp_remote",
    "description": (
        "Send a raw Chrome DevTools Protocol (CDP) command to a REMOTE browser "
        "endpoint (e.g. PPC Chrome via Tailscale). This is the remote variant of "
        "browser_cdp — it accepts an explicit 'endpoint' parameter instead of "
        "reading from config, so you can control a remote browser without changing "
        "the local browser.cdp_url setting.\n\n"
        f"**Default endpoint:** PPC Chrome at {DEFAULT_REMOTE_ENDPOINT} (via Tailscale "
        "portproxy 9223 → localhost 9222). Override with the 'endpoint' parameter "
        "for other remote browsers.\n\n"
        f"**CDP method reference:** {CDP_DOCS_URL}\n\n"
        "**Common patterns:**\n"
        "- List tabs: method='Target.getTargets', params={}\n"
        "- Navigate a tab: method='Page.navigate', params={'url': 'https://...'}, "
        "target_id=<tabId>\n"
        "- Eval in a tab: method='Runtime.evaluate', "
        "params={'expression': '...', 'returnByValue': true}, target_id=<tabId>\n"
        "- Activate a tab (bring to front): method='Target.activateTarget', "
        "params={'targetId': '<tabId>'}\n"
        "- Create new tab: method='Target.createTarget', params={'url': 'https://...'}\n\n"
        "**Usage rules:**\n"
        "- Browser-level methods (Target.*, Browser.*, Storage.*): omit target_id.\n"
        "- Page-level methods (Page.*, Runtime.*, DOM.*, Emulation.*): pass target_id "
        "from Target.getTargets.\n"
        "- Each call is stateless — no session persistence between calls.\n"
        "- If the remote browser is asleep/offline, you'll get a connection error."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "method": {
                "type": "string",
                "description": (
                    "CDP method name, e.g. 'Target.getTargets', "
                    "'Runtime.evaluate', 'Page.navigate'."
                ),
            },
            "params": {
                "type": "object",
                "description": (
                    "Method-specific parameters as a JSON object. Omit or "
                    "pass {} for methods that take no parameters."
                ),
                "properties": {},
                "additionalProperties": True,
            },
            "target_id": {
                "type": "string",
                "description": (
                    "Optional. Target/tab ID from Target.getTargets result "
                    "(each entry's 'targetId'). Use for page-level methods."
                ),
            },
            "endpoint": {
                "type": "string",
                "description": (
                    f"CDP endpoint URL (HTTP or WS). Defaults to PPC Chrome "
                    f"at {DEFAULT_REMOTE_ENDPOINT}. Pass a different URL to "
                    f"control another remote browser."
                ),
            },
            "timeout": {
                "type": "number",
                "description": "Timeout in seconds (default 30, max 300).",
                "default": 30,
            },
        },
        "required": ["method"],
    },
}


def _browser_cdp_remote_check() -> bool:
    """Availability check — always available since we have a default endpoint."""
    return _WS_AVAILABLE


registry.register(
    name="browser_cdp_remote",
    toolset="browser-cdp",
    schema=BROWSER_CDP_REMOTE_SCHEMA,
    handler=lambda args, **kw: browser_cdp_remote(
        method=args.get("method", ""),
        params=args.get("params"),
        target_id=args.get("target_id"),
        endpoint=args.get("endpoint"),
        timeout=args.get("timeout", 30.0),
    ),
    check_fn=_browser_cdp_remote_check,
    emoji="🌐",
)
