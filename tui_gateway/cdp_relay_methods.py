"""
CDP relay registration gateway methods.

When a browser extension connects to /api/ws and sends a `cdp.register`
JSON-RPC request, it's added to the CDP relay registry so the agent can
push CDP commands to it via chrome.debugger.
"""
from __future__ import annotations

import logging

from .method_ctx import HandlerRegistry

logger = logging.getLogger(__name__)

_registry = HandlerRegistry()
method = _registry.method


@method("cdp.register")
def _cdp_register(rid, params: dict) -> dict:
    """Register the calling WebSocket as a CDP relay.

    Called by the browser extension after gateway.ready to announce
    that it can execute chrome.debugger commands.
    """
    from tui_gateway.transport import current_transport
    from tui_gateway.cdp_relay import cdp_relay_registry

    transport = current_transport()
    if transport is None:
        return {"jsonrpc": "2.0", "id": rid, "error": {
            "code": -32603, "message": "No transport bound for cdp.register"
        }}

    peer = getattr(transport, "peer", "") or ""
    relay_id = cdp_relay_registry.register(transport, peer=peer)

    logger.info("CDP relay registered via gateway: id=%s peer=%s", relay_id, peer)

    return {"jsonrpc": "2.0", "id": rid, "result": {
        "relay_id": relay_id,
        "status": "registered",
    }}


@method("cdp.listRelays")
def _cdp_list_relays(rid, params: dict) -> dict:
    """List all connected CDP relay extensions."""
    from tui_gateway.cdp_relay import cdp_relay_registry

    relays = cdp_relay_registry.list_relays()
    return {"jsonrpc": "2.0", "id": rid, "result": {"relays": relays}}


def register(server_module):
    """Bind handlers onto the server module (called from server.py import block)."""
    _registry.install(server_module)
