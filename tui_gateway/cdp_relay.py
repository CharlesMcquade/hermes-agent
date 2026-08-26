"""
CDP Relay Registry — tracks browser extensions connected via the gateway
WebSocket that have registered as CDP relays (can execute chrome.debugger
commands).

When a browser extension connects to /api/ws and sends a `cdp.register`
JSON-RPC request, it's added to this registry. The `browser_cdp_via_extension`
tool can then push `cdp.command` requests to the extension through its
WebSocket transport and wait for the response.

Architecture:
  1. Extension connects to /api/ws, sends cdp.register → registered here
  2. Tool calls send_cdp_command(relay_id, method, params)
  3. We push a JSON-RPC request {id, method: "cdp.command", params} to the
     extension's transport
  4. Extension executes via chrome.debugger, sends JSON-RPC response back
  5. Gateway's ws receive loop sees the response, routes it to the waiting
     future via _pending_responses
  6. Tool gets the result

Thread safety: the gateway runs dispatch in a thread pool (asyncio.to_thread),
so we use a lock for the registries. Response routing uses threading.Event
so the tool can wait synchronously.
"""
from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


@dataclass
class RelayConnection:
    """A connected browser extension that can execute CDP commands."""
    relay_id: str
    transport: Any  # WSTransport from tui_gateway
    peer: str = ""
    registered_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)


class CdpRelayRegistry:
    """Thread-safe registry of connected CDP relay extensions."""

    def __init__(self):
        self._relays: Dict[str, RelayConnection] = {}
        self._lock = threading.Lock()
        # Map JSON-RPC response id → (event, result_holder) for response routing
        self._pending_responses: Dict[str, tuple] = {}

    def register(self, transport: Any, peer: str = "") -> str:
        """Register a new relay connection. Returns the relay_id."""
        relay_id = str(uuid.uuid4())[:8]
        with self._lock:
            # Remove any existing relay with the same transport
            self._relays = {
                k: v for k, v in self._relays.items()
                if v.transport is not transport
            }
            self._relays[relay_id] = RelayConnection(
                relay_id=relay_id,
                transport=transport,
                peer=peer,
            )
        logger.info("CDP relay registered: id=%s peer=%s", relay_id, peer)
        return relay_id

    def unregister(self, transport: Any = None, relay_id: str = None) -> None:
        """Unregister a relay by transport or relay_id."""
        with self._lock:
            if relay_id:
                self._relays.pop(relay_id, None)
            if transport:
                self._relays = {
                    k: v for k, v in self._relays.items()
                    if v.transport is not transport
                }

    def list_relays(self) -> list:
        """List all registered relays."""
        with self._lock:
            return [
                {
                    "relay_id": r.relay_id,
                    "peer": r.peer,
                    "registered_at": r.registered_at,
                    "last_activity": r.last_activity,
                }
                for r in self._relays.values()
            ]

    def get_relay(self, relay_id: str = None) -> Optional[RelayConnection]:
        """Get a relay by ID, or the first/only relay if no ID specified."""
        with self._lock:
            if relay_id:
                return self._relays.get(relay_id)
            if len(self._relays) == 1:
                return next(iter(self._relays.values()))
            if len(self._relays) > 1:
                # Return the most recently active
                return max(self._relays.values(), key=lambda r: r.last_activity)
            return None

    def send_command(
        self,
        method: str,
        params: Dict[str, Any],
        target: Optional[Dict[str, Any]] = None,
        timeout: float = 30.0,
        relay_id: str = None,
    ) -> Dict[str, Any]:
        """
        Send a CDP command to a connected relay extension and wait for the
        response.

        This pushes a JSON-RPC request to the extension's WebSocket transport
        and blocks until the extension responds (or timeout).

        Args:
            method: CDP method name (e.g. "Runtime.evaluate", "Page.navigate")
            params: CDP method parameters
            target: Tab targeting info ({tabId: N}, {active: true}, {url: "..."})
            timeout: Seconds to wait for response
            relay_id: Optional relay ID (auto-selects if omitted)

        Returns: CDP result dict
        Raises: RuntimeError on timeout, connection error, or CDP error
        """
        relay = self.get_relay(relay_id)
        if not relay:
            raise RuntimeError(
                "No CDP relay extension is connected. Install the Hermes "
                "browser extension with CDP relay support and connect it "
                "to this gateway."
            )

        # Generate a unique request ID for response routing
        request_id = f"cdp-{uuid.uuid4().hex[:12]}"
        event = threading.Event()
        result_holder: Dict[str, Any] = {"result": None, "error": None}

        with self._lock:
            self._pending_responses[request_id] = (event, result_holder)

        # Build the JSON-RPC request to send to the extension
        # Special methods map to different JSON-RPC method names on the extension
        if method == "__listTabs__":
            rpc_request = {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": "cdp.listTabs",
                "params": {},
            }
        elif method == "__detach__":
            rpc_request = {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": "cdp.detach",
                "params": params or {},
            }
        else:
            rpc_request = {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": "cdp.command",
                "params": {
                    "method": method,
                    "params": params or {},
                    "target": target or {"active": True},
                    "timeout": int(timeout * 1000),
                },
            }

        # Push the request to the extension via its WebSocket transport
        try:
            loop = getattr(relay.transport, "_loop", None)
            if loop and loop.is_running():
                future = asyncio.run_coroutine_threadsafe(
                    relay.transport.write_async(rpc_request),
                    loop,
                )
                future.result(timeout=5)
            else:
                relay.transport.write(rpc_request)
        except Exception as exc:
            with self._lock:
                self._pending_responses.pop(request_id, None)
            raise RuntimeError(f"Failed to send CDP command to relay: {exc}")

        # Wait for the response
        if not event.wait(timeout=timeout):
            with self._lock:
                self._pending_responses.pop(request_id, None)
            raise RuntimeError(f"CDP command timed out after {timeout}s")

        with self._lock:
            self._pending_responses.pop(request_id, None)
            relay.last_activity = time.time()

        if result_holder["error"]:
            raise RuntimeError(f"CDP relay error: {result_holder['error']}")

        return result_holder["result"] or {}

    def route_response(self, request_id: str, result: Any, error: Any = None) -> bool:
        """
        Route a JSON-RPC response from the extension to the waiting tool call.
        Called by the gateway's ws receive loop when it sees a response frame.

        Returns True if the response was routed to a waiting caller.
        """
        with self._lock:
            entry = self._pending_responses.get(request_id)
            if not entry:
                return False
            event, result_holder = entry
            result_holder["result"] = result
            result_holder["error"] = error
            event.set()
            return True


# Singleton registry
cdp_relay_registry = CdpRelayRegistry()
