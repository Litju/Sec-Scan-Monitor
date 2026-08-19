"""Gateway boundary (ADR-0008).

A gateway port wraps external agent/tool protocol calls. MCP is the
agent/tool boundary (the existing read-only reference desk is preserved
unchanged); A2A is the future agent/agent boundary (designed, not
implemented); HTTP/gRPC are normal service boundaries. agentgateway is
documented as an adapter contract with live qualification recorded as a
limitation until a stable pinned deployment exists.

Ordinary internal function calls are never converted into MCP.
"""

from __future__ import annotations

import json
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Protocol, cast


class GatewayError(RuntimeError):
    """A gateway call failed or was refused."""


class GatewayCall(Protocol):
    """One external protocol call through the gateway."""

    def call(
        self,
        *,
        server: str,
        tool: str,
        arguments: dict[str, Any],
        timeout_seconds: int,
    ) -> dict[str, Any]: ...


@dataclass
class GatewayRoute:
    """Declarative route: which external server/tool may be called with
    which constraints. Unknown routes are refused (deny-by-default)."""

    name: str
    server: str
    tool: str
    timeout_seconds: int = 60
    allow_arguments: set[str] = field(default_factory=set)
    read_only: bool = True


class GatewayService:
    """Application-level gateway: routes, allowlists, and audit of external
    protocol calls. The transport adapter is injected."""

    def __init__(self, transport: GatewayCall, routes: list[GatewayRoute] | None = None) -> None:
        self._transport = transport
        self._routes = {route.name: route for route in routes or []}

    def register(self, route: GatewayRoute) -> None:
        self._routes[route.name] = route

    def invoke(self, route_name: str, arguments: dict[str, Any], timeout_seconds: int | None = None) -> dict[str, Any]:
        route = self._routes.get(route_name)
        if route is None:
            raise GatewayError(f"unknown gateway route {route_name!r}: refused")
        if route.allow_arguments:
            extra = set(arguments) - route.allow_arguments
            if extra:
                raise GatewayError(f"route {route_name!r} refuses arguments {sorted(extra)}")
        return self._transport.call(
            server=route.server,
            tool=route.tool,
            arguments=arguments,
            timeout_seconds=timeout_seconds or route.timeout_seconds,
        )


class McpStdioTransport:
    """Minimal MCP client transport (stdio JSON-RPC) for gateway smoke tests
    and local adapters. The canonical MCP reference desk remains
    `tools/mcp/secscanmonitor-readonly` — this transport does not replace it."""

    def __init__(self, command: list[str]) -> None:
        self._command = command
        self._process: subprocess.Popen[bytes] | None = None
        self._next_id = 1

    def start(self) -> None:
        if self._process is not None:
            return
        self._process = subprocess.Popen(
            self._command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self._rpc("initialize", {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "secscan-gateway", "version": "0.1.0"}})
        self._rpc("notifications/initialized", {}, notify=True)

    def stop(self) -> None:
        if self._process is not None:
            try:
                self._process.terminate()
            except Exception:
                pass
            self._process = None

    def call(self, *, server: str, tool: str, arguments: dict[str, Any], timeout_seconds: int) -> dict[str, Any]:
        if self._process is None:
            self.start()
        response = self._rpc("tools/call", {"name": tool, "arguments": arguments}, timeout=timeout_seconds)
        if "error" in response:
            raise GatewayError(f"MCP tool error: {response['error']}")
        return cast(dict[str, Any], response.get("result", {}))

    def list_tools(self) -> list[dict[str, Any]]:
        if self._process is None:
            self.start()
        response = self._rpc("tools/list", {})
        result = cast(dict[str, Any], response.get("result", {}))
        return cast(list[dict[str, Any]], result.get("tools", []))

    def _rpc(self, method: str, params: dict[str, Any], *, timeout: int = 30, notify: bool = False) -> dict[str, Any]:
        assert self._process is not None
        request_id = self._next_id
        self._next_id += 1
        message = json.dumps({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
        self._process.stdin.write((message + "\n").encode("utf-8"))  # type: ignore[union-attr]
        self._process.stdin.flush()  # type: ignore[union-attr]
        if notify:
            return {}
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            assert self._process.stdout is not None
            line = self._process.stdout.readline()
            if not line:
                break
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if payload.get("id") == request_id:
                return cast(dict[str, Any], payload)
        raise GatewayError(f"MCP RPC {method} timed out")
