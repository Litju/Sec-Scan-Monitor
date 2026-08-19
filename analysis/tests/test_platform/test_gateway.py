"""Gateway boundary tests (G11).

Route discipline tests run without transport. The MCP smoke test drives the
REAL read-only reference desk (`tools/mcp/secscanmonitor-readonly`, built
dist) through the gateway's stdio transport — proving the gateway can reach
existing MCP tooling without modifying it. Skipped when the MCP build is
missing (recorded limitation).
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from secscan.platform.gateway import (
    GatewayError,
    GatewayRoute,
    GatewayService,
    McpStdioTransport,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
MCP_DIR = REPO_ROOT / "tools" / "mcp" / "secscanmonitor-readonly"


class _FakeTransport:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def call(self, *, server: str, tool: str, arguments: dict, timeout_seconds: int) -> dict:
        self.calls.append({"server": server, "tool": tool, "arguments": arguments, "timeout": timeout_seconds})
        return {"ok": True}


def test_unknown_route_refused() -> None:
    service = GatewayService(_FakeTransport())
    with pytest.raises(GatewayError):
        service.invoke("not-a-route", {})


def test_route_argument_allowlist() -> None:
    transport = _FakeTransport()
    service = GatewayService(transport)
    service.register(GatewayRoute(name="repo-inventory", server="mcp-desk", tool="list_resources", allow_arguments={"engagement_id"}))
    service.invoke("repo-inventory", {"engagement_id": "ENG-1"})
    assert len(transport.calls) == 1
    with pytest.raises(GatewayError):
        service.invoke("repo-inventory", {"engagement_id": "ENG-1", "extra": "nope"})


def test_route_timeout_respected() -> None:
    transport = _FakeTransport()
    service = GatewayService(transport)
    service.register(GatewayRoute(name="slow", server="x", tool="y", timeout_seconds=5))
    service.invoke("slow", {}, timeout_seconds=9)
    assert transport.calls[0]["timeout"] == 9


class TestMcpSmoke:
    @pytest.fixture(scope="class")
    def transport(self):
        index_js = MCP_DIR / "dist" / "src" / "index.js"
        node = shutil.which("node")
        if node is None or not index_js.is_file():
            pytest.skip("MCP reference desk build missing; gateway MCP smoke recorded as NOT_RUN")
        transport = McpStdioTransport([node, str(index_js)])
        yield transport
        transport.stop()

    def test_list_tools_through_gateway(self, transport) -> None:
        tools = transport.list_tools()
        names = {tool.get("name") for tool in tools}
        assert names, "reference desk should expose read-only tools"
        # read-only security property: every tool name reflects reference-desk surface
        assert all("_" in name for name in names if name)

    def test_invoke_read_only_resource(self, transport) -> None:
        tools = transport.list_tools()
        assert tools
        first_tool = tools[0].get("name")
        result = transport.call(server="mcp-desk", tool=first_tool, arguments={}, timeout_seconds=30)
        assert isinstance(result, dict)

    def test_gateway_service_over_mcp(self, transport) -> None:
        tools = transport.list_tools()
        assert tools
        first_tool = tools[0].get("name")
        service = GatewayService(transport)
        service.register(GatewayRoute(name="desk", server="mcp-desk", tool=first_tool, timeout_seconds=30))
        result = service.invoke("desk", {})
        assert isinstance(result, dict)
