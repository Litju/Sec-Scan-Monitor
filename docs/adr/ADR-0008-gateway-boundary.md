# ADR-0008: Gateway boundary (MCP/A2A/agentgateway)

| Field | Value |
|---|---|
| status | accepted |
| date | 2026-08-14 |

## Context

The firm must talk to external agents and tools over several protocols (MCP now, A2A later, plain HTTP/gRPC), but protocol plumbing must not leak into the domain, and the existing read-only MCP reference desk must keep its security properties.

## Decision

A gateway port (`secscan.platform.gateway`) wraps external agent/tool protocol calls. MCP is the agent/tool boundary (existing `tools/mcp/secscanmonitor-readonly` preserved, read-only, allowlisted). A2A is the future agent/agent boundary — the boundary is designed but not implemented yet. HTTP/gRPC are normal service boundaries. agentgateway is investigated for a stable pinned local integration; until then the adapter contract is documented and live qualification is recorded as a limitation. Ordinary internal function calls are never converted into MCP.

## Consequences

- Protocol changes are adapter-only changes.
- No fake agentgateway PASS: either a pinned smoke-tested integration or an explicit limitation.
- Cost: gateway port must stay minimal (request/response, typed payloads) to avoid becoming a protocol zoo.
