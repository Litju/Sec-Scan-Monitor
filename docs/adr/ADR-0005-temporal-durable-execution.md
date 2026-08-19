# ADR-0005: Temporal for durable workflow execution

| Field | Value |
|---|---|
| status | accepted |
| date | 2026-08-14 |

## Context

Engagements are long-running, involve humans/approvals, crash across processes, and must never silently duplicate side effects (tool executions, canonical writes, notifications).

## Decision

Temporal Python SDK orchestrates the `EngagementWorkflow` (start, pause, resume, approval wait, failure, retry-safe activities, close). Deterministic workflow code is strictly separated from nondeterministic activities (model calls, MCP calls, I/O, scanner execution, OPA calls, evidence ingestion, report rendering). Stable idempotency keys: engagement_id, workflow_run_id, agent_run_id, tool_invocation_id, capability_execution_id. Retries must not duplicate side effects; DB unique constraints back the keys.

## Consequences

- Crash recovery and replay come from Temporal's execution model.
- Qualification distinguishes `TEMPORAL_UNIT_TEST` (SDK test environment, in-process) from `TEMPORAL_LIVE_SERVER` (real service smoke, optional); the distinction is recorded, never collapsed into one PASS.
- Cost: workflow code must be deterministic (no wall-clock, no randomness, no direct I/O); activity design is more verbose.
