# ADR-0010: OpenTelemetry observability

| Field | Value |
|---|---|
| status | accepted |
| date | 2026-08-14 |

## Context

Operators must reconstruct engagement execution — but traces are a prime exfiltration/leakage channel for secrets and raw client content.

## Decision

OpenTelemetry with OTLP export instruments the platform. Canonical trace hierarchy: engagement → workflow → agent_run → capability_execution → tool_invocation → sandbox_execution → evidence_ingestion → claim → adjudication. Span attributes are restricted to safe identifiers (engagement_id, target_id, workflow_run_id, agent_run_id, capability_id, tool_invocation_id, evidence_id). Secrets, raw file contents, raw sensitive prompts, and credential values never enter spans (enforced by the span policy helper and a leakage test). Phoenix is an optional development profile, not a canonical dependency.

## Consequences

- Cross-cutting correlation without a vendor lock-in (OTLP is provider-neutral).
- Test suite asserts span payloads stay secret-free.
- Cost: instrumentation points must be added to activities and services; the attribute policy helper is the only sanctioned way to add span attributes.
