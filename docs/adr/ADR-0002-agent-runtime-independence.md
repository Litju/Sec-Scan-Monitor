# ADR-0002: Agent-runtime independence

| Field | Value |
|---|---|
| status | accepted |
| date | 2026-08-14 |

## Context

The firm serves agents and must not become hostage to any one agent runtime, model vendor, or orchestration environment. Hermes is the development/operator environment, not a product dependency.

## Decision

Canonical firm state and the domain model are independent of Hermes, Pydantic AI, OpenAI, Anthropic, Nous, and any single model. Agents are described by `AgentManifest` (static contract) and executed as `AgentRun` records. Pydantic AI is the initial execution adapter behind a model port; a deterministic fake model is built in for canonical tests.

## Consequences

- SecScanMonitor remains executable without Hermes or paid LLM access.
- Model output is always untrusted evidence (see ADR-0011).
- Cost: agent implementation must route every model interaction through the model port; provider SDKs may not leak into domain or application layers.
