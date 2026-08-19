# ADR-0001: Platform layering and ports/adapters

| Field | Value |
|---|---|
| status | accepted |
| date | 2026-08-14 |

## Context

The firm control plane must keep business rules (engagement lifecycle, authority, evidence law, adjudication) independent of external systems so that a provider, engine, or protocol change never forces a domain rewrite. The repository's analysis package already contains a direction-agnostic case engine.

## Decision

Implement explicit layers under `secscan.platform.*`: `domain/`, `application/`, `policy/`, `workflows/`, `agents/`, `capabilities/`, `evidence/`, `adjudication/`, `sandbox/`, `gateway/`, `persistence/`, `observability/`, `audit/`, `api/`, `reports/`. Dependencies point inward; `domain/` is pure (Pydantic v2 models, enums, transition tables, `typing.Protocol` ports). External systems are adapters behind ports. The platform extends the canonical `secscan` package and reuses the case engine.

## Consequences

- Architecture tests (import rules) enforce layer purity mechanically.
- Adapters (Temporal, OPA, PostgreSQL, Docker, agentgateway, LLM providers) are replaceable without domain changes.
- Cost: discipline required to avoid leaking adapter types into application/domain; enforced by CI, not convention.
