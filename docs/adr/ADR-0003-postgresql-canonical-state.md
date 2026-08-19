# ADR-0003: PostgreSQL as canonical state

Status: accepted for local/self-hosted operation

## Context

Engagement state, authority decisions, evidence metadata, observations, claims,
adjudications, and findings require one deterministic transactional source of
truth. Local previews must remain synthetic and must not depend on a hosted
control plane.

## Decision

Use PostgreSQL as the canonical state store for the platform boundary. Keep
evidence bytes outside the relational state tables and retain only sanitized,
content-addressed metadata references in the database. Configure connection
material through the local environment; no credential values belong in source,
fixtures, logs, or reports.

## Consequences

- State transitions can be constrained and audited transactionally.
- Evidence metadata and report provenance remain queryable without exposing raw
  evidence bytes.
- A local PostgreSQL instance is required for the persistence integration path.
- Hosted operation and production availability remain `NOT_VALIDATED` by this
  public foundation.
