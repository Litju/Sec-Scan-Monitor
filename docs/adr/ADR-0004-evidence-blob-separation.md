# ADR-0004: Evidence/blob separation (content-addressed store)

| Field | Value |
|---|---|
| status | accepted |
| date | 2026-08-14 |

## Context

Evidence bytes can be large, must be tamper-evident, and must never be silently mutable. Storing arbitrary binaries in relational columns is an anti-pattern. The no-secrets law requires sanitization discipline at every persistence point.

## Decision

Evidence bytes live in a content-addressed store behind an `EvidenceStore` port: SHA-256 addressing, immutable-by-content writes, metadata rows in PostgreSQL referencing the digest. Dev/test backend is `LocalContentAddressedEvidenceStore`; an S3-compatible adapter contract is defined without coupling the domain to one vendor.

## Consequences

- Integrity by construction: content identity cannot change without changing the address.
- Provenance metadata (collector, tool, invocation, timestamps, sanitization state) stays queryable in PostgreSQL.
- Cost: two-tier storage requires disciplined metadata↔blob bookkeeping; deletion/GC semantics are deferred (evidence is preserved by design).
