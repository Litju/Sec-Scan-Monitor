# ADR-0012: Hosted control-plane composition for isolated staging

| Field | Value |
|---|---|
| status | accepted for isolated staging; production not authorized |
| date | 2026-08-16 |
| patch | ARCH-PATCH-004 / F-230 |

## Context

SecScanMonitor now has a desktop-first Next.js surface, a FastAPI platform API,
PostgreSQL adapters, Temporal workflows, OPA policy evaluation, private
evidence metadata, and sandbox contracts. A hosted deployment must preserve
those boundaries instead of turning a preview UI into an unqualified control
plane.

## Decision

- Vercel hosts the Next.js browser/BFF surface as an isolated preview project.
- Neon hosts an isolated PostgreSQL staging project. The repository Alembic
  head is `a230hosted1`; human/client access records and forced RLS are enabled.
- FastAPI remains a separately hosted service boundary. Vercel Functions are
  not used as a long-running Temporal worker host.
- Human identity is verified by an injected standards-based provider adapter;
  agent principals remain separate from human membership and OPA authority.
- Hosted API composition fails closed unless database, identity, Temporal, OPA,
  evidence, sandbox, frontend-origin, and observability boundaries are explicit.
- Typed read models are the browser contract. Evidence bytes are never served
  through the read surface.

## Provider evidence

- Vercel project: `secscanmonitor`; framework `nextjs`; root `apps/web`;
  preview-only deployment recorded in the hosted manifest.
- Neon project: `bitter-sun-29288346`; main branch: `br-wispy-pond-axqonkbn`;
  database: `neondb`.
- Neon temporary migration branch was tested and deleted by the provider
  migration workflow. No connection string or credential is stored here.

## Consequences

The database and tenant-isolation migration are qualified in staging. The
hosted FastAPI deployment, real human identity adapter, Temporal service/worker,
OPA endpoint, private evidence store, and isolated sandbox remain separate
qualification gates. Until each has live evidence, the system must report
`NOT_VALIDATED` and the Vercel project remains preview-only.

## Rollback

Revert the F-230 commits for repository changes. Remove only the isolated Neon
staging project through provider controls if the staging campaign is retired.
No production resource, DNS record, or client system is part of this ADR.
