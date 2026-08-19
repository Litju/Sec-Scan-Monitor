# ADR-0007: Capability registry

| Field | Value |
|---|---|
| status | accepted |
| date | 2026-08-14 |

## Context

Agents must not execute arbitrary binaries or shell out to whatever tool they feel like. Tool identity, risk, and authorization must be declared, reviewable, and enforced.

## Decision

Agents request registered capabilities. `CapabilityManifest` declares id, version, description, risk_class, accepted_inputs, produced_outputs, required_authority, requires_approval, sandbox_profile, network_policy, timeout, resource_limits, tool_identity, tool_version, evidence_type. Only safe foundation capabilities are seeded in this campaign (repo inventory, read-only inspection, report render, evidence normalize). Aggressive engines (Semgrep, OSV-Scanner, Gitleaks, Trivy, PyRIT, garak, PentAGI, Caldera/OpenAEV, OpenCTI, Velociraptor, Volatility, Falco, Tetragon) are future adapters that must fit the registry without core changes.

## Consequences

- Every execution is attributable to a manifest version; unknown capability requests are denied.
- Supply-chain law: external tools are untrusted evidence producers with pinned identity (name, version, digest where applicable).
- Cost: adding a real tool requires a manifest review; no fake integrations are shipped.
