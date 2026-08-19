# ADR-0006: OPA for deterministic authorization

| Field | Value |
|---|---|
| status | accepted |
| date | 2026-08-14 |

## Context

The platform law "the LLM does not own authority" requires a deterministic, auditable authorization boundary. Prompt-based checks are not a boundary. The charter's fixed principles (inspection-only default, no mutation without grant) must be mechanically enforced.

## Decision

Open Policy Agent (Rego) is the policy kernel. Every capability request carries full context (principal, agent, engagement, target, capability, action, risk, authority_grant, approval_state, workflow_phase, requested_resources) and yields exactly `ALLOW`, `DENY`, or `REQUIRE_APPROVAL`. Baseline policy: unknown action/capability DENY; out-of-engagement target DENY; expired grant DENY; mutation/active-testing without grant DENY; high-risk operation REQUIRE_APPROVAL; inspection within valid scope ALLOW. A subprocess adapter calls the pinned `opa` binary; a mock adapter exists only for unit tests and never counts as integration PASS.

## Consequences

- Authority is data + deterministic rules, auditable and testable.
- Policy changes are code-reviewed Rego, version-controlled in the repository.
- Cost: OPA binary (or container) required for integration qualification; unit tests use the SDK-free decision-type path.
