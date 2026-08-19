# ADR-0009: Sandbox execution (Docker now, microVM later)

| Field | Value |
|---|---|
| status | accepted |
| date | 2026-08-14 |

## Context

Running external scanners and untrusted evidence producers on the operator's host is unacceptable. The platform needs a real isolation boundary with a clean upgrade path.

## Decision

`SandboxBackend` port with a constrained local Docker backend for qualification. Default profile for untrusted operations: network none, read-only input mount, isolated scratch output, no host secrets, no Docker socket inside, bounded CPU/RAM/PIDs, execution timeout, explicit command allowlist from the capability manifest, captured stdout/stderr. A capability marked sandbox-required REFUSES when no backend is available — never a silent fallback to unrestricted host execution. Stronger Firecracker-class microVM backends are future architecture behind the same port.

## Consequences

- Isolation semantics are versioned in the profile, not ad hoc per invocation.
- Qualification can assert refusal behavior deterministically even where no Docker daemon exists.
- Cost: Docker backend is constrained-process isolation (documented residual risk, see threat model T-09); microVM hardening is deferred work, not faked.
