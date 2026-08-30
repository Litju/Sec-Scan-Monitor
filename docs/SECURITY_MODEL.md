# Security model

SecScanMonitor treats every target, event source, tool output, model output, and detector result as untrusted input. The public v0.3 boundary enforces:

- inspection-only authority by default;
- explicit engagement, target, tenant, case, scope, and principal binding;
- fail-closed policy decisions for unknown actions, capabilities, grants, and approvals;
- sandbox boundaries for command-capable adapters;
- metadata and content-addressed evidence separation;
- deterministic sanitization before evidence or report persistence;
- no raw secrets, credentials, private keys, personal data, or raw target evidence in public artifacts;
- no direct agent-to-database or browser-to-database path;
- explicit unavailable and `NOT_VALIDATED` states instead of fabricated clean states.

## Detection and response invariants

- An event source is untrusted; ingest does not establish truth.
- A detector result is not Incident authority.
- `Signal` cannot directly create `Incident`.
- Hunt results require canonical evidence, observations, and claims.
- Incident confirmation requires explicit adjudication.
- `ResponseProposal` requires OPA policy evaluation.
- Human approval cannot be synthesized by a UI, LLM, agent, or tool output.
- Approval is not execution. There is no response executor in v0.3.
- ATT&CK or ATLAS mapping provides classification context, not proof.

The model is advisory-first. It does not authorize exploit attempts, production active testing, credential testing, target mutation, deployment changes, or response execution without separate explicit authority. A source, adapter, policy engine, or dependency being unavailable is never interpreted as a clean result.
