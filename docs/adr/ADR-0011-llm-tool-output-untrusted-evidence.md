# ADR-0011: LLM/tool output as untrusted evidence

| Field | Value |
|---|---|
| status | accepted |
| date | 2026-08-14 |

## Context

Models hallucinate, scanners lie, and both can be adversarially fed. If agent or scanner output can directly become a Finding or an authorization, the firm's no-false-confidence and advisory-first guarantees collapse.

## Decision

Every LLM output and every tool output enters the platform as untrusted evidence: an `EvidenceObject` that flows through Observation → Claim → Adjudication before any Finding exists. Findings are created only by the adjudication engine. Models may recommend actions; only the policy/application boundary authorizes them. Confidence is categorical (never fabricated numerics). Scanner output likewise cannot instantiate Findings directly.

## Consequences

- The "raw signal is not a finding" law is structural, not procedural.
- Adversarial tests feed secret-bearing and misleading outputs and assert they cannot become Findings or persist secrets.
- Cost: agent implementations must model outputs as claims with explicit uncertainty; convenience shortcuts (direct finding creation) are forbidden and architecture-tested.
