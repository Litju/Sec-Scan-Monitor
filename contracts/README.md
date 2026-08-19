# Contracts Package

## Purpose

The `contracts/` package holds the firm's service contracts and its schema discipline:

- `brigade-roster.md` — the seven service personas and their deployment rules (pinned by `.secscan/policy.yaml`)
- `engagement-protocol.md` — intake contract fields, pass types, authority levels, report format, refusal rules
- `schemas/` — JSON Schema (Draft 2020-12) contract files retained from the FL-001 foundation; direction-agnostic and still authoritative for typed contracts
- `codegen/` — scaffold placeholders for later milestones

## Authority

Contract meaning is defined by, in order:

1. `docs/SECSCANMONITOR_FIRM_CHARTER.md`
2. `AGENTS.md`
3. `.secscan/policy.yaml`
4. `.secscan/drift-rules.yaml`
5. This package

If a contract question is not answered by the current approved docs, stop rather than inventing a speculative field or new contract.

## Rules

- Every schema is JSON Schema Draft 2020-12 with a required `contract_version` field.
- Breaking field changes require a version bump and authority review; additive fields require documentation updates.
- Canonical contracts are produced by the deterministic Python layer (`analysis/`); advisory output never overwrites canonical contracts.
- This package does not authorize shell access, network authority, direct internet exposure, target mutation, or autonomous phase promotion.
- No schema may add speculative fields unsupported by the approved bundle.
- No secret-like material belongs in any contract or schema; secret references are pointer-only.

## Ownership model

- Python (`analysis/`) owns canonical deterministic contract production.
- The MCP reference desk consumes contract summaries; it must not redefine them.
- Brigade personas consume and produce engagement artifacts under the engagement protocol.
- The internal governance swarm owns contract change approval.
