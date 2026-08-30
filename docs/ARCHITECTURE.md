# Architecture

PostgreSQL is the canonical state store. Process memory, UI state, agent output, detector output, and transport delivery are not canonical truth.

## Current composition

- **Firm Control Plane** binds engagements, targets, principals, scopes, and authority.
- **Security Graph** preserves scoped security relationships.
- **Security Event Plane** authenticates and normalizes external telemetry into canonical `SecurityEvent` records.
- **Detection/Response control plane** leases durable work, records `DetectionRun` and `Signal` state, correlates signals, supports bounded hunts, adjudicates Incidents, and creates governed `ResponseProposal` records.
- **Authority and OPA** evaluate deterministic policy and fail closed.
- **Durable workflow** supports restart/replay reconstruction without treating process memory as truth.
- **Edge Runner and protocol adapters** connect customer-side and MCP/A2A sources through scoped boundaries.
- **Evidence and adjudication** convert evidence into observations, claims, findings, and incidents only through explicit authority transitions.
- **Web Command Center, OpenTUI Operator Console, and API** consume shared canonical read models.

Dependency direction remains inward:

```text
Web / OpenTUI / API / Edge Runner / protocol adapters
                         |
                         v
       application and durable orchestration
                         |
                         v
                 canonical domain
                         |
                         v
 PostgreSQL / OPA / evidence / workflow adapters
```

## Inspection flow

```text
Evidence -> Observation -> Claim -> Adjudication -> Finding -> Report
```

Agents do not construct findings. A finding is an adjudicated conclusion with evidence references, rationale, severity, remediation guidance, verification steps, and confidence.

## Detection and response flow

```text
External event -> canonical SecurityEvent -> durable detection work
-> DetectionRun / Signal -> explicit triage -> Correlation / Hunt
-> Observation / Claim -> Adjudication -> Incident -> ResponseProposal
-> OPA -> Human Approval
```

A `Signal` cannot directly create an Incident. Hunt output must become canonical evidence and claims before adjudication. OPA and human approval govern proposals only: **v0.3 has no response executor, and approval does not execute an action.**

This public architecture describes the generic SecScanMonitor platform only. Private products, operational evidence, and private qualification artifacts are outside the public boundary.
