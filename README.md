# SecScanMonitor

[![CI](https://github.com/Litju/Sec-Scan-Monitor/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Litju/Sec-Scan-Monitor/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Litju/Sec-Scan-Monitor/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/Litju/Sec-Scan-Monitor/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/Litju/Sec-Scan-Monitor/badge)](https://securityscorecards.dev/viewer/?uri=github.com/Litju/Sec-Scan-Monitor)
[![License](https://img.shields.io/badge/license-source--available-5b6472.svg)](LICENSE)

<p align="center"><img src="apps/web/app/icon.svg" alt="SecScanMonitor product mark" width="128"></p>

> **SecScanMonitor is an evidence-first autonomous cybersecurity firm platform for software, AI agents, MCP/A2A systems, workflows, and agent-built systems.**

It is not a chatbot, a generic SIEM, or an autonomous hacking agent. Security work remains contract-bound, evidence-grounded, advisory-first, and subject to explicit authority.

This repository is **SOURCE-VISIBLE / SOURCE-AVAILABLE**. It is **NOT OPEN SOURCE**. The restrictive evaluation license permits viewing, permitted cloning, and private execution of unmodified copies for non-production evaluation, testing, security research, or assessment of a potential commercial license. See [LICENSE](LICENSE).

## Current capabilities

### Inspection

- AppSec
- Agent Security
- Vulnerability Intelligence
- Supply Chain

### Continuous Security

- Security Graph and Security Event Plane
- Continuous Patrol with no-change/no-noise semantics
- MCP/A2A Agent Security Gateway and customer-side Edge Runner
- restart/replay reconstruction from canonical state

### Detection & Response — v0.3

- authenticated, scope-bound security-event ingest into canonical PostgreSQL `SecurityEvent` records;
- durable detection orchestration, bounded Sigma-compatible rules, `DetectionRun` records, and `Signal` records;
- bounded correlation, Threat Hunting, and `IncidentHypothesis` records;
- canonical evidence and claims, adjudication, and explicit Incident creation;
- governed `ResponseProposal` records evaluated by real OPA and requiring human approval.

**RESPONSE EXECUTION IS NOT ENABLED.**

### Product surfaces

The Web Command Center, OpenTUI Operator Console, and API consume shared canonical state. Preview data remains available for safe evaluation, but it is not the qualified live topology.

## Canonical chains

Inspection:

```text
Evidence -> Observation -> Claim -> Adjudication -> Finding -> Report
```

Detection & Response:

```text
External Security Source -> SecurityEvent -> DetectionRun -> Signal
-> Correlation / Hunt -> IncidentHypothesis -> Observation / Claim
-> Adjudication -> Incident -> ResponseProposal -> OPA -> Human Approval
```

Signal != Incident. Tool output != truth. ATT&CK/ATLAS mapping != proof. LLM != authority. Approval != execution.

## v0.3 qualification status

The v0.3 system was qualified with controlled synthetic live telemetry using real network transport, PostgreSQL, repository-pinned OPA, separate producer, API, and worker processes, MCP/A2A, Edge Runner, Web, and OpenTUI.

The campaign qualified a benign no-noise baseline; endpoint, cloud/identity, and agent/MCP scenarios; correlation; Hunt; Incident adjudication; `ResponseProposal`; restart/replay; cross-tenant and cross-case denial; failure injection; and integrated Web/TUI operation. This is controlled qualification evidence, not customer production validation.

Limitations: there is no production deployment, formal release or tag, response executor, or DFIR capability. Sigma compatibility is a bounded subset. Performance figures are qualification-only and are not product benchmarks.

## Run it locally

### Platform core

```bash
cd analysis
python -m venv .venv
python -m pip install -e '.[dev]'
python -m pytest -q
python -m mypy src
python -m ruff check src tests
```

### Web Command Center

```bash
cd apps/web
npm ci
npm test
npm run typecheck
npm run lint
npm run build
```

### OpenTUI Operator Console

```bash
cd apps/tui
npm ci
npm test
npm run typecheck
npm run build
```

The default safe evaluation mode may use synthetic preview data. Integrated live mode requires the documented PostgreSQL, repository-pinned OPA, API, and worker environment. See [Development](docs/DEVELOPMENT.md) and the [Security model](docs/SECURITY_MODEL.md).

## Public boundary

The public tree is an exact, deterministic export. It contains generic platform code, public contracts, synthetic examples, and security controls. It does not contain client material, raw evidence, credentials, private history, or private qualification artifacts. Unknown files and secret-like or path-identifying content fail the export.

Issues and security reports may be accepted, but external source-code contributions require separate written authorization. See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).
