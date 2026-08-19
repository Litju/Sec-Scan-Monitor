# SecScanMonitor

[![CI](https://github.com/Litju/Sec-Scan-Monitor/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Litju/Sec-Scan-Monitor/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Litju/Sec-Scan-Monitor/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/Litju/Sec-Scan-Monitor/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/Litju/Sec-Scan-Monitor/badge)](https://securityscorecards.dev/viewer/?uri=github.com/Litju/Sec-Scan-Monitor)
[![License](https://img.shields.io/badge/license-source--available-5b6472.svg)](LICENSE)

<p align="center">
  <img src="apps/web/app/icon.svg" alt="SecScanMonitor product mark" width="128">
</p>

> **SecScanMonitor is an evidence-first cybersecurity platform for AI agents, workflows, and agent-built software.**

This repository is a source-visible/source-available publication. It is **not
open source**. The restrictive evaluation license permits viewing, permitted
cloning, and private execution of unmodified copies for non-production
evaluation, testing, security research, or assessment of a potential
commercial license. See LICENSE.

## Platform scope

SecScanMonitor keeps security work bounded, evidence-first, and advisory-first:

- **Cases and targets:** contract-bound engagements with explicit scope,
  authority, and lifecycle state.
- **Agent security:** inspection paths for agent-built systems, workflows, and
  software without allowing an agent to self-authorize or create a finding.
- **Policy and execution:** deterministic OPA decisions, capability manifests,
  sandboxed execution boundaries, and refusal on missing authority.
- **Evidence and adjudication:** provenance-backed evidence, observations,
  claims, adjudication, Findings, and advisory reports.
- **Security services:** generic extension contracts for AppSec, vulnerability
  intelligence, supply-chain security, and other bounded specialist services.
- **Product surfaces:** local APIs, controlled read models, a public UI, and
  synthetic examples for safe evaluation.

The canonical chain is:

    EvidenceObject -> Observation -> Claim -> Adjudication -> Finding -> Report

Agents produce claims with evidence references. Adjudication is the control
point for authoritative Findings; incomplete evidence remains explicitly
uncertain or not validated.

## Architecture

The platform uses inward dependency direction:

    adapters -> application -> domain

PostgreSQL, OPA, Temporal, Docker sandboxing, object storage, and FastAPI are
replaceable adapters around the platform contracts. The public UI defaults to a
read-only synthetic preview. Hosted operation, live external systems, and
production deployment are not validated by this publication.

## Run it locally

### Platform core

    cd analysis
    python -m venv .venv
    python -m pip install -e '.[dev]'
    python -m pytest -q
    python -m mypy src
    python -m ruff check src tests

### Web surface

    cd apps/web
    npm ci
    npm test
    npm run typecheck
    npm run lint
    npm run build

The web application uses synthetic, non-personal, non-client data by default.
Read docs/DEVELOPMENT.md for the local loop and docs/SECURITY_MODEL.md for the
security boundary.

## Public boundary

The public tree is an exact, deterministic export. It contains generic
platform code, public contracts, synthetic examples, and security controls. It
does not contain client material, raw evidence, credentials, private history,
or private qualification artifacts. Unknown files and secret-like or
path-identifying content fail the export.

Issues and security reports may be accepted, but external source-code
contributions require separate written authorization. See CONTRIBUTING.md and
SECURITY.md.
