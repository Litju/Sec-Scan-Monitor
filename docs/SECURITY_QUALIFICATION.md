# Public security qualification

Status: `PASS_WITH_LIMITATIONS` for the qualified v0.3 publication. Live qualification and exported-tree qualification are separate evidence scopes.

## Private/live qualification

Controlled synthetic telemetry exercised real loopback network transport, PostgreSQL 16.6, repository-pinned OPA 1.19.0, separate producer/API/worker processes, MCP/A2A, Edge Runner, Web, and OpenTUI.

Qualified behavior included the benign no-noise baseline; endpoint, cloud/identity, and agent/MCP scenarios; correlation; Hunt; Incident adjudication; governed `ResponseProposal`; restart/replay; scope denial; failure injection; and integrated Web/TUI operation.

Measured regression evidence:

- Python: 489 passed, 1 explicit environment skip; focused detection/live/continuous suite: 57 passed.
- PostgreSQL: migrations 1, RLS 1, integration 13, side-effect 2, inspection 1; single Alembic head `v03live03`.
- Web: 23 tests, typecheck, lint with 0 errors, and production build.
- Playwright: 12 preview and 1 live check, including accessibility, responsiveness, and visual coverage.
- OpenTUI: 6 tests, typecheck, build, and real runtime attestation.
- mypy: 129 source files; Ruff: pass; read-only MCP: 31 tests.
- Gitleaks: pass; TruffleHog: 0 verified and 0 unverified; OSV-Scanner: no issues; pip-audit: no known vulnerabilities; npm audit: root, Web, OpenTUI, and MCP all 0.

These measurements are qualification evidence, not customer production validation or product benchmarks.

## Public exported-tree qualification

- Public PR: [#12](https://github.com/Litju/Sec-Scan-Monitor/pull/12)
- Public PR head: `90694207284b3a7b4f2d8a9b9725bad2e6c7847b`
- Public main/merge commit: `4bc8346868534731c001beee5e5eb9a634699adf`
- Deterministic export: 306 files
- Export tree SHA-256: `e19d4ac4c26ae06e2575708699a3d61f6a37041097610d94d5da1236220b3ef7`
- License SHA-256: `f85d4c7ec5f306e30aff6eff5e49f108c773f4e0c629c595c8e463b2816cacd3`
- SBOM SHA-256: `806ef6e7144349e17d74adf91352e4fe36f4bde846b040f7475e984cc10d8bf8`
- Clean-clone qualification: pass
- Public drift: 0
- Scientific-content leakage: 0
- Secret leakage: 0
- Private-path leakage: 0

The exported tree was checked with its Python suite, mypy, Ruff, Web tests/typecheck/lint/build, OpenTUI tests/typecheck/build, Playwright accessibility, Gitleaks, TruffleHog, OSV-Scanner, pip-audit, npm audit, license checks, deterministic CycloneDX SBOM generation, and explicit private/scientific/secret/path leakage checks. OpenTUI and the broader live topology were qualified separately rather than inferred from the public CI run.

## Limitations

- No production deployment, formal release, or tag was performed.
- v0.3 has no response executor and no DFIR capability.
- Sigma compatibility is a bounded subset.
- Performance measurements are qualification-only; memory was not measured.
- Public exported-tree checks do not independently prove the private live topology; the scopes remain deliberately separate.
