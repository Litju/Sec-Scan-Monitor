# Public security qualification

Status: `PASS_WITH_LIMITATIONS` for the local source-visible public surface as of 2026-08-19.

The clean-clone qualification completed before publication:

- exact fail-closed allowlisted export: 253 UTF-8 text files; two independent exports
  produced the same per-file hashes and tree hash;
- Python: 177 passed, 5 explicitly recorded integration skips, strict mypy passed,
  and Ruff passed;
- web: 18 unit tests passed, typecheck, lint, npm audit, and production build passed;
- Playwright: 3 accessibility/product-flow checks passed;
- OPA: public policy tests passed with the separately downloaded and checksum-verified
  v1.19.0 Windows binary; the binary is not part of the public tree;
- sandbox: public-safe unit and refusal semantics passed;
- database migration: clean SQLite run reached `b7e2f1a4c903 (head)`;
- deterministic CycloneDX SBOM generation and its test passed;
- exporter secret-pattern scan, scientific deny-term scan, private-path scan, and
  binary scan returned zero matches.

This document is intentionally conservative. These checks do not qualify hosted
operation, external identity, production storage, active testing, live model use,
or current state of any external system. The skipped MCP reference-desk smoke
checks and PostgreSQL side-effect-ledger checks remain `NOT_VALIDATED`; they are
optional external integrations and are not hidden behind a clean-clone PASS.

Qualification evidence must record:

- source, public commit, commands, timestamps, and sanitized output references;
- secret, privacy, PII, local-path, binary, dependency-license, and deterministic-export results;
- evidence → observation → claim → adjudication → finding behavior;
- no raw evidence or credential values;
- all skipped or unavailable integrations as `NOT_VALIDATED`;
- unresolved Critical or High findings as blockers.
