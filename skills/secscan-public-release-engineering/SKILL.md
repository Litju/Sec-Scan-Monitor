---
name: secscan-public-release-engineering
version: 0.1.0
description: Build and review a deterministic, fail-closed sanitized public export.
---

# Public release engineering

Use this skill for a public-export pass.

## Required order

1. Verify the source repository identity and clean worktree.
2. Read the public/private boundary and export manifest.
3. Review every source-to-destination entry; unknown entries are blockers.
4. Run secret, privacy, PII, local-path, binary, license, and dependency checks without reproducing sensitive values.
5. Build the export twice from the same source revision and compare the complete tree.
6. Run public tests, clean-clone tests, synthetic dogfood, SBOM, and provenance checks.
7. Record `PASS`, `PASS_WITH_LIMITATIONS`, `NOT_VALIDATED`, or a blocker with command, output reference, and rollback path.

## Hard rules

- Do not copy private history, evidence, exports, ledgers, client artifacts, caches, binaries, credentials, personal data, or local paths.
- Do not use a heuristic scrub as authorization. The allowlist is the authorization.
- Do not publish a secret match, token fragment, private key body, or raw evidence in a report.
- Do not claim hosted or production qualification without direct evidence.
- Do not create a release tag, GitHub Release, package publication, or production deployment during a foundation export.

## Reusable lesson

Each export failure becomes a code-level guard and a regression test when the failure mode is reusable. A one-off private artifact remains excluded and is recorded without copying its contents.
