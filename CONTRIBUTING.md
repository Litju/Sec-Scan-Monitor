# Contributing

Contributions must preserve SecScanMonitor’s advisory-first boundary.

External source-code contributions are not accepted unless explicitly
authorized under a separate written contribution agreement. Issues and private
security reports may still be accepted; opening one does not grant source-code
ownership or any license beyond the root LICENSE.

Before opening a pull request:

1. Read [GOVERNANCE.md](GOVERNANCE.md), [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md), and [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).
2. Keep changes inspection-only unless the change is explicitly documented as a local implementation detail with a rollback path.
3. Do not add credentials, private keys, personal data, client names, raw evidence, reports, ledgers, screenshots containing sensitive material, or local-machine paths.
4. Add or update a deterministic test for non-trivial behavior.
5. Run the Python and web checks relevant to the changed area.
6. State what was verified and what remains `NOT_VALIDATED`.

Pull requests should explain the authority boundary, evidence path, failure behavior, and any public/private classification decision. Do not use pull_request_target workflows or introduce unpinned action references. Maintainers may close source-change pull requests that lack written authorization.
