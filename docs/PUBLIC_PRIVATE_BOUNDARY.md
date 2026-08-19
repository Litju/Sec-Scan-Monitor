# Public/private boundary

The public repository contains reusable platform code, public contracts, synthetic examples, local development documentation, and security controls that can be reviewed without operational context.

Private-only material includes engagement records, client names and reports, raw or exported evidence, ledgers, recovery material, local environment files, credentials, deployment identifiers, private qualification receipts, caches, binaries, legacy archives, and any artifact that identifies a private operator or workspace.

The export is an explicit source-to-destination map. It is not a heuristic scrubber and it does not infer that an unclassified file is safe. Unknown, symlinked, binary, secret-like, client-specific, path-identifying, or license-uncleared material blocks the export.

The private release state records source revision, manifest digest, exporter version, public tree digest, and the public commit after publication. The public tree contains no private repository history.
