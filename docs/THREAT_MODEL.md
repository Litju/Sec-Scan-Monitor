# Threat model

The public foundation considers:

- malicious or compromised target repositories;
- untrusted scanner and model output;
- prompt injection in target documentation;
- confused-deputy requests from an agent or browser;
- credential and personal-data exposure;
- replay, duplicate side effects, and stale state;
- unsafe sandbox commands, network escape, and resource exhaustion;
- supply-chain compromise in dependencies, actions, images, and generated artifacts;
- false confidence caused by missing or unqualified tools.

Primary mitigations are contract binding, capability allowlists, fail-closed policy, immutable snapshot expectations, sandboxing, no-network defaults for scanner capabilities, deterministic evidence, idempotency keys, redaction, pinned dependencies/actions/images, and explicit qualification receipts.

Residual risk: hosted identity, managed storage, production orchestration, external model providers, and live target behavior are `NOT_VALIDATED` by this public foundation.
