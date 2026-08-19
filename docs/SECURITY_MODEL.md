# Security model

SecScanMonitor treats every target and tool output as untrusted input. The public foundation enforces these controls:

- inspection-only authority by default;
- explicit engagement, target, scope, and principal binding;
- fail-closed policy decisions for unknown actions, capabilities, grants, and approvals;
- sandbox boundaries for command-capable adapters;
- metadata and content-addressed evidence separation;
- deterministic sanitization before evidence/report persistence;
- no raw secrets, credentials, private keys, personal data, or raw target evidence in public artifacts;
- no direct agent-to-database or browser-to-database path;
- explicit unavailable and `NOT_VALIDATED` states instead of fallback claims.

The model is advisory. It does not authorize exploit attempts, production active testing, credential testing, target mutation, or deployment changes without an engagement contract and explicit authority.
