# Agent authority model

Agents are bounded workers, not autonomous administrators.

The coordinator can read a contract, select an allowed specialist, and request registered capabilities. The security specialist can produce observations and claims. Both have an inspection ceiling and cannot create findings, execute arbitrary shell commands, mutate a target, or bypass policy.

The authority path is:

```text
engagement contract -> principal binding -> capability registry -> policy decision -> approval when required -> bounded execution
```

Unknown scope, missing target, missing grant, mismatched identifiers, unsupported tool output, or absent approval fails closed. A human approval is a recorded, request-bound fact; it is not inferred from a role name or a browser header.
