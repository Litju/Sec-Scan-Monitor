# Evidence and adjudication

Evidence is retained with source identity, timestamps, content address, tool identity, invocation identity, sanitization state, and chain-of-custody metadata. Raw bytes are kept behind the evidence-store boundary and are never an unrestricted API response.

The public finding lifecycle is:

1. A bounded capability emits evidence metadata or sanitized output.
2. An observation records what the evidence supports.
3. A claim states a conclusion with uncertainty and evidence references.
4. Adjudication evaluates supporting and contradicting evidence and records a verdict.
5. Only the adjudication service constructs a finding.

`INCONCLUSIVE`, `UNKNOWN`, and `NOT_VALIDATED` are first-class outcomes. A clean scan, an unavailable tool, or an empty preview fixture is not evidence of zero risk.
