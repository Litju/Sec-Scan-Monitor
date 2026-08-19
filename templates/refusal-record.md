# Refusal Record

Record type: `refusal-record` | Filed in: `ledgers/engagement-ledger.yaml`

```yaml
- engagement_id: ENG-<year>-<seq>
  date: <YYYY-MM-DD>
  requester: <agent | workflow | operator>
  requested_target: <as declared by requester>
  decision: refused
  refusal_reason: <one of the refusal rules below>
  detail: <short factual explanation; no secrets reproduced>
  required_to_proceed: <what the requester must provide or change>
```

Refusal rules (`contracts/engagement-protocol.md` §6) — the firm refuses and records engagements where:

- the target or scope is not declared
- the pass type or authority level is missing
- the scope would require reading secret material beyond the contract
- the requested work would violate a charter principle
- the requester is not authorized for the target

A refusal is the firm enforcing its own boundaries, not a failure of the engagement process.
