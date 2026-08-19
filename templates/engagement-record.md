# Engagement Record

Record type: `engagement-record` | Filed in: `ledgers/engagement-ledger.yaml`

```yaml
- engagement_id: ENG-<year>-<seq>
  requester: <agent | workflow | operator>
  target: <repository or workspace>
  scope: <files, dirs, systems in scope; explicit exclusions>
  pass_type: <diff-gate | posture | triage | briefing | drift-review>
  authority_level: <inspection-only | remediation>
  constraints: <time box, output channel, redaction requirements, stop conditions>
  decision: <accepted | refused>
  refusal_reason: <required when decision is refused>
  date: <YYYY-MM-DD>
  personas_deployed: [<persona skills>]
  report_path: <relative path of delivered firm report>
  verdict: <go | conditional | no-go>
  findings_count: <n>
  critical: <n>
  high: <n>
  medium: <n>
  low: <n>
  status: <open | closed>
  closure_notes: <findings tracked to closure or explicitly waived>
```

Rules:

- No engagement work without a record; the record is the contract evidence.
- Refusals are recorded with reasons (they are features, not failures).
- The report path points to the sanitized delivered report; raw evidence is never referenced by path from the record.
- No secret-like material appears anywhere in the record.
