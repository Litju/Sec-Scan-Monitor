# Firm Report

Record type: `firm-report` | Format: `contracts/engagement-protocol.md` §5

```text
ENGAGEMENT: <engagement_id> (<pass_type>, <authority_level>)
TARGET: <target>
SCOPE: <scope>
DATE: <timestamp>
PERSONAS: <deployed personas>

1. EXECUTIVE SUMMARY
   verdict: <go | conditional | no-go>
   headline risks: <short list>

2. FINDINGS
   - <finding_id> [<SEVERITY>] <title>
     evidence: <source + command/output reference>
     impact: <what it means>
     remediation: <guidance>
     verification: <how to confirm the fix>

3. GAPS AND ASSUMPTIONS
   - <what was not validated / open questions>

4. SECRET-SCAN SUMMARY
   <existence flags only; never reproduce material>

5. CHAIN-OF-CUSTODY RECORD
   - <sources read, timestamps, sanitization applied>

6. GO/NO-GO OR NEXT STEPS
   verdict: <go | conditional | no-go>
```

Severity scale (fixed): Critical / High / Medium / Low.

- Critical: exploitable exposure, secret material, broken auth, data-loss path
- High: likely compromise path, lockout risk, missing rollback for state changes
- Medium: weakened posture, missing validation, unclear control
- Low: hygiene, consistency, documentation

The deterministic builder `analysis/src/secscan/reports/firm_report.py` renders this format from typed findings and enforces the no-secrets guarantee.
