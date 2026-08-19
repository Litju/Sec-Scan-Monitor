# Engagement Protocol

| Field | Value |
|---|---|
| version | firm-v1 |
| status | active |
| authority | Charter §5–§7; pinned by `.secscan/policy.yaml` |

The engagement protocol defines how the firm is hired, how it refuses, how it works, and how it reports. It applies to every client of the firm, including the firm itself (dogfood engagements).

## 1. Intake contract (required for every engagement)

| Field | Required | Meaning |
|---|---|---|
| engagement_id | yes | `ENG-<year>-<seq>` (filed in `ledgers/engagement-ledger.yaml`) |
| requester | yes | Who hires the firm (agent, workflow, or operator) |
| target | yes | The repository, workspace, or artifact set under review |
| scope | yes | Files, dirs, systems, and data in scope; explicit exclusions |
| pass_type | yes | One of: `diff-gate`, `posture`, `triage`, `briefing`, `drift-review` |
| authority_level | yes | `inspection-only` (default) or `remediation` (explicit, per-change) |
| constraints | no | Time box, output channel, redaction requirements, stop conditions |

Missing target, scope, pass type, or authority level → **refusal** (recorded with reason).

## 2. Pass types

| Pass type | Personas typically deployed | Default authority | Output |
|---|---|---|---|
| `diff-gate` — PR/diff security review | Red Team, Compliance | inspection-only | Findings on the diff, go/no-go for merge |
| `posture` — full repo/workspace assessment | Blue Team, Red Team, Compliance, Drift | inspection-only | Severity-scored posture report |
| `triage` — incident triage | Forensics, Blue Team | inspection-only | Triage summary, containment + recovery guidance |
| `briefing` — advisory research | Threat Intel | inspection-only | Cited brief with open questions |
| `drift-review` — design vs. implementation | Architecture & Drift | inspection-only | Drift report with correction packet |

## 3. Authority levels

- **inspection-only (default)**: read, analyze, report. No writes to the target, no config changes, no remediation.
- **remediation**: only with explicit per-change authority in the contract. Each remediation is staged: evidence → dry-run/report → explicit go → apply → verify → rollback note. Remediation never includes secret handling or architecture changes.

## 4. Engagement lifecycle

1. **Intake** — requester submits the intake contract fields.
2. **Decision** — Firm Coordinator accepts or refuses. Refusal reasons: out-of-scope target, secret-laden scope, missing contract fields, charter conflict. Refusals are recorded.
3. **Deploy** — Coordinator selects personas; each loads its skill and scope.
4. **Review** — Specialists execute. Evidence captured with chain of custody (source, timestamp, sanitization record). No target mutation without authority.
5. **Compile** — Coordinator assembles the firm report.
6. **Verify** — Report is checked: every finding has evidence, every severity is justified, no secret material appears, no unsupported claims.
7. **Close** — Report delivered; engagement record filed; findings tracked to closure or explicitly waived by the requester.

## 5. Firm report format

Every firm report contains:

```text
ENGAGEMENT: <engagement_id> (<pass_type>, <authority_level>)
TARGET: <target>
SCOPE: <scope>
DATE: <timestamp>
PERSONAS: <deployed personas>

1. EXECUTIVE SUMMARY
   verdict, headline risks, go/no-go (where applicable)
2. FINDINGS
   per finding: id, severity (Critical/High/Medium/Low), title,
   evidence (source + command/output reference), impact,
   remediation guidance, verification step
3. GAPS AND ASSUMPTIONS
   what was not validated, open questions
4. SECRET-SCAN SUMMARY
   existence flags only; never reproduces material
5. CHAIN-OF-CUSTODY RECORD
   sources read, timestamps, sanitization applied
6. GO/NO-GO OR NEXT STEPS
```

Severity scale (fixed):

- **Critical**: exploitable exposure, secret material, broken auth, data-loss path
- **High**: likely compromise path, lockout risk, missing rollback for state changes
- **Medium**: weakened posture, missing validation, unclear control
- **Low**: hygiene, consistency, documentation

## 6. Refusal rules

The firm refuses (and records) engagements where:

- the target or scope is not declared
- the pass type or authority level is missing
- the scope would require reading secret material beyond the contract
- the requested work would violate a charter principle
- the requester is not authorized for the target

Refusal is a feature: it is the firm enforcing its own boundaries.

## 7. Dogfooding

The firm applies this protocol to itself. Internal reviews (repository changes, governance patches, phase gates) are engagements with `requester: internal-swarm` and the same record-keeping. The firm's own repo is audited at least at every phase gate.
