"""Firm report builder: engagement-scoped findings, sanitization, and rendering.

This module wires the case engine (sanitize + contract discipline) into firm
report production. Reports are rendered from typed engagement findings with
redaction by construction: every free-text field passes through
`secscan.sanitize.filters.scrub_text`, and the rendered output is re-checked
against secret-like patterns before it is allowed out.

Canonical authority: `contracts/engagement-protocol.md` section 5 (report
format) and the severity scale defined there.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict

from secscan.contracts.enums import FindingSeverity
from secscan.sanitize.filters import payload_contains_secret_like_content, scrub_text

PassType = Literal["diff-gate", "posture", "triage", "briefing", "drift-review"]
AuthorityLevel = Literal["inspection-only", "remediation"]
Verdict = Literal["go", "conditional", "no-go"]


class FirmFinding(BaseModel):
    """One severity-scored finding in a firm report."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str
    severity: FindingSeverity
    title: str
    evidence: str
    impact: str
    remediation: str
    verification: str


class FirmReport(BaseModel):
    """Typed engagement report matching the engagement protocol format."""

    model_config = ConfigDict(extra="forbid")

    engagement_id: str
    target: str
    scope: str
    pass_type: PassType
    authority_level: AuthorityLevel = "inspection-only"
    date: str
    personas: list[str]
    findings: list[FirmFinding] = []
    gaps: list[str] = []
    secret_scan_summary: str = "No secret-like material detected."
    custody_notes: list[str] = []
    verdict: Verdict = "go"


class FirmReportSanitizationError(RuntimeError):
    """Raised when rendered report output still contains secret-like content."""


def sanitize_firm_report(report: FirmReport) -> tuple[FirmReport, list[str]]:
    """Return a sanitized copy of the report plus sanitization notes.

    Every free-text field is scrubbed deterministically. Hostname aliases
    are intentionally not applied here: the firm report carries no
    host-identifying fields by design.
    """

    notes: list[str] = []

    def scrub(value: str) -> str:
        scrubbed, scrub_notes = scrub_text(value)
        notes.extend(scrub_notes)
        return scrubbed

    sanitized_findings = [
        finding.model_copy(
            update={
                "title": scrub(finding.title),
                "evidence": scrub(finding.evidence),
                "impact": scrub(finding.impact),
                "remediation": scrub(finding.remediation),
                "verification": scrub(finding.verification),
            },
        )
        for finding in report.findings
    ]
    return report.model_copy(
        update={
            "target": scrub(report.target),
            "scope": scrub(report.scope),
            "secret_scan_summary": scrub(report.secret_scan_summary),
            "gaps": [scrub(gap) for gap in report.gaps],
            "custody_notes": [scrub(note) for note in report.custody_notes],
            "findings": sanitized_findings,
        },
    ), notes


def render_firm_report(report: FirmReport) -> str:
    """Render the typed report into the protocol markdown format."""

    lines = [
        f"ENGAGEMENT: {report.engagement_id} ({report.pass_type}, {report.authority_level})",
        f"TARGET: {report.target}",
        f"SCOPE: {report.scope}",
        f"DATE: {report.date}",
        f"PERSONAS: {', '.join(report.personas) if report.personas else 'not recorded'}",
        "",
        "1. EXECUTIVE SUMMARY",
        f"   verdict: {report.verdict}",
        f"   findings: {len(report.findings)}",
        "",
        "2. FINDINGS",
    ]
    for finding in report.findings:
        lines.extend(
            [
                f"   - {finding.finding_id} [{finding.severity.value.upper()}] {finding.title}",
                f"     evidence: {finding.evidence}",
                f"     impact: {finding.impact}",
                f"     remediation: {finding.remediation}",
                f"     verification: {finding.verification}",
            ],
        )
    if not report.findings:
        lines.append("   (none)")
    lines.extend(
        [
            "",
            "3. GAPS AND ASSUMPTIONS",
        ],
    )
    lines.extend(f"   - {gap}" for gap in report.gaps) if report.gaps else lines.append("   (none)")
    lines.extend(
        [
            "",
            "4. SECRET-SCAN SUMMARY",
            f"   {report.secret_scan_summary}",
            "",
            "5. CHAIN-OF-CUSTODY RECORD",
        ],
    )
    lines.extend(f"   - {note}" for note in report.custody_notes) if report.custody_notes else lines.append("   (none)")
    lines.extend(
        [
            "",
            "6. GO/NO-GO OR NEXT STEPS",
            f"   verdict: {report.verdict}",
        ],
    )
    return "\n".join(lines) + "\n"


def build_firm_report(report: FirmReport) -> tuple[str, list[str]]:
    """Sanitize, render, and assert the no-secrets guarantee.

    Returns (rendered_markdown, sanitization_notes). Raises
    FirmReportSanitizationError if the final output still contains
    secret-like content.
    """

    sanitized, notes = sanitize_firm_report(report)
    rendered = render_firm_report(sanitized)
    if payload_contains_secret_like_content(rendered):
        raise FirmReportSanitizationError(
            "rendered firm report still contains secret-like content; report blocked",
        )
    return rendered, notes
