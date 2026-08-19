from __future__ import annotations

from secscan.contracts.enums import FindingSeverity
from secscan.reports.firm_report import FirmFinding, FirmReport, build_firm_report


def test_report_build_is_typed_and_advisory_scoped() -> None:
    finding = FirmFinding(
        finding_id="F-PUBLIC-001",
        severity=FindingSeverity.LOW,
        title="Synthetic observation",
        evidence="Synthetic evidence only.",
        impact="No live target impact established.",
        remediation="Review the bounded observation.",
        verification="Repeat the local fixture check.",
    )
    report = FirmReport(
        engagement_id="ENG-PUBLIC-001",
        target="Synthetic agent platform",
        scope="Inspection-only fixture",
        pass_type="briefing",
        date="2026-08-16",
        personas=["reviewer"],
        findings=[finding],
    )
    rendered, notes = build_firm_report(report)
    assert "F-PUBLIC-001" in rendered
    assert "inspection-only" in rendered
    assert isinstance(notes, list)
