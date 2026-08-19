"""Platform report rendering — thin wrapper over the case engine.

The case engine (`secscan.reports.firm_report`) owns sanitization and
rendering; this layer adapts adjudicated platform findings into the
protocol report format and asserts the no-secrets guarantee at the platform
boundary. No reimplementation: the case engine is the single renderer.
"""

from __future__ import annotations

from secscan.platform.reports.firm_assessment import AssessmentFinding, FirmAssessmentReport
from secscan.reports.firm_report import (
    FirmFinding,
    FirmReport,
    FirmReportSanitizationError,
    render_firm_report,
)

__all__ = [
    "FirmFinding",
    "AssessmentFinding",
    "FirmAssessmentReport",
    "FirmReport",
    "FirmReportSanitizationError",
    "render_firm_report",
]
