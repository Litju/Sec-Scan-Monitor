"""Adjudication engine (ADR-0011).

Claims + evidence are adjudicated to CONFIRMED / SUPPORTED / INCONCLUSIVE /
REJECTED. A Finding can only be created through adjudication — this module
is the only construction site for Findings in the platform.

Inputs: claims, supporting/contradicting evidence, specialist identity,
tool confidence, engagement scope. Confidence stays categorical; no
fabricated numeric calibration.
"""

from __future__ import annotations

from secscan.platform.domain.common import Confidence, Severity
from secscan.platform.domain.evidence import Claim
from secscan.platform.domain.finding import Adjudication, AdjudicationVerdict, Finding
from secscan.platform.domain.ids import (
    AdjudicationId,
    EngagementId,
    EvidenceId,
    FindingId,
    PrincipalId,
    new_id,
)


class AdjudicationInputError(ValueError):
    """Malformed adjudication request."""


class AdjudicationService:
    """Deterministic verdict engine over claims and evidence."""

    def adjudicate(
        self,
        *,
        engagement_id: EngagementId,
        claim: Claim,
        supporting_evidence_ids: list[str],
        contradicting_evidence_ids: list[str],
        specialist_identity: str,
        tool_confidence: Confidence | None = None,
        scope_note: str = "",
        severity: Severity | None = None,
        decided_by_principal_id: PrincipalId,
    ) -> tuple[Adjudication, Finding | None]:
        """Adjudicate one claim. Returns (adjudication, finding-or-None).

        CONFIRMED/SUPPORTED produce a Finding; INCONCLUSIVE/REJECTED do not.
        """
        if claim.engagement_id != engagement_id:
            raise AdjudicationInputError(
                f"claim {claim.claim_id} belongs to engagement {claim.engagement_id}, not {engagement_id}"
            )

        evidence_ok = bool(claim.evidence_ids) or bool(supporting_evidence_ids)
        contradicted = bool(contradicting_evidence_ids)

        if contradicted and not evidence_ok:
            verdict = AdjudicationVerdict.REJECTED
            confidence = Confidence.HIGH
        elif contradicted:
            verdict = AdjudicationVerdict.INCONCLUSIVE
            confidence = Confidence.UNKNOWN
        elif not evidence_ok:
            verdict = AdjudicationVerdict.INCONCLUSIVE
            confidence = Confidence.UNKNOWN
        else:
            # Evidence exists, no contradiction: corroboration strength
            # drives CONFIRMED vs SUPPORTED.
            if claim.confidence == Confidence.HIGH and tool_confidence in {None, Confidence.HIGH}:
                verdict = AdjudicationVerdict.CONFIRMED
                confidence = Confidence.HIGH
            else:
                verdict = AdjudicationVerdict.SUPPORTED
                confidence = claim.confidence if claim.confidence != Confidence.UNKNOWN else Confidence.MEDIUM

        rationale = _rationale(verdict, claim, contradicted, specialist_identity)

        def _as_evidence_ids(values: list[str]) -> list[EvidenceId]:
            return [EvidenceId(value) for value in values]

        supporting = _as_evidence_ids(supporting_evidence_ids) or claim.evidence_ids
        contradicting = _as_evidence_ids(contradicting_evidence_ids)
        adjudication = Adjudication(
            adjudication_id=AdjudicationId(new_id("ADJ")),
            engagement_id=engagement_id,
            claim_ids=[claim.claim_id],
            supporting_evidence_ids=supporting,
            contradicting_evidence_ids=contradicting,
            verdict=verdict,
            rationale=rationale,
            confidence=confidence,
            specialist_identity=specialist_identity,
            tool_confidence=tool_confidence,
            scope_note=scope_note,
            decided_by_principal_id=decided_by_principal_id,
        )

        finding: Finding | None = None
        if verdict in {AdjudicationVerdict.CONFIRMED, AdjudicationVerdict.SUPPORTED}:
            if severity is None:
                raise AdjudicationInputError(
                    "severity is required to create a Finding from a confirmed/supported claim"
                )
            finding = Finding(
                finding_id=FindingId(new_id("FIN")),
                engagement_id=engagement_id,
                originating_adjudication_id=adjudication.adjudication_id,
                title=(
                    claim.statement
                    if len(claim.statement) <= 255
                    else claim.statement[:252].rsplit(" ", 1)[0] + "..."
                ),
                severity=severity,
                summary=claim.statement,
                supporting_evidence_ids=adjudication.supporting_evidence_ids,
                contradicting_evidence_ids=adjudication.contradicting_evidence_ids,
                rationale=rationale,
                confidence=confidence,
            )
        return adjudication, finding

def _rationale(
    verdict: AdjudicationVerdict,
    claim: Claim,
    contradicted: bool,
    specialist_identity: str,
) -> str:
    base = f"claim {claim.claim_id} by {claim.agent_id} ({specialist_identity or 'unattributed'})"
    if verdict == AdjudicationVerdict.CONFIRMED:
        return f"{base}: evidence corroborates with high confidence; no contradicting evidence."
    if verdict == AdjudicationVerdict.SUPPORTED:
        return f"{base}: evidence supports the claim; categorical confidence {claim.confidence.value}."
    if verdict == AdjudicationVerdict.INCONCLUSIVE:
        if contradicted:
            return f"{base}: supporting and contradicting evidence both present; inconclusive."
        return f"{base}: insufficient evidence; inconclusive."
    return f"{base}: no evidence and/or contradiction; rejected."
