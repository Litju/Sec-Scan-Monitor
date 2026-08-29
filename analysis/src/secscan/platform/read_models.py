"""Bounded, typed application read models.

The in-memory implementation is intentionally limited to local/test
composition. Hosted mode must inject a canonical PostgreSQL-backed service;
the API never silently falls back to this class.
"""

from __future__ import annotations

import base64
import binascii
from collections.abc import Sequence
from typing import Any, Generic, Mapping, TypeVar

from pydantic import BaseModel, ConfigDict, Field

from secscan.platform.domain.engagement import Engagement

T = TypeVar("T")


class ReadModelError(ValueError):
    """Invalid pagination or read-model input."""


class CursorPage(BaseModel, Generic[T]):
    model_config = ConfigDict(extra="forbid")

    items: list[T]
    next_cursor: str | None = None
    limit: int = Field(ge=1, le=100)


class FirmSummaryReadModel(BaseModel):
    clients: int
    targets: int
    engagements: int
    findings: int
    evidence_items: int
    audit_events: int
    data_mode: str


class ClientReadModel(BaseModel):
    client_id: str
    name: str
    contact: str | None = None


class TargetReadModel(BaseModel):
    target_id: str
    client_id: str | None = None
    kind: str
    name: str
    snapshot_id: str | None = None
    snapshot_digest: str | None = None


class EngagementReadModel(BaseModel):
    engagement_id: str
    client_id: str
    requester_principal_id: str
    target_ids: list[str]
    scope: str
    pass_type: str
    authority_level: str
    status: str
    updated_at: str


class FindingReadModel(BaseModel):
    finding_id: str
    engagement_id: str | None = None
    client_id: str | None = None
    severity: str | None = None
    confidence: str | None = None
    title: str | None = None
    summary: str | None = None
    impact: str | None = None
    status: str | None = None
    adjudication: str | None = None
    supporting_evidence_ids: list[str] = Field(default_factory=list)
    contradicting_evidence_ids: list[str] = Field(default_factory=list)
    verification_step: str | None = None
    remediation_guidance: str | None = None


class EvidenceMetadataReadModel(BaseModel):
    evidence_id: str
    engagement_id: str | None = None
    client_id: str | None = None
    sha256: str | None = None
    sanitization_state: str | None = None
    retrieval: str = "metadata-only"


class AuditEventReadModel(BaseModel):
    audit_event_id: str
    engagement_id: str | None = None
    principal_id: str | None = None
    kind: str
    summary: str
    occurred_at: str


class DetectionSignalReadModel(BaseModel):
    signal_id: str
    tenant_id: str
    case_id: str
    rule_id: str
    rule_version: int
    severity: str
    confidence: str
    status: str
    event_ids: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    source: str


class HuntReadModel(BaseModel):
    hunt_id: str
    hypothesis_id: str
    tenant_id: str
    case_id: str
    disposition: str
    status: str
    evidence_refs: list[str] = Field(default_factory=list)
    source: str


class IncidentReadModel(BaseModel):
    incident_id: str
    tenant_id: str
    case_id: str
    status: str
    severity: str
    confidence: str
    signal_ids: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    provenance_source: str
    provenance_source_type: str
    adjudicated_at: str


class ResponseProposalReadModel(BaseModel):
    proposal_id: str
    incident_id: str
    tenant_id: str
    case_id: str
    target_id: str
    action: str
    opa_decision: str
    human_approval_state: str
    status: str
    evidence_refs: list[str] = Field(default_factory=list)
    source: str


class InMemoryReadModelService:
    """Deterministic read models for preview/local/test composition only."""

    def __init__(self, state: Any) -> None:
        self._state = state

    def firm_summary(self) -> FirmSummaryReadModel:
        return FirmSummaryReadModel(
            clients=len(self._state.clients),
            targets=len(self._state.targets),
            engagements=len(self._state.engagements),
            findings=len(self._state.findings),
            evidence_items=len(self._state.evidence_metadata),
            audit_events=self._state.audit.count(),
            data_mode="SYNTHETIC / NON-PERSONAL / NON-CLIENT / QUALIFICATION_ONLY",
        )

    def list_clients(self, *, cursor: str | None = None, limit: int = 50) -> CursorPage[ClientReadModel]:
        values = [
            ClientReadModel(
                client_id=str(client_id),
                name=str(value.get("name", client_id)),
                contact=value.get("contact"),
            )
            for client_id, value in self._state.clients.items()
        ]
        return _page(sorted(values, key=lambda item: item.client_id), cursor=cursor, limit=limit)

    def list_targets(
        self,
        *,
        client_id: str | None = None,
        cursor: str | None = None,
        limit: int = 50,
    ) -> CursorPage[TargetReadModel]:
        values = []
        for target_id, value in self._state.targets.items():
            target_client_id = value.get("client_id") or _client_for_target(self._state.engagements.values(), str(target_id))
            if client_id is not None and target_client_id != client_id:
                continue
            values.append(
                TargetReadModel(
                    target_id=str(value.get("target_id", target_id)),
                    client_id=target_client_id,
                    kind=str(value.get("kind", "repository")),
                    name=str(value.get("name", target_id)),
                )
            )
        return _page(sorted(values, key=lambda item: item.target_id), cursor=cursor, limit=limit)

    def list_engagements(
        self,
        *,
        client_id: str | None = None,
        cursor: str | None = None,
        limit: int = 50,
    ) -> CursorPage[EngagementReadModel]:
        values = [_engagement_model(engagement) for engagement in self._state.engagements.values()]
        if client_id is not None:
            values = [value for value in values if value.client_id == client_id]
        return _page(sorted(values, key=lambda item: item.engagement_id), cursor=cursor, limit=limit)

    def get_engagement(self, engagement_id: str) -> EngagementReadModel | None:
        engagement = self._state.engagements.get(engagement_id)
        if engagement is None:
            engagement = next(
                (value for key, value in self._state.engagements.items() if str(key) == engagement_id),
                None,
            )
        return _engagement_model(engagement) if engagement is not None else None

    def list_findings(
        self,
        *,
        engagement_id: str | None = None,
        cursor: str | None = None,
        limit: int = 50,
    ) -> CursorPage[FindingReadModel]:
        values = [
            FindingReadModel(
                finding_id=str(finding_id),
                engagement_id=_optional_string(value.get("engagement_id")),
                client_id=_optional_string(value.get("client_id")),
                severity=_optional_string(value.get("severity")),
                confidence=_optional_string(value.get("confidence")),
                title=_optional_string(value.get("title")),
            )
            for finding_id, value in self._state.findings.items()
            if engagement_id is None or str(value.get("engagement_id")) == engagement_id
        ]
        return _page(sorted(values, key=lambda item: item.finding_id), cursor=cursor, limit=limit)

    def list_evidence(
        self,
        *,
        engagement_id: str | None = None,
        cursor: str | None = None,
        limit: int = 50,
    ) -> CursorPage[EvidenceMetadataReadModel]:
        values = [
            EvidenceMetadataReadModel(
                evidence_id=str(evidence_id),
                engagement_id=_optional_string(value.get("engagement_id")),
                client_id=_optional_string(value.get("client_id")),
                sha256=_optional_string(value.get("sha256")),
                sanitization_state=_optional_string(value.get("sanitization_state")),
            )
            for evidence_id, value in self._state.evidence_metadata.items()
            if engagement_id is None or str(value.get("engagement_id")) == engagement_id
        ]
        return _page(sorted(values, key=lambda item: item.evidence_id), cursor=cursor, limit=limit)

    def list_audit(self, *, cursor: str | None = None, limit: int = 50) -> CursorPage[AuditEventReadModel]:
        values = [
            AuditEventReadModel(
                audit_event_id=str(event.audit_event_id),
                engagement_id=str(event.engagement_id) if event.engagement_id else None,
                principal_id=str(event.principal_id) if event.principal_id else None,
                kind=event.kind.value,
                summary=event.summary,
                occurred_at=event.occurred_at.isoformat(),
            )
            for event in self._state.audit.read_since()
        ]
        return _page(sorted(values, key=lambda item: (item.occurred_at, item.audit_event_id)), cursor=cursor, limit=limit)

    def list_detection_signals(self, *, cursor: str | None = None, limit: int = 50) -> CursorPage[DetectionSignalReadModel]:
        values = [_detection_signal_model(value) for value in _state_records(self._state, "detection_signals")]
        return _page(sorted(values, key=lambda item: item.signal_id), cursor=cursor, limit=limit)

    def list_hunts(self, *, cursor: str | None = None, limit: int = 50) -> CursorPage[HuntReadModel]:
        values = [_hunt_model(value) for value in _state_records(self._state, "hunts")]
        return _page(sorted(values, key=lambda item: item.hunt_id), cursor=cursor, limit=limit)

    def list_incidents(self, *, cursor: str | None = None, limit: int = 50) -> CursorPage[IncidentReadModel]:
        values = [_incident_model(value) for value in _state_records(self._state, "incidents")]
        return _page(sorted(values, key=lambda item: item.incident_id), cursor=cursor, limit=limit)

    def list_response_proposals(self, *, cursor: str | None = None, limit: int = 50) -> CursorPage[ResponseProposalReadModel]:
        values = [_response_proposal_model(value) for value in _state_records(self._state, "response_proposals")]
        return _page(sorted(values, key=lambda item: item.proposal_id), cursor=cursor, limit=limit)

    def experience(self) -> dict[str, Any]:
        clients = {str(client_id): str(value.get("name", client_id)) for client_id, value in self._state.clients.items()}
        targets = {str(target_id): str(value.get("name", target_id)) for target_id, value in self._state.targets.items()}
        cases = self.list_engagements(limit=100).items
        findings = self.list_findings(limit=100).items
        evidence = self.list_evidence(limit=100).items
        audit = self.list_audit(limit=100).items
        return compose_experience_snapshot(
            mode="LOCAL_INTEGRATED",
            source_label="LOCAL / LOOPBACK / IN-MEMORY DEV READ MODEL",
            cases=cases,
            findings=findings,
            evidence_count_by_case={
                str(item.engagement_id): sum(1 for evidence_item in evidence if evidence_item.engagement_id == item.engagement_id)
                for item in cases
            },
            activity_count_by_case={
                str(item.engagement_id): sum(1 for audit_item in audit if audit_item.engagement_id == item.engagement_id)
                for item in cases
            },
            audit=audit,
            clients=clients,
            targets=targets,
            detection_signals=self.list_detection_signals(limit=100).items,
            hunts=self.list_hunts(limit=100).items,
            incidents=self.list_incidents(limit=100).items,
            response_proposals=self.list_response_proposals(limit=100).items,
        )


def _engagement_model(engagement: Engagement) -> EngagementReadModel:
    return EngagementReadModel(
        engagement_id=str(engagement.engagement_id),
        client_id=str(engagement.client_id),
        requester_principal_id=str(engagement.requester_principal_id),
        target_ids=[str(target_id) for target_id in engagement.target_ids],
        scope=engagement.scope,
        pass_type=engagement.pass_type.value,
        authority_level=engagement.authority_level.value,
        status=engagement.status.value,
        updated_at=engagement.updated_at.isoformat(),
    )


def compose_experience_snapshot(
    *,
    mode: str,
    source_label: str,
    cases: list[EngagementReadModel],
    findings: list[FindingReadModel],
    evidence_count_by_case: Mapping[str, int],
    activity_count_by_case: Mapping[str, int],
    audit: list[AuditEventReadModel],
    clients: Mapping[str, str],
    targets: Mapping[str, str],
    detection_signals: list[DetectionSignalReadModel],
    hunts: list[HuntReadModel],
    incidents: list[IncidentReadModel],
    response_proposals: list[ResponseProposalReadModel],
    tenant_id: str | None = None,
) -> dict[str, Any]:
    """Build the bounded operator projection from already scope-filtered DTOs."""

    selected_tenant = tenant_id or next(
        (item.tenant_id for item in detection_signals + hunts + incidents + response_proposals if item.tenant_id),
        "operator-scope",
    )

    def scope(case_id: str) -> dict[str, str]:
        return {"tenantId": selected_tenant, "caseId": case_id}

    def status(value: str, fallback: str = "UNKNOWN") -> str:
        normalized = value.upper()
        return {
            "SUPPORTS": "VERIFIED",
            "REFUTES": "CONTRADICTED",
            "REQUIRE_APPROVAL": "APPROVAL_REQUIRED",
            "ALLOW": "VERIFIED",
            "CONTAINED": "CONFIRMED",
            "RECOVERING": "CONFIRMED",
            "OPEN": "NEW",
            "CLOSED": "RESOLVED",
            "REFUSED": "DENIED",
            "REVOKED": "DENIED",
        }.get(normalized, normalized if normalized in {
            "NEW", "CHANGED", "RESOLVED", "DENIED", "APPROVAL_REQUIRED", "INCONCLUSIVE", "UNAVAILABLE",
            "DEGRADED", "VERIFIED", "CONTRADICTED", "CANDIDATE", "CONFIRMED", "DISMISSED", "APPROVED", "EXPIRED", "UNKNOWN",
        } else fallback)

    def provenance(source: str, observed_at: str, evidence_refs: list[str], state: str) -> dict[str, Any]:
        return {
            "source": source,
            "sourceType": "canonical-read-model",
            "observedAt": observed_at,
            "evidenceRefs": evidence_refs,
            "status": status(state),
        }

    case_views: list[dict[str, Any]] = []
    for case in cases:
        case_target = next((targets.get(target_id) for target_id in case.target_ids if targets.get(target_id)), None)
        case_state = status(case.status)
        case_views.append({
            "id": case.engagement_id,
            "caseId": case.engagement_id,
            "clientLabel": clients.get(case.client_id, case.client_id),
            "targetLabel": case_target or ", ".join(case.target_ids) or "target not validated",
            "state": case_state,
            "summary": f"{case.status} case · {case.scope}",
            "updatedAt": case.updated_at,
            "findingIds": [item.finding_id for item in findings if item.engagement_id == case.engagement_id],
            "evidenceCount": evidence_count_by_case.get(case.engagement_id, 0),
            "activityCount": activity_count_by_case.get(case.engagement_id, 0),
            "scope": scope(case.engagement_id),
            "provenance": provenance("canonical case read model", case.updated_at, [], case_state),
        })

    finding_views: list[dict[str, Any]] = []
    for finding in findings:
        case_id = finding.engagement_id or "unknown"
        finding_state = status(finding.adjudication or finding.status or "UNKNOWN")
        finding_views.append({
            "id": finding.finding_id,
            "findingId": finding.finding_id,
            "caseId": case_id,
            "title": finding.title or finding.summary or "Canonical finding",
            "severity": finding.severity or "UNKNOWN",
            "state": finding_state,
            "adjudication": finding_state,
            "evidenceRefs": list(finding.supporting_evidence_ids),
            "scope": scope(case_id),
            "provenance": provenance("canonical finding read model", "not_validated", list(finding.supporting_evidence_ids), finding_state),
        })

    activity_views: list[dict[str, Any]] = [
        {
            "id": item.audit_event_id,
            "caseId": item.engagement_id,
            "occurredAt": item.occurred_at,
            "sequence": index + 1,
            "kind": item.kind,
            "title": item.summary,
            "detail": item.summary,
            "state": status(item.kind, "UNKNOWN"),
            "evidenceRefs": [],
            "scope": scope(item.engagement_id or "unknown"),
            "source": "canonical audit read model",
        }
        for index, item in enumerate(audit)
    ]

    signal_views: list[dict[str, Any]] = [
        {
            "id": item.signal_id,
            "signalId": item.signal_id,
            "caseId": item.case_id,
            "ruleId": item.rule_id,
            "ruleVersion": item.rule_version,
            "severity": item.severity,
            "confidence": item.confidence,
            "state": status(item.status),
            "eventIds": item.event_ids,
            "evidenceRefs": item.evidence_refs,
            "scope": {"tenantId": item.tenant_id, "caseId": item.case_id},
            "source": item.source,
        }
        for item in detection_signals
    ]
    hunt_views: list[dict[str, Any]] = [
        {
            "id": item.hunt_id,
            "huntId": item.hunt_id,
            "hypothesisId": item.hypothesis_id,
            "caseId": item.case_id,
            "disposition": status(item.disposition),
            "state": status(item.status),
            "evidenceRefs": item.evidence_refs,
            "scope": {"tenantId": item.tenant_id, "caseId": item.case_id},
            "source": item.source,
        }
        for item in hunts
    ]
    incident_views: list[dict[str, Any]] = [
        {
            "id": item.incident_id,
            "incidentId": item.incident_id,
            "caseId": item.case_id,
            "state": status(item.status),
            "severity": item.severity,
            "confidence": item.confidence,
            "signalIds": item.signal_ids,
            "evidenceRefs": item.evidence_refs,
            "scope": {"tenantId": item.tenant_id, "caseId": item.case_id},
            "provenance": {
                "source": item.provenance_source,
                "sourceType": item.provenance_source_type,
                "observedAt": item.adjudicated_at,
                "evidenceRefs": item.evidence_refs,
                "status": status(item.status),
            },
        }
        for item in incidents
    ]
    proposal_views: list[dict[str, Any]] = [
        {
            "id": item.proposal_id,
            "proposalId": item.proposal_id,
            "incidentId": item.incident_id,
            "caseId": item.case_id,
            "targetId": item.target_id,
            "action": item.action,
            "opaDecision": status(item.opa_decision),
            "humanApprovalState": status(item.human_approval_state),
            "state": status(item.status),
            "evidenceRefs": item.evidence_refs,
            "scope": {"tenantId": item.tenant_id, "caseId": item.case_id},
            "source": item.source,
        }
        for item in response_proposals
    ]

    attention: list[dict[str, Any]] = []
    for item in finding_views:
        if item["state"] not in {"RESOLVED", "DISMISSED"}:
            attention.append({
                "id": f"finding-{item['findingId']}", "kind": "finding", "title": "Finding needs review",
                "detail": item["title"], "caseId": item["caseId"], "entityId": item["findingId"],
                "status": item["state"], "observedAt": item["provenance"]["observedAt"],
                "nextAction": "Inspect the adjudicated conclusion.", "evidenceRefs": item["evidenceRefs"],
                "scope": item["scope"], "source": "canonical finding projection",
            })
    for item in signal_views:
        if item["state"] in {"NEW", "CHANGED"}:
            attention.append({
                "id": f"signal-{item['signalId']}", "kind": "detection", "title": "New detection signal",
                "detail": f"{item['ruleId']} · {item['severity']}", "caseId": item["caseId"], "entityId": item["signalId"],
                "status": item["state"], "observedAt": "not_validated", "nextAction": "Inspect the bounded signal evidence.",
                "evidenceRefs": item["evidenceRefs"], "scope": item["scope"], "source": item["source"],
            })
    for item in incident_views:
        if item["state"] == "CONFIRMED":
            attention.append({
                "id": f"incident-{item['incidentId']}", "kind": "incident", "title": "Confirmed incident",
                "detail": f"{item['incidentId']} · {item['severity']}", "caseId": item["caseId"], "entityId": item["incidentId"],
                "status": item["state"], "observedAt": item["provenance"]["observedAt"], "nextAction": "Inspect adjudication provenance.",
                "evidenceRefs": item["evidenceRefs"], "scope": item["scope"], "source": item["provenance"]["source"],
            })
    for item in proposal_views:
        if item["humanApprovalState"] == "APPROVAL_REQUIRED":
            attention.append({
                "id": f"proposal-{item['proposalId']}", "kind": "response", "title": "Response proposal awaits approval",
                "detail": f"{item['action']} · {item['targetId']}", "caseId": item["caseId"], "entityId": item["proposalId"],
                "status": item["state"], "observedAt": "not_validated", "nextAction": "Review the exact human approval binding.",
                "evidenceRefs": item["evidenceRefs"], "scope": item["scope"], "source": item["source"],
            })

    return {
        "mode": mode,
        "connectionState": "CONNECTED",
        "sourceLabel": source_label,
        "tenantId": selected_tenant,
        "attention": attention,
        "cases": case_views,
        "findings": finding_views,
        "activity": activity_views,
        "graphNodes": [],
        "graphEdges": [],
        "runners": [],
        "detectionSignals": signal_views,
        "hunts": hunt_views,
        "incidents": incident_views,
        "responseProposals": proposal_views,
    }


def _state_records(state: Any, name: str) -> list[Any]:
    records = getattr(state, name, {})
    return list(records.values()) if isinstance(records, dict) else list(records)


def _record_dict(record: Any) -> dict[str, Any]:
    if isinstance(record, BaseModel):
        return record.model_dump(mode="json", by_alias=True)
    if isinstance(record, dict):
        return dict(record)
    return {key: getattr(record, key) for key in dir(record) if not key.startswith("_") and not callable(getattr(record, key))}


def _record_value(record: dict[str, Any], *names: str, default: Any = None) -> Any:
    for name in names:
        if name in record:
            return record[name]
    scope = record.get("scope")
    if isinstance(scope, dict):
        for name in names:
            if name in scope:
                return scope[name]
    return default


def _record_list(record: dict[str, Any], *names: str) -> list[str]:
    value = _record_value(record, *names, default=[])
    return [str(item) for item in value] if isinstance(value, (list, tuple, set)) else []


def _detection_signal_model(value: Any) -> DetectionSignalReadModel:
    record = _record_dict(value)
    return DetectionSignalReadModel(
        signal_id=str(_record_value(record, "signal_id", "signalId", default="unknown")),
        tenant_id=str(_record_value(record, "tenant_id", "tenantId", "tenant", default="unknown")),
        case_id=str(_record_value(record, "case_id", "caseId", "case", default="unknown")),
        rule_id=str(_record_value(record, "rule_id", "ruleId", default="unknown")),
        rule_version=int(_record_value(record, "rule_version", "ruleVersion", default=1)),
        severity=str(_record_value(record, "severity", default="UNKNOWN")),
        confidence=str(_record_value(record, "confidence", default="UNKNOWN")),
        status=str(_record_value(record, "status", "state", default="UNKNOWN")),
        event_ids=_record_list(record, "event_ids", "eventIds"),
        evidence_refs=_record_list(record, "evidence_refs", "evidenceRefs", "raw_evidence_refs", "rawEvidenceRefs"),
        source=str(_record_value(record, "source", default="local detection projection")),
    )


def _hunt_model(value: Any) -> HuntReadModel:
    record = _record_dict(value)
    disposition = str(_record_value(record, "disposition", default="INCONCLUSIVE"))
    status = "VERIFIED" if disposition == "SUPPORTS" else "CONTRADICTED" if disposition == "REFUTES" else str(_record_value(record, "status", "state", default="INCONCLUSIVE"))
    return HuntReadModel(
        hunt_id=str(_record_value(record, "hunt_id", "huntId", "execution_id", "executionId", "result_id", "resultId", default="unknown")),
        hypothesis_id=str(_record_value(record, "hypothesis_id", "hypothesisId", default="unknown")),
        tenant_id=str(_record_value(record, "tenant_id", "tenantId", "tenant", default="unknown")),
        case_id=str(_record_value(record, "case_id", "caseId", "case", default="unknown")),
        disposition=disposition,
        status=status,
        evidence_refs=_record_list(record, "evidence_refs", "evidenceRefs", "supporting_evidence_refs", "supportingEvidenceRefs"),
        source=str(_record_value(record, "source", default="local threat-hunt projection")),
    )


def _incident_model(value: Any) -> IncidentReadModel:
    record = _record_dict(value)
    return IncidentReadModel(
        incident_id=str(_record_value(record, "incident_id", "incidentId", default="unknown")),
        tenant_id=str(_record_value(record, "tenant_id", "tenantId", "tenant", default="unknown")),
        case_id=str(_record_value(record, "case_id", "caseId", "case", default="unknown")),
        status=str(_record_value(record, "status", "state", default="UNKNOWN")),
        severity=str(_record_value(record, "severity", default="UNKNOWN")),
        confidence=str(_record_value(record, "confidence", default="UNKNOWN")),
        signal_ids=_record_list(record, "signal_ids", "signalIds", "source_signal_ids", "sourceSignalIds"),
        evidence_refs=_record_list(record, "evidence_refs", "evidenceRefs", "supporting_evidence_refs", "supportingEvidenceRefs"),
        provenance_source=str(_record_value(record, "provenance_source", "provenanceSource", "source", default="local incident adjudication")),
        provenance_source_type=str(_record_value(record, "provenance_source_type", "provenanceSourceType", default="local")),
        adjudicated_at=str(_record_value(record, "adjudicated_at", "adjudicatedAt", default="not_validated")),
    )


def _response_proposal_model(value: Any) -> ResponseProposalReadModel:
    record = _record_dict(value)
    return ResponseProposalReadModel(
        proposal_id=str(_record_value(record, "proposal_id", "proposalId", default="unknown")),
        incident_id=str(_record_value(record, "incident_id", "incidentId", default="unknown")),
        tenant_id=str(_record_value(record, "tenant_id", "tenantId", "tenant", default="unknown")),
        case_id=str(_record_value(record, "case_id", "caseId", "case", default="unknown")),
        target_id=str(_record_value(record, "target_id", "targetId", "target", default="unknown")),
        action=str(_record_value(record, "action", default="UNKNOWN")),
        opa_decision=str(_record_value(record, "opa_decision", "opaDecision", default="UNKNOWN")),
        human_approval_state=str(_record_value(record, "human_approval_state", "humanApprovalState", default="UNKNOWN")),
        status=str(_record_value(record, "status", "state", "human_approval_state", "humanApprovalState", default="UNKNOWN")),
        evidence_refs=_record_list(record, "evidence_refs", "evidenceRefs", "supporting_evidence_refs", "supportingEvidenceRefs"),
        source=str(_record_value(record, "source", default="local response proposal projection")),
    )


def _client_for_target(engagements: Sequence[Engagement], target_id: str) -> str | None:
    for engagement in engagements:
        if target_id in {str(item) for item in engagement.target_ids}:
            return str(engagement.client_id)
    return None


def _optional_string(value: Any) -> str | None:
    return None if value is None else str(value)


def _page(items: list[T], *, cursor: str | None, limit: int) -> CursorPage[T]:
    if not 1 <= limit <= 100:
        raise ReadModelError("limit must be between 1 and 100")
    offset = _decode_cursor(cursor)
    page_items = items[offset : offset + limit]
    next_cursor = _encode_cursor(offset + limit) if offset + limit < len(items) else None
    return CursorPage(items=page_items, next_cursor=next_cursor, limit=limit)


def _encode_cursor(offset: int) -> str:
    return base64.urlsafe_b64encode(str(offset).encode("ascii")).decode("ascii").rstrip("=")


def _decode_cursor(cursor: str | None) -> int:
    if cursor is None:
        return 0
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        offset = int(base64.urlsafe_b64decode(padded.encode("ascii")).decode("ascii"))
    except (ValueError, UnicodeDecodeError, binascii.Error) as exc:
        raise ReadModelError("invalid cursor") from exc
    if offset < 0:
        raise ReadModelError("invalid cursor")
    return offset
