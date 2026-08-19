"""Bounded, typed application read models.

The in-memory implementation is intentionally limited to local/test
composition. Hosted mode must inject a canonical PostgreSQL-backed service;
the API never silently falls back to this class.
"""

from __future__ import annotations

import base64
import binascii
from collections.abc import Sequence
from typing import Any, Generic, TypeVar

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
