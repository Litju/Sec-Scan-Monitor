"""Typed security-event boundary kept separate from operational telemetry."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Iterable

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class _FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, populate_by_name=True)


class EventClass(str, Enum):
    GENERIC_SECSCAN = "secscan_activity"
    AGENT_ACTIVITY = "agent_activity"
    MCP_ACTIVITY = "mcp_activity"
    A2A_ACTIVITY = "a2a_activity"
    ENDPOINT_ACTIVITY = "endpoint_activity"
    CLOUD_AUDIT_ACTIVITY = "cloud_audit_activity"
    OCSF_ACTIVITY = "ocsf_activity"
    CAPABILITY_DECISION = "capability_decision"
    SCANNER_ACTIVITY = "scanner_activity"
    TARGET_CHANGE = "target_change"


class EventProvenance(_FrozenModel):
    source_record_id: str
    source_system: str
    collector_version: str
    raw_evidence_ref: str
    source_digest: str

    @field_validator("source_record_id", "source_system", "collector_version", "raw_evidence_ref", "source_digest")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("event provenance fields must be non-empty")
        return value


class SecurityEvent(_FrozenModel):
    """Normalized event; it is not a Finding and cannot create one directly."""

    event_id: str
    source: str
    source_type: str
    event_class: EventClass
    occurred_at: datetime
    observed_at: datetime
    tenant: str
    case: str
    target: str
    actor: str
    object_ref: str = Field(alias="object")
    action: str
    outcome: str
    severity: str | None = None
    raw_evidence_ref: str
    normalization_version: str
    provenance: EventProvenance
    attributes: dict[str, Any] = Field(default_factory=dict)
    source_family: str = "secscan"
    ocsf_class: str = "secscan_activity"
    ocsf_version: str = "1.8.0"
    ingested_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    ordering_metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator(
        "event_id",
        "source",
        "source_type",
        "tenant",
        "case",
        "target",
        "actor",
        "object_ref",
        "action",
        "outcome",
        "raw_evidence_ref",
        "normalization_version",
        "source_family",
        "ocsf_class",
        "ocsf_version",
    )
    @classmethod
    def _non_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("security event identity and provenance fields must be non-empty")
        return value

    @field_validator("occurred_at", "observed_at", "ingested_at")
    @classmethod
    def _timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("security event timestamps must be timezone-aware")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def _timestamp_order(self) -> SecurityEvent:
        if self.occurred_at > self.observed_at:
            raise ValueError("occurred_at cannot be later than observed_at")
        if self.raw_evidence_ref != self.provenance.raw_evidence_ref:
            raise ValueError("event raw_evidence_ref must match provenance raw_evidence_ref")
        return self

    def canonical_dict(self, *, include_event_id: bool = True) -> dict[str, Any]:
        payload = self.model_dump(mode="json", by_alias=True)
        if not include_event_id:
            payload.pop("event_id", None)
        # Arrival time and transport ordering are not source content. Excluding
        # them keeps a replay of the same source record idempotent.
        payload.pop("ingested_at", None)
        payload.pop("ordering_metadata", None)
        return payload

    @property
    def fingerprint(self) -> str:
        canonical = json.dumps(self.canonical_dict(include_event_id=False), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class EventIdentityConflict(RuntimeError):
    """One event identity was reused for a different payload."""


class EventTimestampError(ValueError):
    """A source event contains an invalid or ambiguous timestamp order."""


class OperationalTelemetryRejected(RuntimeError):
    """Operational telemetry cannot enter the security-event plane."""


class EventIngestResult(_FrozenModel):
    event: SecurityEvent
    created: bool
    duplicate: bool


class SecurityEventPlane:
    """Deterministic, idempotent event boundary for normalized security events."""

    def __init__(self) -> None:
        self._events: dict[str, SecurityEvent] = {}
        self._fingerprints: dict[str, str] = {}

    @staticmethod
    def derive_event_id(
        *, source: str, source_record_id: str, occurred_at: datetime, source_digest: str
    ) -> str:
        if occurred_at.tzinfo is None or occurred_at.utcoffset() is None:
            raise EventTimestampError("event identity requires a timezone-aware occurred_at")
        payload = {
            "source": source,
            "source_record_id": source_record_id,
            "occurred_at": occurred_at.astimezone(UTC).isoformat(),
            "source_digest": source_digest,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return f"SE-{hashlib.sha256(canonical).hexdigest()[:32]}"

    def normalize(self, raw: dict[str, Any]) -> SecurityEvent:
        """Normalize only the current event classes and preserve raw data by reference."""
        source = str(raw.get("source", ""))
        source_record_id = str(raw.get("source_record_id", ""))
        source_digest = str(raw.get("source_digest", ""))
        occurred_at = self._parse_timestamp(raw.get("occurred_at"))
        observed_at = self._parse_timestamp(raw.get("observed_at"))
        derived_id = self.derive_event_id(
            source=source,
            source_record_id=source_record_id,
            occurred_at=occurred_at,
            source_digest=source_digest,
        )
        supplied_id = raw.get("event_id")
        if supplied_id is not None and str(supplied_id) != derived_id:
            raise EventIdentityConflict("caller-supplied event_id does not match deterministic identity")
        try:
            event_class = EventClass(str(raw["event_class"]))
        except (KeyError, ValueError) as exc:
            raise ValueError("unsupported security event class") from exc
        provenance = EventProvenance(
            source_record_id=source_record_id,
            source_system=str(raw.get("source_system", source)),
            collector_version=str(raw.get("collector_version", "")),
            raw_evidence_ref=str(raw.get("raw_evidence_ref", "")),
            source_digest=source_digest,
        )
        try:
            return SecurityEvent(
                event_id=derived_id,
                source=source,
                source_type=str(raw.get("source_type", "")),
                event_class=event_class,
                occurred_at=occurred_at,
                observed_at=observed_at,
                tenant=str(raw.get("tenant", "")),
                case=str(raw.get("case", "")),
                target=str(raw.get("target", "")),
                actor=str(raw.get("actor", "")),
                object=str(raw.get("object", "")),
                action=str(raw.get("action", "")),
                outcome=str(raw.get("outcome", "")),
                severity=str(raw["severity"]) if raw.get("severity") is not None else None,
                raw_evidence_ref=str(raw.get("raw_evidence_ref", "")),
                normalization_version=str(raw.get("normalization_version", "security-events-v1")),
                provenance=provenance,
                attributes=dict(raw.get("attributes", {})),
                source_family=str(raw.get("source_family", "secscan")),
                ocsf_class=str(raw.get("ocsf_class", event_class.value)),
                ocsf_version=str(raw.get("ocsf_version", "1.8.0")),
                ingested_at=self._parse_timestamp(raw.get("ingested_at"))
                if raw.get("ingested_at") is not None
                else datetime.now(UTC),
                ordering_metadata=dict(raw.get("ordering_metadata", {})),
            )
        except ValueError as exc:
            if "occurred_at" in str(exc) or "observed_at" in str(exc):
                raise EventTimestampError(str(exc)) from exc
            raise

    @staticmethod
    def _parse_timestamp(value: object) -> datetime:
        if isinstance(value, datetime):
            parsed = value
        elif isinstance(value, str):
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError as exc:
                raise EventTimestampError("normalization requires ISO-8601 timestamps") from exc
        else:
            raise EventTimestampError("normalization requires datetime or ISO-8601 timestamp values")
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise EventTimestampError("security event timestamps must be timezone-aware")
        return parsed.astimezone(UTC)

    def ingest(self, event: SecurityEvent) -> EventIngestResult:
        expected_id = self.derive_event_id(
            source=event.source,
            source_record_id=event.provenance.source_record_id,
            occurred_at=event.occurred_at,
            source_digest=event.provenance.source_digest,
        )
        if event.event_id != expected_id:
            raise EventIdentityConflict("event_id does not match deterministic event identity")
        existing = self._events.get(event.event_id)
        if existing is not None:
            if existing.fingerprint != event.fingerprint:
                raise EventIdentityConflict(f"event identity {event.event_id} was reused for different content")
            return EventIngestResult(event=existing, created=False, duplicate=True)
        existing_id = self._fingerprints.get(event.fingerprint)
        if existing_id is not None and existing_id != event.event_id:
            raise EventIdentityConflict("same event payload was assigned multiple identities")
        self._events[event.event_id] = event
        self._fingerprints[event.fingerprint] = event.event_id
        return EventIngestResult(event=event, created=True, duplicate=False)

    def ingest_raw(self, raw: dict[str, Any]) -> EventIngestResult:
        return self.ingest(self.normalize(raw))

    def events(self, *, tenant: str | None = None, case: str | None = None) -> tuple[SecurityEvent, ...]:
        values: Iterable[SecurityEvent] = self._events.values()
        if tenant is not None:
            values = (event for event in values if event.tenant == tenant)
        if case is not None:
            values = (event for event in values if event.case == case)
        return tuple(sorted(values, key=lambda event: (event.occurred_at, event.observed_at, event.event_id)))

    def ingest_telemetry(self, _telemetry: object) -> None:
        raise OperationalTelemetryRejected("operational telemetry uses the OpenTelemetry path, not security events")
