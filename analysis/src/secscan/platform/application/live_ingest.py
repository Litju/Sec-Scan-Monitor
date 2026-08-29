"""Authenticated live security-source ingestion application service."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from secscan.platform.continuous_security.events import SecurityEventPlane
from secscan.platform.detection_response.domain import (
    SOURCE_FAMILY_EVENT_CLASSES,
    SUPPORTED_OCSF_CLASSES,
    SUPPORTED_OCSF_VERSION,
    DetectionInputError,
    SecuritySourceBinding,
)
from secscan.platform.detection_response.engine import BoundedSecurityEventIngestor
from secscan.sanitize.filters import payload_contains_secret_like_content

_MAX_EVENT_METADATA_BYTES = 16_384
_MAX_EVENT_METADATA_DEPTH = 5
_MAX_EVENT_METADATA_ITEMS = 128
_MAX_EVENT_METADATA_STRING_BYTES = 1_024
_FORBIDDEN_EVENT_METADATA_KEYS = frozenset({"body", "bytes", "content", "data", "payload", "raw"})


class LiveSecurityEventInput(BaseModel):
    """Strict network envelope; scope and source family come from registration."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    source_id: str = Field(min_length=1, max_length=128)
    source_record_id: str = Field(min_length=1, max_length=512)
    source_digest: str = Field(min_length=1, max_length=128)
    event_class: str = Field(min_length=1, max_length=96)
    ocsf_class: str | None = Field(default=None, max_length=96)
    ocsf_version: str = Field(default="1.8.0", min_length=1, max_length=32)
    occurred_at: datetime
    observed_at: datetime
    actor: str = Field(min_length=1, max_length=255)
    object_ref: str = Field(alias="object", min_length=1, max_length=255)
    action: str = Field(min_length=1, max_length=255)
    outcome: str = Field(min_length=1, max_length=96)
    severity: str | None = Field(default=None, max_length=16)
    raw_evidence_ref: str = Field(min_length=1, max_length=512)
    normalization_version: str = Field(min_length=1, max_length=64)
    collector_version: str = Field(min_length=1, max_length=64)
    source_system: str = Field(min_length=1, max_length=128)
    attributes: dict[str, Any] = Field(default_factory=dict)
    ordering_metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("occurred_at", "observed_at")
    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("live event timestamps must be timezone-aware")
        return value.astimezone(UTC)

    @field_validator(
        "source_id",
        "source_record_id",
        "source_digest",
        "event_class",
        "ocsf_class",
        "ocsf_version",
        "actor",
        "object_ref",
        "action",
        "outcome",
        "severity",
        "raw_evidence_ref",
        "normalization_version",
        "collector_version",
        "source_system",
    )
    @classmethod
    def _secret_free_text(cls, value: str | None) -> str | None:
        if value is not None and payload_contains_secret_like_content(value):
            raise ValueError("secret-like event text is not accepted")
        return value

    @field_validator("ocsf_version")
    @classmethod
    def _supported_ocsf_version(cls, value: str) -> str:
        if value != SUPPORTED_OCSF_VERSION:
            raise ValueError(f"only OCSF {SUPPORTED_OCSF_VERSION} is supported")
        return value

    @field_validator("ocsf_class")
    @classmethod
    def _supported_ocsf_class(cls, value: str | None) -> str | None:
        if value is not None and value not in SUPPORTED_OCSF_CLASSES:
            raise ValueError("unsupported OCSF event class")
        return value

    @field_validator("attributes", "ordering_metadata")
    @classmethod
    def _bounded_metadata(cls, value: dict[str, Any]) -> dict[str, Any]:
        def visit(item: Any, depth: int) -> None:
            if depth > _MAX_EVENT_METADATA_DEPTH:
                raise ValueError("event metadata nesting is too deep")
            if isinstance(item, dict):
                if len(item) > _MAX_EVENT_METADATA_ITEMS:
                    raise ValueError("event metadata has too many fields")
                for key, child in item.items():
                    if not isinstance(key, str) or len(key.encode("utf-8")) > _MAX_EVENT_METADATA_STRING_BYTES:
                        raise ValueError("event metadata keys are invalid or too large")
                    if key.casefold() in _FORBIDDEN_EVENT_METADATA_KEYS:
                        raise ValueError("raw event payload fields are not accepted")
                    visit(child, depth + 1)
            elif isinstance(item, list):
                if len(item) > _MAX_EVENT_METADATA_ITEMS:
                    raise ValueError("event metadata has too many items")
                for child in item:
                    visit(child, depth + 1)
            elif isinstance(item, str):
                if len(item.encode("utf-8")) > _MAX_EVENT_METADATA_STRING_BYTES:
                    raise ValueError("event metadata strings are too large")
            elif item is not None and not isinstance(item, (bool, int, float)):
                raise ValueError("event metadata must be JSON values")

        visit(value, 0)
        try:
            encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise ValueError("event metadata must be JSON serializable") from exc
        if len(encoded.encode("utf-8")) > _MAX_EVENT_METADATA_BYTES:
            raise ValueError("event metadata exceeds its size bound")
        if payload_contains_secret_like_content(value):
            raise ValueError("secret-like event metadata is not accepted")
        return value

    @model_validator(mode="after")
    def _ordered(self) -> LiveSecurityEventInput:
        if self.occurred_at > self.observed_at:
            raise ValueError("occurred_at cannot be later than observed_at")
        if self.event_class not in SUPPORTED_OCSF_CLASSES:
            raise ValueError("unsupported event class")
        if self.ocsf_class is not None and self.ocsf_class != self.event_class:
            raise ValueError("OCSF class must match the normalized event class")
        return self


class LiveIngestReceipt(BaseModel):
    model_config = ConfigDict(frozen=True)

    event_id: str
    source_id: str
    tenant_id: str
    case_id: str
    target_id: str
    event_created: bool
    work_id: str
    work_created: bool
    work_status: str


class SecurityEventIngestService:
    """One source boundary: authenticate, normalize, then atomically persist."""

    def __init__(self, repository: Any) -> None:
        self._repository = repository

    def register_source(
        self, binding: SecuritySourceBinding, *, access_principal_id: str | None = None
    ) -> SecuritySourceBinding:
        return cast(
            SecuritySourceBinding,
            self._repository.register_source(binding, access_principal_id=access_principal_id),
        )

    def ingest(
        self,
        request: LiveSecurityEventInput,
        *,
        principal_id: str,
        access_principal_id: str | None = None,
    ) -> LiveIngestReceipt:
        binding = self._repository.load_source(
            request.source_id,
            access_principal_id=access_principal_id,
        )
        if binding is None or binding.status != "ACTIVE":
            raise PermissionError("source is not registered")
        if binding.principal_id != principal_id:
            raise PermissionError("source principal is not authorized")
        allowed_classes = SOURCE_FAMILY_EVENT_CLASSES[binding.source_family]
        if request.event_class not in allowed_classes:
            raise DetectionInputError("event class is not allowed for the registered source family")

        raw = request.model_dump(mode="json", by_alias=True)
        raw.update(
            {
                "source": binding.source_id,
                "source_type": binding.source_type,
                "source_family": binding.source_family,
                "event_class": request.event_class,
                "ocsf_class": request.ocsf_class or request.event_class,
                "tenant": binding.scope.tenant_id,
                "case": binding.scope.case_id,
                "target": binding.scope.target_id,
            }
        )
        raw.pop("source_id", None)
        # ``SecurityEventPlane`` is used only as the canonical normalizer;
        # PostgreSQL remains the event and replay source of truth.
        normalized = BoundedSecurityEventIngestor(
            SecurityEventPlane(), scope=binding.scope
        ).ingest_raw(raw, scope=binding.scope)
        work, work_created, event_created = self._repository.ingest_event(
            normalized.event,
            access_principal_id=access_principal_id,
        )
        return LiveIngestReceipt(
            event_id=normalized.event.event_id,
            source_id=binding.source_id,
            tenant_id=binding.scope.tenant_id,
            case_id=binding.scope.case_id,
            target_id=binding.scope.target_id,
            event_created=event_created,
            work_id=work.work_id,
            work_created=work_created,
            work_status=work.status.value,
        )


__all__ = ["LiveIngestReceipt", "LiveSecurityEventInput", "SecurityEventIngestService"]
