"""Pure v0.3 detection, hunting, adjudication, and response contracts."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Mapping, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from secscan.platform.continuous_security.events import EventIngestResult, SecurityEvent
from secscan.platform.domain.common import Confidence, Severity, utc_now


class DetectionResponseModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)


def canonical_json(value: Any) -> str:
    """Return one stable representation for digests and idempotency keys."""

    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json", by_alias=True, exclude_none=True)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def content_digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def stable_id(prefix: str, *parts: Any) -> str:
    return f"{prefix}{content_digest(parts)[:32]}"


def _non_empty(value: str) -> str:
    if not value.strip():
        raise ValueError("value must be non-empty")
    return value


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamps must be timezone-aware")
    return value.astimezone(UTC)


class Scope(DetectionResponseModel):
    """The minimum scope carried by every v0.3 read and write."""

    tenant_id: str = Field(alias="tenant")
    case_id: str = Field(alias="case")
    target_id: str = Field(alias="target")

    _tenant_non_empty = field_validator("tenant_id")(classmethod(lambda _cls, value: _non_empty(value)))
    _case_non_empty = field_validator("case_id")(classmethod(lambda _cls, value: _non_empty(value)))
    _target_non_empty = field_validator("target_id")(classmethod(lambda _cls, value: _non_empty(value)))

    def key(self) -> tuple[str, str, str]:
        return self.tenant_id, self.case_id, self.target_id


class SecuritySourceBinding(DetectionResponseModel):
    """Canonical source identity and the scope it is allowed to submit to."""

    source_id: str
    principal_id: str
    scope: Scope
    source_family: str
    source_type: str
    status: str = "ACTIVE"

    _non_empty_fields = field_validator("source_id", "principal_id", "source_family", "source_type")(
        classmethod(lambda _cls, value: _non_empty(value))
    )

    @field_validator("source_family")
    @classmethod
    def _supported_source_family(cls, value: str) -> str:
        if value not in SUPPORTED_SOURCE_FAMILIES:
            raise ValueError(f"unsupported source family: {value}")
        return value


class DetectionWorkStatus(str, Enum):
    PENDING = "PENDING"
    CLAIMED = "CLAIMED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class DetectionWorkItem(DetectionResponseModel):
    """Durable event-to-detection handoff state; leases make retries recoverable."""

    work_id: str
    event_id: str
    scope: Scope
    event_fingerprint: str
    status: DetectionWorkStatus
    attempts: int = 0
    lease_until: datetime | None = None
    worker_id: str | None = None
    run_ids: tuple[str, ...] = ()
    signal_ids: tuple[str, ...] = ()
    last_error: str | None = None
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    completed_at: datetime | None = None

    _non_empty_fields = field_validator("work_id", "event_id", "event_fingerprint")(
        classmethod(lambda _cls, value: _non_empty(value))
    )

    @field_validator("created_at", "updated_at", "lease_until", "completed_at")
    @classmethod
    def _timestamps_aware(cls, value: datetime | None) -> datetime | None:
        return None if value is None else _aware(value)

    @field_validator("attempts")
    @classmethod
    def _attempts_non_negative(cls, value: int) -> int:
        if value < 0:
            raise ValueError("work attempts cannot be negative")
        return value


class EventSourceFamily(str, Enum):
    SECSCAN = "secscan"
    MCP_A2A_GATEWAY = "mcp_a2a_gateway"
    EDGE_RUNNER = "edge_runner"
    OCSF_JSON = "ocsf_json"
    ENDPOINT_FIXTURE = "endpoint_fixture"
    CLOUD_AUDIT_FIXTURE = "cloud_audit_fixture"


SUPPORTED_SOURCE_FAMILIES = frozenset(item.value for item in EventSourceFamily)
SUPPORTED_OCSF_VERSION = "1.8.0"
MAX_CORRELATION_WINDOW_SECONDS = 86_400
MAX_HUNT_QUERY_BYTES = 16_384
SUPPORTED_OCSF_CLASSES = frozenset(
    {
        "secscan_activity",
        "agent_activity",
        "mcp_activity",
        "a2a_activity",
        "endpoint_activity",
        "cloud_audit_activity",
        "ocsf_activity",
        "capability_decision",
        "scanner_activity",
        "target_change",
    }
)

# A source binding is intentionally narrower than the global OCSF vocabulary.
# The generic ``secscan``/``ocsf_json`` families may carry any supported class;
# qualification families are pinned to the class they claim to collect.
SOURCE_FAMILY_EVENT_CLASSES: dict[str, frozenset[str]] = {
    "endpoint_fixture": frozenset({"endpoint_activity"}),
    "cloud_audit_fixture": frozenset({"cloud_audit_activity"}),
    "mcp_a2a_gateway": frozenset({"mcp_activity", "a2a_activity"}),
    "edge_runner": frozenset({"capability_decision"}),
    "secscan": SUPPORTED_OCSF_CLASSES,
    "ocsf_json": SUPPORTED_OCSF_CLASSES,
}


class DetectionRuleType(str, Enum):
    EVENT_MATCH = "EVENT_MATCH"
    COUNT_OVER_WINDOW = "COUNT_OVER_WINDOW"


class RuleStatus(str, Enum):
    DRAFT = "DRAFT"
    TEST = "TEST"
    ACTIVE = "ACTIVE"
    DEPRECATED = "DEPRECATED"
    DISABLED = "DISABLED"


class EvaluationResult(str, Enum):
    MATCH = "MATCH"
    NO_MATCH = "NO_MATCH"


class FixtureLabel(str, Enum):
    EXPECTED_MATCH = "EXPECTED_MATCH"
    EXPECTED_NO_MATCH = "EXPECTED_NO_MATCH"
    NEAR_MISS = "NEAR_MISS"


class HuntDisposition(str, Enum):
    SUPPORTS = "SUPPORTS"
    REFUTES = "REFUTES"
    INCONCLUSIVE = "INCONCLUSIVE"


class IncidentState(str, Enum):
    CANDIDATE = "CANDIDATE"
    CONFIRMED = "CONFIRMED"
    CONTAINED = "CONTAINED"
    RECOVERING = "RECOVERING"
    RESOLVED = "RESOLVED"
    DISMISSED = "DISMISSED"


class OpaDecision(str, Enum):
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    ALLOW = "ALLOW"


class HumanApprovalState(str, Enum):
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    EXPIRED = "EXPIRED"


class ResponseAction(str, Enum):
    ISOLATE_RUNNER = "ISOLATE_RUNNER"
    SUSPEND_CAPABILITY = "SUSPEND_CAPABILITY"
    BLOCK_TOOL = "BLOCK_TOOL"
    REVOKE_SESSION = "REVOKE_SESSION"


class DetectionRuleVersion(DetectionResponseModel):
    rule_id: str
    version: int
    title: str
    rule_type: DetectionRuleType
    content_digest: str
    source: str
    source_reference: str
    owner: str = "SecScanMonitor"
    event_schema: str = "OCSF"
    ocsf_version: str = SUPPORTED_OCSF_VERSION
    supported_source_families: tuple[str, ...]
    severity: Severity
    confidence: Confidence
    confidence_metadata: dict[str, Any] = Field(default_factory=dict)
    attack_mappings: tuple[str, ...] = ()
    atlas_mappings: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    predicates: dict[str, Any] = Field(default_factory=dict)
    correlation_keys: tuple[str, ...] = ()
    window_seconds: int = 0
    threshold: int = 1
    status: RuleStatus = RuleStatus.ACTIVE
    created_at: datetime = Field(default_factory=utc_now)
    modified_at: datetime = Field(default_factory=utc_now)
    evaluation_metadata: dict[str, Any] = Field(default_factory=dict)

    _rule_non_empty = field_validator(
        "rule_id", "title", "content_digest", "source", "source_reference", "owner"
    )(
        classmethod(lambda _cls, value: _non_empty(value))
    )
    _timestamps_aware = field_validator("created_at", "modified_at")(classmethod(lambda _cls, value: _aware(value)))

    @field_validator("event_schema")
    @classmethod
    def _supported_event_schema(cls, value: str) -> str:
        if value != "OCSF":
            raise ValueError("only the OCSF event schema is supported")
        return value

    @field_validator("ocsf_version")
    @classmethod
    def _supported_ocsf_version(cls, value: str) -> str:
        if value != SUPPORTED_OCSF_VERSION:
            raise ValueError(f"only OCSF {SUPPORTED_OCSF_VERSION} is supported")
        return value

    @field_validator("version")
    @classmethod
    def _positive_version(cls, value: int) -> int:
        if value < 1:
            raise ValueError("rule version must be positive")
        return value

    @field_validator("supported_source_families")
    @classmethod
    def _supported_sources(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value or any(item not in SUPPORTED_SOURCE_FAMILIES for item in value):
            raise ValueError("rule source families must use the bounded source-family set")
        return tuple(sorted(set(value)))

    @model_validator(mode="after")
    def _correlation_bounds(self) -> DetectionRuleVersion:
        if self.rule_type == DetectionRuleType.EVENT_MATCH and (self.window_seconds or self.threshold != 1):
            raise ValueError("event-match rules cannot carry correlation bounds")
        if self.rule_type == DetectionRuleType.COUNT_OVER_WINDOW:
            if (
                self.window_seconds <= 0
                or self.window_seconds > MAX_CORRELATION_WINDOW_SECONDS
                or self.threshold < 2
                or not self.correlation_keys
            ):
                raise ValueError(
                    "count-over-window rules require keys, a window between 1 and 86400 seconds, and threshold >= 2"
                )
        return self


class DetectionRule(DetectionResponseModel):
    rule_id: str
    name: str
    versions: tuple[DetectionRuleVersion, ...]
    active_version: int
    owner: str = "SecScanMonitor"

    _rule_non_empty = field_validator("rule_id", "name", "owner")(
        classmethod(lambda _cls, value: _non_empty(value))
    )

    @model_validator(mode="after")
    def _active_version_exists(self) -> DetectionRule:
        if not self.versions or not any(
            version.rule_id == self.rule_id and version.version == self.active_version for version in self.versions
        ):
            raise ValueError("active rule version must exist in the rule")
        if any(version.rule_id != self.rule_id for version in self.versions):
            raise ValueError("all rule versions must belong to the rule")
        if len({version.version for version in self.versions}) != len(self.versions):
            raise ValueError("rule versions must be unique")
        if any(version.owner != self.owner for version in self.versions):
            raise ValueError("rule ownership must match every rule version")
        return self

    @property
    def active(self) -> DetectionRuleVersion:
        return next(version for version in self.versions if version.version == self.active_version)


class DetectionPlan(DetectionResponseModel):
    plan_id: str
    rule_id: str
    rule_version: int
    rule_type: DetectionRuleType
    content_digest: str
    event_schema: str
    supported_source_families: tuple[str, ...]
    predicates: dict[str, Any]
    correlation_keys: tuple[str, ...] = ()
    window_seconds: int = 0
    threshold: int = 1

    _non_empty_fields = field_validator("plan_id", "rule_id", "content_digest", "event_schema")(
        classmethod(lambda _cls, value: _non_empty(value))
    )

    @field_validator("event_schema")
    @classmethod
    def _supported_event_schema(cls, value: str) -> str:
        if value != "OCSF":
            raise ValueError("only the OCSF event schema is supported")
        return value

    @field_validator("supported_source_families")
    @classmethod
    def _supported_sources(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value or any(item not in SUPPORTED_SOURCE_FAMILIES for item in value):
            raise ValueError("plan source families must use the bounded source-family set")
        return tuple(sorted(set(value)))

    @model_validator(mode="after")
    def _correlation_bounds(self) -> DetectionPlan:
        if self.rule_type == DetectionRuleType.EVENT_MATCH and (self.window_seconds or self.threshold != 1):
            raise ValueError("event-match plans cannot carry correlation bounds")
        if self.rule_type == DetectionRuleType.COUNT_OVER_WINDOW:
            if (
                self.window_seconds <= 0
                or self.window_seconds > MAX_CORRELATION_WINDOW_SECONDS
                or self.threshold < 2
                or not self.correlation_keys
            ):
                raise ValueError(
                    "count-over-window plans require keys, a window between 1 and 86400 seconds, and threshold >= 2"
                )
        return self


class DetectionEvaluation(DetectionResponseModel):
    evaluation_id: str
    run_id: str
    scope: Scope
    rule_id: str
    rule_version: int
    input_event_ids: tuple[str, ...]
    evaluated_at: datetime
    matched_predicates: tuple[str, ...]
    result: EvaluationResult
    signal_id: str | None = None
    engine_version: str
    rule_digest: str
    idempotency_key: str

    _timestamps_aware = field_validator("evaluated_at")(classmethod(lambda _cls, value: _aware(value)))


class DetectionSignal(DetectionResponseModel):
    """An evidence-linked detector output, never an Incident or Finding."""

    signal_id: str
    scope: Scope
    rule_id: str
    rule_version: int
    event_ids: tuple[str, ...]
    source_signal_ids: tuple[str, ...] = ()
    detected_at: datetime
    severity: Severity
    confidence: Confidence
    matched_predicates: tuple[str, ...]
    raw_evidence_refs: tuple[str, ...]
    rule_digest: str
    status: str = "NEW"

    _timestamps_aware = field_validator("detected_at")(classmethod(lambda _cls, value: _aware(value)))

    @model_validator(mode="after")
    def _has_inputs(self) -> DetectionSignal:
        if not self.event_ids and not self.source_signal_ids:
            raise ValueError("a detection signal requires source events or source signals")
        if any(not item.strip() for item in self.raw_evidence_refs):
            raise ValueError("detection signals require raw evidence references")
        return self


class DetectionRun(DetectionResponseModel):
    run_id: str
    scope: Scope
    rule_ids: tuple[str, ...]
    input_event_ids: tuple[str, ...]
    evaluation_ids: tuple[str, ...]
    signal_ids: tuple[str, ...]
    engine_version: str
    started_at: datetime
    completed_at: datetime
    status: str = "COMPLETED"

    _timestamps_aware = field_validator("started_at", "completed_at")(classmethod(lambda _cls, value: _aware(value)))


class LabeledFixture(DetectionResponseModel):
    fixture_id: str
    label: FixtureLabel
    event: SecurityEvent
    rule_id: str
    rationale: str

    _non_empty_fields = field_validator("fixture_id", "rule_id", "rationale")(
        classmethod(lambda _cls, value: _non_empty(value))
    )


class RuleEvaluationMetrics(DetectionResponseModel):
    rule_id: str
    metric_scope: str = "FIXTURE_ONLY"
    true_positive: int
    false_positive: int
    true_negative: int
    false_negative: int
    precision: float
    recall: float
    near_miss_count: int


class EvaluationReport(DetectionResponseModel):
    metric_scope: str = "FIXTURE_ONLY"
    rules: tuple[RuleEvaluationMetrics, ...]
    mutation_digests: tuple[str, ...]


class HuntHypothesis(DetectionResponseModel):
    hypothesis_id: str
    scope: Scope
    question: str
    entity_keys: tuple[str, ...]
    supporting_signal_ids: tuple[str, ...] = ()
    required_evidence_refs: tuple[str, ...] = ()
    created_at: datetime = Field(default_factory=utc_now)

    _non_empty_fields = field_validator("hypothesis_id", "question")(
        classmethod(lambda _cls, value: _non_empty(value))
    )
    _timestamps_aware = field_validator("created_at")(classmethod(lambda _cls, value: _aware(value)))


class HuntPlan(DetectionResponseModel):
    plan_id: str
    hypothesis_id: str
    scope: Scope
    window_start: datetime
    window_end: datetime
    query: dict[str, Any]
    exit_criteria: str
    max_events: int = 500

    _non_empty_fields = field_validator("plan_id", "hypothesis_id", "exit_criteria")(
        classmethod(lambda _cls, value: _non_empty(value))
    )
    _timestamps_aware = field_validator("window_start", "window_end")(classmethod(lambda _cls, value: _aware(value)))

    @model_validator(mode="after")
    def _window_valid(self) -> HuntPlan:
        if self.window_start > self.window_end:
            raise ValueError("hunt window_start cannot be later than window_end")
        if self.max_events < 1 or self.max_events > 5000:
            raise ValueError("hunt max_events must be bounded between 1 and 5000")
        try:
            query_size = len(canonical_json(self.query).encode("utf-8"))
        except (TypeError, ValueError) as exc:
            raise ValueError("hunt query must be JSON-serializable") from exc
        if query_size > MAX_HUNT_QUERY_BYTES:
            raise ValueError("hunt query must be no larger than 16384 UTF-8 bytes")
        return self


class HuntExecution(DetectionResponseModel):
    execution_id: str
    plan_id: str
    scope: Scope
    query_digest: str
    input_event_ids: tuple[str, ...]
    input_signal_ids: tuple[str, ...]
    started_at: datetime
    completed_at: datetime
    result_id: str

    _timestamps_aware = field_validator("started_at", "completed_at")(classmethod(lambda _cls, value: _aware(value)))


class HuntResult(DetectionResponseModel):
    result_id: str
    execution_id: str
    hypothesis_id: str
    scope: Scope
    disposition: HuntDisposition
    event_ids: tuple[str, ...]
    signal_ids: tuple[str, ...]
    supporting_evidence_refs: tuple[str, ...]
    refuting_evidence_refs: tuple[str, ...]
    result_digest: str


class IncidentHypothesis(DetectionResponseModel):
    hypothesis_id: str
    scope: Scope
    question: str
    source_signal_ids: tuple[str, ...]
    affected_entities: tuple[str, ...]
    created_at: datetime = Field(default_factory=utc_now)

    _non_empty_fields = field_validator("hypothesis_id", "question")(
        classmethod(lambda _cls, value: _non_empty(value))
    )
    _timestamps_aware = field_validator("created_at")(classmethod(lambda _cls, value: _aware(value)))

    @field_validator("source_signal_ids", "affected_entities")
    @classmethod
    def _required_refs(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value or any(not item.strip() for item in value):
            raise ValueError("incident hypotheses require source signals and affected entities")
        return value


class IncidentInvestigation(DetectionResponseModel):
    investigation_id: str
    hypothesis_id: str
    scope: Scope
    observation_ids: tuple[str, ...]
    claim_ids: tuple[str, ...]
    opened_at: datetime = Field(default_factory=utc_now)

    _non_empty_fields = field_validator("investigation_id", "hypothesis_id")(
        classmethod(lambda _cls, value: _non_empty(value))
    )
    _timestamps_aware = field_validator("opened_at")(classmethod(lambda _cls, value: _aware(value)))


class IncidentAdjudication(DetectionResponseModel):
    adjudication_id: str
    hypothesis_id: str
    scope: Scope
    supporting_claim_ids: tuple[str, ...]
    supporting_evidence_refs: tuple[str, ...]
    contradicting_claim_ids: tuple[str, ...]
    contradicting_evidence_refs: tuple[str, ...]
    decided_by: str
    decided_at: datetime
    reason: str
    confidence: Confidence
    severity: Severity

    _timestamps_aware = field_validator("decided_at")(classmethod(lambda _cls, value: _aware(value)))
    _non_empty_fields = field_validator("adjudication_id", "hypothesis_id", "decided_by", "reason")(
        classmethod(lambda _cls, value: _non_empty(value))
    )


class Incident(DetectionResponseModel):
    """Operational incident, distinct from vulnerability Finding and Case."""

    incident_id: str
    hypothesis_id: str
    investigation_id: str
    adjudication_id: str
    scope: Scope
    state: IncidentState
    severity: Severity
    confidence: Confidence
    source_signal_ids: tuple[str, ...]
    observation_ids: tuple[str, ...]
    claim_ids: tuple[str, ...]
    supporting_evidence_refs: tuple[str, ...]
    contradicting_evidence_refs: tuple[str, ...]
    adjudicated_at: datetime
    authorized_action_executed: bool = False

    _timestamps_aware = field_validator("adjudicated_at")(classmethod(lambda _cls, value: _aware(value)))

    @model_validator(mode="after")
    def _containment_requires_action(self) -> Incident:
        if self.state == IncidentState.CONTAINED and not self.authorized_action_executed:
            raise ValueError("an incident cannot be CONTAINED without a recorded authorized action")
        return self


class ResponseProposal(DetectionResponseModel):
    proposal_id: str
    incident_id: str
    scope: Scope
    target_id: str
    action: ResponseAction
    reason: str
    supporting_evidence_refs: tuple[str, ...]
    expected_impact: str
    risk: str
    rollback_plan: str
    expires_at: datetime
    proposal_digest: str
    opa_decision: OpaDecision
    human_approval_state: HumanApprovalState
    authorized_action_executed: bool = False

    _non_empty_fields = field_validator(
        "proposal_id", "incident_id", "target_id", "reason", "expected_impact", "risk", "rollback_plan", "proposal_digest"
    )(classmethod(lambda _cls, value: _non_empty(value)))
    _timestamps_aware = field_validator("expires_at")(classmethod(lambda _cls, value: _aware(value)))

    @model_validator(mode="after")
    def _not_executed(self) -> ResponseProposal:
        if self.authorized_action_executed:
            raise ValueError("v0.3 response proposals cannot record an executed action")
        return self


class CapabilityRequest(DetectionResponseModel):
    request_id: str
    proposal_id: str
    scope: Scope
    target_id: str
    action: ResponseAction
    proposal_digest: str
    requested_at: datetime

    _timestamps_aware = field_validator("requested_at")(classmethod(lambda _cls, value: _aware(value)))


class HumanApproval(DetectionResponseModel):
    approval_id: str
    proposal_id: str
    proposal_digest: str
    scope: Scope
    target_id: str
    action: ResponseAction
    decision: HumanApprovalState
    decided_by: str
    decided_at: datetime
    source: str
    expires_at: datetime

    _non_empty_fields = field_validator("approval_id", "proposal_id", "proposal_digest", "decided_by", "source")(
        classmethod(lambda _cls, value: _non_empty(value))
    )
    _timestamps_aware = field_validator("decided_at", "expires_at")(classmethod(lambda _cls, value: _aware(value)))


class SecurityEventIngestPort(Protocol):
    def ingest(self, event: SecurityEvent) -> EventIngestResult: ...

    def ingest_raw(self, raw: dict[str, Any]) -> EventIngestResult: ...

    def events(self, *, tenant: str | None = None, case: str | None = None) -> tuple[SecurityEvent, ...]: ...


class ResponsePolicyPort(Protocol):
    def decide(self, context: Mapping[str, Any]) -> OpaDecision: ...


class DetectionScopeError(PermissionError):
    """A read or write crossed the bound tenant/case/target scope."""


class DetectionInputError(ValueError):
    """Malformed or unsupported detection input."""


class UnsupportedDetectionConstruct(DetectionInputError):
    """The bounded v0.3 rule/Sigma subset refuses this construct."""


class AdjudicationRefused(PermissionError):
    """The evidence/authority chain is insufficient for an Incident."""


class ResponseAuthorizationError(PermissionError):
    """OPA or human approval binding failed closed."""


class ResponseExecutionDisabled(RuntimeError):
    """v0.3 proposes actions but has no execution authority."""


# Short aliases used in architecture documents and by callers that prefer the
# domain vocabulary without the Incident prefix.
Investigation = IncidentInvestigation
