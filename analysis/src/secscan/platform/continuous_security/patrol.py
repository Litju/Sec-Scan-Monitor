"""Deterministic snapshot diffing and targeted continuous patrol."""

from __future__ import annotations

import hashlib
import json
from enum import Enum
from typing import Any, Callable, Iterable

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SECURITY_SURFACES = (
    "source",
    "dependencies",
    "sbom",
    "agent_declarations",
    "mcp_tools",
    "a2a_agents",
    "capabilities",
    "opa_policies",
    "deployment",
    "vulnerability_intelligence",
    "exposure_reachability",
)


class _FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ChangeState(str, Enum):
    NEW = "NEW"
    CHANGED = "CHANGED"
    RESOLVED = "RESOLVED"
    UNCHANGED = "UNCHANGED"
    UNKNOWN = "UNKNOWN"


class FindingState(str, Enum):
    OPEN = "OPEN"
    CHANGED = "CHANGED"
    RESOLVED = "RESOLVED"


class CanonicalSnapshot(_FrozenModel):
    """Canonical patrol input. Metadata is deliberately outside security diffing."""

    tenant_id: str
    case_id: str
    target_id: str
    snapshot_id: str
    surfaces: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("tenant_id", "case_id", "target_id", "snapshot_id")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("snapshot scope identifiers must be non-empty")
        return value

    @property
    def security_payload(self) -> dict[str, Any]:
        return {name: self.surfaces.get(name, {}) for name in SECURITY_SURFACES}

    @property
    def digest(self) -> str:
        payload = {
            "tenant_id": self.tenant_id,
            "case_id": self.case_id,
            "target_id": self.target_id,
            "surfaces": self.security_payload,
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


class SnapshotDelta(_FrozenModel):
    surface: str
    key: str
    state: ChangeState
    before: Any = None
    after: Any = None

    @property
    def affected_surface(self) -> str:
        return f"{self.surface}:{self.key}"


class PatrolCandidate(_FrozenModel):
    """A claim candidate returned by targeted assessment, not a Finding."""

    condition_key: str
    title: str
    severity: str
    affected_surface: str
    supporting_evidence_refs: tuple[str, ...]
    adjudicated: bool = False
    rationale: str = ""

    @model_validator(mode="after")
    def _requires_evidence_for_adjudication(self) -> PatrolCandidate:
        if self.adjudicated and not self.supporting_evidence_refs:
            raise ValueError("an adjudicated patrol candidate requires evidence references")
        return self


class PatrolFinding(_FrozenModel):
    """Stable finding identity for one continuing condition and scope."""

    finding_id: str
    condition_key: str
    tenant_id: str
    case_id: str
    target_id: str
    title: str
    severity: str
    state: FindingState
    affected_surface: str
    supporting_evidence_refs: tuple[str, ...]
    snapshot_id: str
    rationale: str = ""


class PatrolRunResult(_FrozenModel):
    baseline_snapshot_id: str
    current_snapshot_id: str
    baseline_digest: str
    current_digest: str
    deltas: tuple[SnapshotDelta, ...]
    reassessed_surfaces: tuple[str, ...]
    findings: tuple[PatrolFinding, ...]


class InMemoryFindingStore:
    """Test/reference store; PostgreSQL remains the production canonical adapter."""

    def __init__(self) -> None:
        self._findings: dict[tuple[str, str, str, str], PatrolFinding] = {}

    @staticmethod
    def _key(tenant_id: str, case_id: str, target_id: str, condition_key: str) -> tuple[str, str, str, str]:
        return tenant_id, case_id, target_id, condition_key

    def get(self, *, tenant_id: str, case_id: str, target_id: str, condition_key: str) -> PatrolFinding | None:
        return self._findings.get(self._key(tenant_id, case_id, target_id, condition_key))

    def for_surface(self, *, tenant_id: str, case_id: str, target_id: str, surface: str) -> tuple[PatrolFinding, ...]:
        return tuple(
            sorted(
                (
                    finding
                    for finding in self._findings.values()
                    if finding.tenant_id == tenant_id
                    and finding.case_id == case_id
                    and finding.target_id == target_id
                    and finding.affected_surface == surface
                    and finding.state != FindingState.RESOLVED
                ),
                key=lambda finding: finding.finding_id,
            )
        )

    def upsert(
        self,
        *,
        candidate: PatrolCandidate,
        snapshot: CanonicalSnapshot,
        state: FindingState,
    ) -> PatrolFinding:
        key = self._key(snapshot.tenant_id, snapshot.case_id, snapshot.target_id, candidate.condition_key)
        existing = self._findings.get(key)
        if existing is None:
            finding_id = "PF-" + hashlib.sha256("|".join(key).encode("utf-8")).hexdigest()[:32]
        else:
            finding_id = existing.finding_id
        finding = PatrolFinding(
            finding_id=finding_id,
            condition_key=candidate.condition_key,
            tenant_id=snapshot.tenant_id,
            case_id=snapshot.case_id,
            target_id=snapshot.target_id,
            title=candidate.title,
            severity=candidate.severity,
            state=state,
            affected_surface=candidate.affected_surface,
            supporting_evidence_refs=candidate.supporting_evidence_refs,
            snapshot_id=snapshot.snapshot_id,
            rationale=candidate.rationale,
        )
        self._findings[key] = finding
        return finding

    def resolve_surface(self, *, snapshot: CanonicalSnapshot, surface: str) -> tuple[PatrolFinding, ...]:
        resolved: list[PatrolFinding] = []
        for finding in self.for_surface(
            tenant_id=snapshot.tenant_id,
            case_id=snapshot.case_id,
            target_id=snapshot.target_id,
            surface=surface,
        ):
            updated = finding.model_copy(update={"state": FindingState.RESOLVED, "snapshot_id": snapshot.snapshot_id})
            self._findings[self._key(snapshot.tenant_id, snapshot.case_id, snapshot.target_id, finding.condition_key)] = updated
            resolved.append(updated)
        return tuple(resolved)

    def all(self) -> tuple[PatrolFinding, ...]:
        return tuple(sorted(self._findings.values(), key=lambda finding: finding.finding_id))


def _stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def diff_snapshots(previous: CanonicalSnapshot, current: CanonicalSnapshot) -> tuple[SnapshotDelta, ...]:
    if (previous.tenant_id, previous.case_id, previous.target_id) != (
        current.tenant_id,
        current.case_id,
        current.target_id,
    ):
        raise ValueError("patrol cannot diff snapshots across tenant, case, or target scope")
    deltas: list[SnapshotDelta] = []
    for surface in SECURITY_SURFACES:
        before = previous.surfaces.get(surface, {})
        after = current.surfaces.get(surface, {})
        if _stable_json(before) == _stable_json(after):
            continue
        if isinstance(before, dict) and isinstance(after, dict):
            keys = sorted(set(before) | set(after))
            for key in keys:
                before_value = before.get(key)
                after_value = after.get(key)
                if _stable_json(before_value) == _stable_json(after_value):
                    continue
                if key not in before:
                    state = ChangeState.NEW
                elif key not in after:
                    state = ChangeState.RESOLVED
                else:
                    state = ChangeState.CHANGED
                deltas.append(SnapshotDelta(surface=surface, key=str(key), state=state, before=before_value, after=after_value))
        else:
            deltas.append(SnapshotDelta(surface=surface, key="$", state=ChangeState.CHANGED, before=before, after=after))
    return tuple(sorted(deltas, key=lambda delta: (delta.surface, delta.key, delta.state.value)))


Assessment = Callable[[SnapshotDelta], Iterable[PatrolCandidate]]


class PatrolEngine:
    """Run only the affected reassessment surface and preserve finding identity."""

    def __init__(self, finding_store: InMemoryFindingStore) -> None:
        self._finding_store = finding_store

    def run(
        self,
        *,
        baseline: CanonicalSnapshot,
        current: CanonicalSnapshot,
        assess: Assessment,
    ) -> PatrolRunResult:
        deltas = diff_snapshots(baseline, current)
        reassessed: list[str] = []
        findings: list[PatrolFinding] = []
        for delta in deltas:
            if delta.state == ChangeState.RESOLVED:
                findings.extend(self._finding_store.resolve_surface(snapshot=current, surface=delta.affected_surface))
                continue
            if delta.state not in {ChangeState.NEW, ChangeState.CHANGED}:
                continue
            reassessed.append(delta.affected_surface)
            candidates = sorted(assess(delta), key=lambda item: item.condition_key)
            for candidate in candidates:
                if not candidate.adjudicated:
                    continue
                state = FindingState.OPEN if delta.state == ChangeState.NEW else FindingState.CHANGED
                findings.append(self._finding_store.upsert(candidate=candidate, snapshot=current, state=state))
            if delta.state == ChangeState.CHANGED and not candidates:
                findings.extend(self._finding_store.resolve_surface(snapshot=current, surface=delta.affected_surface))
        return PatrolRunResult(
            baseline_snapshot_id=baseline.snapshot_id,
            current_snapshot_id=current.snapshot_id,
            baseline_digest=baseline.digest,
            current_digest=current.digest,
            deltas=deltas,
            reassessed_surfaces=tuple(sorted(set(reassessed))),
            findings=tuple(sorted(findings, key=lambda finding: finding.finding_id)),
        )
