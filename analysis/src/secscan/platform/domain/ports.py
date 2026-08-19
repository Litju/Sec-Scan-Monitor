"""Ports: the domain-facing contracts implemented by adapters.

Everything external to the firm's business rules is reached through these
Protocols. Adapters live in their own platform subpackages (persistence,
policy, sandbox, gateway, agents) and must not leak types into domain.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Protocol

from secscan.platform.domain.audit import AuditEvent
from secscan.platform.domain.authority import PolicyDecision
from secscan.platform.domain.engagement import Engagement
from secscan.platform.domain.ids import ClientId, EngagementId
from secscan.platform.domain.planning import AssessmentPlan
from secscan.platform.domain.profiles import TargetSecurityProfile
from secscan.platform.domain.qualification import QualificationReceipt
from secscan.platform.domain.services import SecurityServiceContract, ServiceRun


class EvidenceStore(Protocol):
    """Content-addressed blob store (SHA-256 addressing, immutable writes)."""

    def put(self, content: bytes, *, content_type: str) -> str: ...

    def get(self, sha256: str) -> bytes: ...


class PolicyEngine(Protocol):
    """Deterministic authorization decider (OPA/Rego adapter implements it)."""

    def decide(self, request: dict[str, Any]) -> PolicyDecision: ...


class SandboxBackend(Protocol):
    """Isolated execution backend for capabilities."""

    def is_available(self) -> bool: ...

    def run(
        self,
        *,
        command: list[str],
        profile: dict[str, Any],
        timeout_seconds: int,
        input_bytes: bytes | None = None,
        mounts: list[tuple[str, str, bool]] | None = None,
        environment: dict[str, str] | None = None,
        working_dir: str | None = None,
    ) -> dict[str, Any]:
        """Run a command under a profile; return captured result dict.

        ``mounts`` entries are ``(host_path, container_path, read_only)``.
        The application layer only passes read-only target mounts for
        inspection capabilities; scratch is provided by the backend itself.
        """
        ...


class AuditSink(Protocol):
    """Append-only audit ledger."""

    def append(self, event: AuditEvent) -> None: ...

    def read_since(self, since: datetime | None = None) -> list[AuditEvent]: ...


class ModelPort(Protocol):
    """Structured-output model boundary. Fake model for CI; provider
    adapters (e.g. Pydantic AI) are optional execution adapters."""

    def complete_structured(
        self,
        *,
        prompt: str,
        output_schema: type[Any],
        context: dict[str, Any] | None = None,
    ) -> Any:
        """Return an instance of output_schema. Fail closed on schema error."""
        ...


class EngagementRepository(Protocol):
    """Canonical engagement persistence (PostgreSQL adapter implements it).

    The application layer reads and writes engagements through this port;
    correctness never depends on process-local dictionaries. The in-memory
    AppState used by the dev/test API is a composition convenience, not
    canonical state.
    """

    def save(self, engagement: Engagement) -> None: ...

    def get(self, engagement_id: EngagementId) -> Engagement | None: ...


class SecurityServiceRepository(Protocol):
    """Canonical persistence seam for inspection-service state."""

    def save_profile(self, *, profile: TargetSecurityProfile, client_id: ClientId) -> str: ...

    def save_plan(self, *, plan: AssessmentPlan, client_id: ClientId, profile_id: str) -> None: ...

    def save_run(self, *, run: ServiceRun, payload: dict[str, Any] | None = None) -> None: ...

    def save_qualification(
        self,
        *,
        contract: SecurityServiceContract,
        receipt: QualificationReceipt,
    ) -> None: ...

    def commit(self) -> None: ...

    def get_profile_for_engagement(
        self,
        *,
        client_id: ClientId,
        engagement_id: EngagementId,
    ) -> dict[str, Any] | None: ...

    def get_plan(self, *, client_id: ClientId, engagement_id: EngagementId) -> dict[str, Any] | None: ...

    def get_assessment_chain(
        self,
        *,
        client_id: ClientId,
        engagement_id: EngagementId,
    ) -> dict[str, Any] | None: ...

    def list_runs(self, *, client_id: ClientId, engagement_id: EngagementId) -> list[Any]: ...

    def list_qualifications(self) -> list[Any]: ...
