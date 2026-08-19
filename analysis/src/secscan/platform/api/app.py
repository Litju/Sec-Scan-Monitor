"""Localhost-first firm API (ADR §18).

Authorization is enforced at the application boundary: every request passes
through the operator auth dependency, which refuses non-loopback clients in
dev mode. No anonymous mutation endpoints exist. Raw evidence bytes are
never served through an unrestricted endpoint — metadata only.

Dev auth: clearly marked local/operator provider. It refuses to activate on
non-loopback binding (checked at app creation), per charter
localhost_first_firm_services.
"""

from __future__ import annotations

import hmac
import ipaddress
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, cast

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from secscan.platform.application.authority_service import AuthorityService
from secscan.platform.application.engagement_service import EngagementService
from secscan.platform.audit import InMemoryAuditSink
from secscan.platform.domain.authority import Approval
from secscan.platform.domain.engagement import (
    AuthorityLevel,
    Engagement,
    EngagementStatus,
    InvalidEngagementTransition,
    PassType,
)
from secscan.platform.domain.ids import (
    ClientId,
    EngagementId,
    PrincipalId,
    TargetId,
)
from secscan.platform.domain.ports import EngagementRepository, PolicyEngine
from secscan.platform.domain.services import SecurityServiceRegistry, default_service_registry
from secscan.platform.hosted.commands import HostedCommandError, HostedWorkflowRequest, HostedWorkflowUnavailable
from secscan.platform.hosted.config import HostedConfigurationError, RuntimeConfig
from secscan.platform.hosted.identity import (
    HumanAccessDenied,
    HumanAccessService,
    HumanIdentityVerifier,
    VerifiedHumanIdentity,
    extract_bearer_token,
)
from secscan.platform.policy import DeterministicDecisionAdapter

OPERATOR_PRINCIPAL = PrincipalId("PRN-OPERATOR")
LOGGER = logging.getLogger(__name__)


def _operator_approver_authorizer(approval: Approval, principal: PrincipalId) -> bool:
    """Development API approval authority is bound to the operator principal."""
    return principal == OPERATOR_PRINCIPAL


class DevAuthInactiveError(RuntimeError):
    """Dev auth refused to activate because the binding is not loopback."""


class LocalOperatorAuth:
    """Development operator provider.

    Two controls, honestly separated:
    - The per-request client check (effective control): every request from
      a non-loopback peer is refused with 403 regardless of binding. This
      is what keeps the API localhost-first even if the process is bound
      to a wider interface by an operator.
    - The bind_host argument check (defense-in-depth): refuses to activate
      when the declared bind host is non-loopback. It inspects the
      configuration, not the actual socket — the request check is the
      enforcement that cannot be bypassed by uvicorn flags.
    """

    def __init__(self, bind_host: str = "127.0.0.1") -> None:
        self._bind_host = bind_host
        self._activate()

    def _activate(self) -> None:
        if not _is_loopback(self._bind_host):
            raise DevAuthInactiveError(
                f"dev auth refuses to activate on non-loopback binding {self._bind_host!r} "
                "(charter: localhost_first_firm_services)"
            )

    def authenticate(self, principal_header: str | None, request: Request) -> PrincipalId:
        client_host = request.client.host if request.client else ""
        if not _is_loopback(client_host):
            raise HTTPException(status_code=403, detail="dev auth: non-loopback clients refused")
        if not principal_header:
            raise HTTPException(status_code=401, detail="dev auth: X-Secscan-Principal header required")
        return PrincipalId(principal_header)


def _is_loopback(host: str) -> bool:
    if not host:
        return False
    if host in {"127.0.0.1", "localhost", "::1"}:
        return True
    if host == "testclient":
        # TestClient ASGI-transport sentinel (starlette/httpx). Not a real
        # network host; treated as the loopback test harness.
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


@dataclass
class AppState:
    """Dev/test composition root (in-memory). Canonical-state law: this is
    NOT canonical state — the same create_app accepts a Postgres-backed
    state via `engagement_repo`; see the PG-backed API integration test.
    Production composition wires PostgreSQL repositories."""

    clients: dict[str, dict[str, Any]] = field(default_factory=dict)
    targets: dict[str, dict[str, Any]] = field(default_factory=dict)
    engagements: dict[str, Engagement] = field(default_factory=dict)
    runs: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    evidence_metadata: dict[str, dict[str, Any]] = field(default_factory=dict)
    findings: dict[str, dict[str, Any]] = field(default_factory=dict)
    approvals: dict[str, Approval] = field(default_factory=dict)
    reports: dict[str, dict[str, Any]] = field(default_factory=dict)
    audit: InMemoryAuditSink = field(default_factory=InMemoryAuditSink)
    capabilities: list[dict[str, Any]] = field(default_factory=list)
    policy: PolicyEngine = field(default_factory=DeterministicDecisionAdapter)
    service_registry: SecurityServiceRegistry = field(default_factory=default_service_registry)
    security_profiles: dict[str, dict[str, Any]] = field(default_factory=dict)
    assessment_plans: dict[str, dict[str, Any]] = field(default_factory=dict)
    service_runs: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    qualification: dict[str, dict[str, Any]] = field(default_factory=dict)


def create_app(
    state: AppState | None = None,
    bind_host: str = "127.0.0.1",
    engagement_repo: EngagementRepository | None = None,
    *,
    runtime_config: RuntimeConfig | None = None,
    identity_verifier: HumanIdentityVerifier | None = None,
    read_model_service: Any | None = None,
    human_access_service: HumanAccessService | None = None,
    readiness_probe: Callable[[], dict[str, Any]] | None = None,
    hosted_command_service: Any | None = None,
    hosted_evidence_store: Any | None = None,
    hosted_workflow_executor: Any | None = None,
    hosted_workflow_secret: str | None = None,
    hosted_token_revocation_store: Any | None = None,
) -> FastAPI:
    """Localhost-first firm API.

    `engagement_repo` (optional): when provided, every engagement mutation
    is persisted through the canonical repository port and reads fall back
    to it — PostgreSQL-backed composition. Without it, the in-memory
    AppState serves dev/test (not canonical state).
    """
    runtime_config = runtime_config or RuntimeConfig.from_env()
    if runtime_config.is_hosted:
        runtime_config.require_hosted_boundaries()
        if state is not None or engagement_repo is not None:
            raise HostedConfigurationError(
                "HOSTED_INTEGRATED refuses in-memory state and local engagement repositories"
            )
        if identity_verifier is None or read_model_service is None or human_access_service is None:
            raise HostedConfigurationError(
                "HOSTED_INTEGRATED requires verified identity, tenant access, and canonical read models"
            )
        return _create_hosted_app(
            runtime_config,
            identity_verifier,
            read_model_service,
            human_access_service,
            readiness_probe,
            hosted_command_service,
            hosted_evidence_store,
            hosted_workflow_executor,
            hosted_workflow_secret,
            hosted_token_revocation_store,
        )

    state = state or AppState()
    auth = LocalOperatorAuth(bind_host=bind_host)
    engagement_service = EngagementService(audit=state.audit)
    app = FastAPI(title="SecScanMonitor Firm API", version="0.1.0", docs_url=None, redoc_url=None)

    def _load_engagement(engagement_id: str) -> Engagement | None:
        engagement = state.engagements.get(EngagementId(engagement_id))
        if engagement is None and engagement_repo is not None:
            engagement = engagement_repo.get(EngagementId(engagement_id))
            if engagement is not None:
                state.engagements[engagement.engagement_id] = engagement
        return engagement

    def _persist(engagement: Engagement) -> None:
        state.engagements[engagement.engagement_id] = engagement
        if engagement_repo is not None:
            engagement_repo.save(engagement)

    def _principal(
        request: Request,
        principal_header: str | None = Header(default=None, alias="X-Secscan-Principal"),
    ) -> PrincipalId:
        return auth.authenticate(principal_header, request)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "service": "secscan-platform", "version": "0.1.0"}

    @app.post("/clients")
    def create_client(payload: dict[str, Any], principal: PrincipalId = Depends(_principal)) -> dict[str, Any]:
        client_id = ClientId(payload["client_id"])
        state.clients[client_id] = {"client_id": client_id, "name": payload["name"]}
        return state.clients[client_id]

    @app.get("/clients/{client_id}")
    def get_client(client_id: str, principal: PrincipalId = Depends(_principal)) -> dict[str, Any]:
        if client_id not in state.clients:
            raise HTTPException(status_code=404, detail="client not found")
        return state.clients[client_id]

    @app.post("/targets")
    def create_target(payload: dict[str, Any], principal: PrincipalId = Depends(_principal)) -> dict[str, Any]:
        target_id = TargetId(payload["target_id"])
        state.targets[target_id] = {
            "target_id": target_id,
            "kind": payload.get("kind", "repository"),
            "name": payload["name"],
        }
        return state.targets[target_id]

    @app.get("/targets/{target_id}")
    def get_target(target_id: str, principal: PrincipalId = Depends(_principal)) -> dict[str, Any]:
        if target_id not in state.targets:
            raise HTTPException(status_code=404, detail="target not found")
        return state.targets[target_id]

    @app.post("/engagements")
    def create_engagement(payload: dict[str, Any], principal: PrincipalId = Depends(_principal)) -> dict[str, Any]:
        engagement = engagement_service.create(
            engagement_id=EngagementId(payload["engagement_id"]),
            client_id=ClientId(payload["client_id"]),
            requester_principal_id=principal,
            target_ids=[TargetId(t) for t in payload["target_ids"]],
            scope=payload["scope"],
            pass_type=PassType(payload["pass_type"]),
            authority_level=AuthorityLevel(payload.get("authority_level", "inspection-only")),
            constraints=payload.get("constraints"),
        )
        _persist(engagement)
        return _engagement_view(engagement)

    @app.get("/engagements/{engagement_id}")
    def get_engagement(engagement_id: str, principal: PrincipalId = Depends(_principal)) -> dict[str, Any]:
        engagement = _load_engagement(engagement_id)
        if engagement is None:
            raise HTTPException(status_code=404, detail="engagement not found")
        return _engagement_view(engagement)

    @app.post("/engagements/{engagement_id}/authorize")
    def authorize_engagement(engagement_id: str, principal: PrincipalId = Depends(_principal)) -> dict[str, Any]:
        engagement = _get_engagement_or_404(engagement_id)
        if engagement.status in {EngagementStatus.DRAFT, EngagementStatus.INTAKE, EngagementStatus.SCOPE_VALIDATED}:
            while engagement.status != EngagementStatus.AUTHORIZED:
                engagement_service.transition(
                    engagement,
                    EngagementStatus.INTAKE if engagement.status == EngagementStatus.DRAFT else
                    EngagementStatus.SCOPE_VALIDATED if engagement.status == EngagementStatus.INTAKE else
                    EngagementStatus.AUTHORIZED,
                    principal_id=principal,
                    reason="api authorize",
                )
        elif engagement.status != EngagementStatus.AUTHORIZED:
            raise HTTPException(status_code=409, detail=f"cannot authorize from {engagement.status.value}")
        _persist(engagement)
        return _engagement_view(engagement)

    @app.post("/engagements/{engagement_id}/suspend")
    def suspend_engagement(engagement_id: str, principal: PrincipalId = Depends(_principal)) -> dict[str, Any]:
        engagement = _get_engagement_or_404(engagement_id)
        try:
            engagement_service.suspend(engagement, principal_id=principal, reason="api suspend")
        except InvalidEngagementTransition as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        _persist(engagement)
        return _engagement_view(engagement)

    @app.post("/engagements/{engagement_id}/resume")
    def resume_engagement(engagement_id: str, principal: PrincipalId = Depends(_principal)) -> dict[str, Any]:
        engagement = _get_engagement_or_404(engagement_id)
        try:
            engagement_service.resume(engagement, principal_id=principal, reason="api resume")
        except (InvalidEngagementTransition, ValueError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        _persist(engagement)
        return _engagement_view(engagement)

    @app.get("/capabilities")
    def list_capabilities(principal: PrincipalId = Depends(_principal)) -> list[dict[str, Any]]:
        from secscan.platform.capabilities import FOUNDATION_CAPABILITIES

        return [capability.model_dump(mode="json") for capability in FOUNDATION_CAPABILITIES]

    @app.get("/services")
    def list_services(principal: PrincipalId = Depends(_principal)) -> list[dict[str, Any]]:
        """Public-language service catalog; internal engines stay hidden."""
        return [
            {
                "service_id": contract.service_id,
                "name": contract.name,
                "version": contract.version,
                "qualification_state": contract.qualification_state.value,
                "visibility": contract.visibility.value,
                "supported_target_types": contract.supported_target_types,
            }
            for contract in state.service_registry.all()
        ]

    @app.get("/engagements/{engagement_id}/security-profile")
    def security_profile(engagement_id: str, principal: PrincipalId = Depends(_principal)) -> dict[str, Any]:
        _get_engagement_or_404(engagement_id)
        profile = state.security_profiles.get(engagement_id)
        if profile is None:
            raise HTTPException(status_code=404, detail="target security profile not available")
        return profile

    @app.get("/engagements/{engagement_id}/assessment-plan")
    def assessment_plan(engagement_id: str, principal: PrincipalId = Depends(_principal)) -> dict[str, Any]:
        _get_engagement_or_404(engagement_id)
        plan = state.assessment_plans.get(engagement_id)
        if plan is None:
            raise HTTPException(status_code=404, detail="assessment plan not available")
        return plan

    @app.get("/engagements/{engagement_id}/service-runs")
    def service_runs(engagement_id: str, principal: PrincipalId = Depends(_principal)) -> list[dict[str, Any]]:
        _get_engagement_or_404(engagement_id)
        return state.service_runs.get(engagement_id, [])

    @app.get("/qualification")
    def qualification_status(principal: PrincipalId = Depends(_principal)) -> dict[str, dict[str, Any]]:
        if state.qualification:
            return state.qualification
        return {
            contract.service_id: {
                "service_id": contract.service_id,
                "version": contract.version,
                "qualification_state": contract.qualification_state.value,
                "visibility": contract.visibility.value,
            }
            for contract in state.service_registry.all()
        }

    @app.get("/engagements/{engagement_id}/runs")
    def list_runs(engagement_id: str, principal: PrincipalId = Depends(_principal)) -> list[dict[str, Any]]:
        _get_engagement_or_404(engagement_id)
        return state.runs.get(engagement_id, [])

    @app.get("/evidence/{evidence_id}/metadata")
    def evidence_metadata(evidence_id: str, principal: PrincipalId = Depends(_principal)) -> dict[str, Any]:
        meta = state.evidence_metadata.get(evidence_id)
        if meta is None:
            raise HTTPException(status_code=404, detail="evidence not found")
        return meta  # metadata only; raw bytes are never served here

    @app.get("/findings/{finding_id}")
    def get_finding(finding_id: str, principal: PrincipalId = Depends(_principal)) -> dict[str, Any]:
        finding = state.findings.get(finding_id)
        if finding is None:
            raise HTTPException(status_code=404, detail="finding not found")
        return finding

    @app.get("/engagements/{engagement_id}/findings")
    def list_findings(engagement_id: str, principal: PrincipalId = Depends(_principal)) -> list[dict[str, Any]]:
        _get_engagement_or_404(engagement_id)
        return [finding for finding in state.findings.values() if finding.get("engagement_id") == engagement_id]

    @app.post("/approvals/{approval_id}/approve")
    def approve(approval_id: str, principal: PrincipalId = Depends(_principal)) -> dict[str, Any]:
        approval = state.approvals.get(approval_id)
        if approval is None:
            raise HTTPException(status_code=404, detail="approval not found")
        # application boundary: approval decisions go through
        # AuthorityService.decide_approval and emit an APPROVAL_DECISION
        # audit event — the API never mutates the aggregate directly.
        try:
            AuthorityService(
                policy=state.policy,
                audit=state.audit,
                approver_authorizer=_operator_approver_authorizer,
            ).decide_approval(
                approval,
                decision="approved",
                by=principal,
            )
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        return {"approval_id": approval.approval_id, "decision": approval.decision}

    @app.post("/approvals/{approval_id}/deny")
    def deny(approval_id: str, principal: PrincipalId = Depends(_principal)) -> dict[str, Any]:
        approval = state.approvals.get(approval_id)
        if approval is None:
            raise HTTPException(status_code=404, detail="approval not found")
        try:
            AuthorityService(
                policy=state.policy,
                audit=state.audit,
                approver_authorizer=_operator_approver_authorizer,
            ).decide_approval(
                approval,
                decision="denied",
                by=principal,
            )
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        return {"approval_id": approval.approval_id, "decision": approval.decision}

    @app.get("/engagements/{engagement_id}/report")
    def get_report(engagement_id: str, principal: PrincipalId = Depends(_principal)) -> dict[str, Any]:
        report = state.reports.get(engagement_id)
        if report is None:
            raise HTTPException(status_code=404, detail="report not found")
        return report  # sanitized by the report renderer (no-secrets asserted)

    def _get_engagement_or_404(engagement_id: str) -> Engagement:
        engagement = _load_engagement(engagement_id)
        if engagement is None:
            raise HTTPException(status_code=404, detail="engagement not found")
        return engagement

    return app


def _create_hosted_app(
    runtime_config: RuntimeConfig,
    identity_verifier: HumanIdentityVerifier,
    read_model_service: Any,
    human_access_service: HumanAccessService,
    readiness_probe: Callable[[], dict[str, Any]] | None,
    command_service: Any | None,
    evidence_store: Any | None,
    workflow_executor: Any | None,
    workflow_secret: str | None,
    token_revocation_store: Any | None,
) -> FastAPI:
    """Hosted authenticated command/read surface over canonical PostgreSQL."""

    app = FastAPI(title="SecScanMonitor Firm API", version="0.1.0", docs_url=None, redoc_url=None)

    def _human_identity(
        authorization: str | None = Header(default=None, alias="Authorization"),
        cookie: str | None = Header(default=None, alias="Cookie"),
    ) -> VerifiedHumanIdentity:
        try:
            token = extract_bearer_token(authorization)
            identity = identity_verifier.verify_bearer_token(token)
            session_verifier = getattr(identity_verifier, "verify_session_cookie", None)
            if callable(session_verifier) and cookie and session_verifier(cookie) != identity.subject:
                raise PermissionError("active human session does not match identity")
        except (ValueError, PermissionError) as exc:
            raise HTTPException(status_code=401, detail="human identity verification failed") from exc
        except Exception as exc:
            raise HTTPException(status_code=401, detail="human identity verification failed") from exc
        if (
            not identity.human_principal_id
            or not identity.subject
            or identity.issuer != runtime_config.auth_issuer
        ):
            raise HTTPException(status_code=401, detail="human identity verification failed")
        return identity

    @app.post("/auth/revoke")
    def revoke_hosted_session(
        authorization: str | None = Header(default=None, alias="Authorization"),
    ) -> dict[str, str]:
        if token_revocation_store is None:
            raise HTTPException(status_code=503, detail="session revocation is not ready")
        try:
            token = extract_bearer_token(authorization)
            identity = identity_verifier.verify_bearer_token(token)
            token_revocation_store.revoke(token, identity.human_principal_id)
        except (ValueError, PermissionError) as exc:
            raise HTTPException(status_code=401, detail="human identity verification failed") from exc
        except Exception as exc:
            raise HTTPException(status_code=503, detail="session revocation failed closed") from exc
        return {"status": "revoked"}

    def _require_client_access(identity: VerifiedHumanIdentity, client_id: str) -> None:
        try:
            human_access_service.require_client_access(identity, client_id)
        except (HumanAccessDenied, ValueError) as exc:
            # Keep tenant existence opaque; PostgreSQL RLS remains the final
            # enforcement boundary for every returned row.
            raise HTTPException(status_code=404, detail="resource not found") from exc

    def _require_command_service() -> Any:
        if command_service is None:
            raise HTTPException(status_code=503, detail="hosted command boundary is not ready")
        return command_service

    def _require_evidence_store() -> Any:
        if evidence_store is None:
            raise HTTPException(status_code=503, detail="private evidence store is not ready")
        return evidence_store

    @app.post("/internal/workflows/{workflow_run_id}/execute")
    def hosted_execute_workflow(
        workflow_run_id: str,
        payload: HostedWorkflowExecutionRequest,
        secret: str | None = Header(default=None, alias="X-Secscan-Workflow-Secret"),
    ) -> dict[str, Any]:
        if not workflow_secret or not secret or not hmac.compare_digest(secret, workflow_secret):
            raise HTTPException(status_code=404, detail="not found")
        if workflow_executor is None or payload.workflow_run_id != workflow_run_id:
            raise HTTPException(status_code=503, detail="hosted workflow execution is not ready")
        try:
            return cast(
                dict[str, Any],
                workflow_executor.run(
                    HostedWorkflowRequest(
                        engagement_id=payload.engagement_id,
                        workflow_run_id=payload.workflow_run_id,
                        client_id=payload.client_id,
                        target_id=payload.target_id,
                        principal_id=payload.principal_id,
                        target_snapshot_id=payload.target_snapshot_id,
                        target_snapshot_sha256=payload.target_snapshot_sha256,
                        target_source_identity=payload.target_source_identity,
                    ),
                ),
            )
        except Exception as exc:
            LOGGER.error(
                "hosted workflow executor failed closed: %s: %s",
                type(exc).__name__,
                str(exc)[:160],
                extra={"workflow_run_id": workflow_run_id},
            )
            raise HTTPException(status_code=503, detail="hosted workflow execution failed closed") from exc

    @app.get("/health")
    def hosted_health() -> dict[str, str]:
        return {"status": "ok", "service": "secscan-platform", "version": "0.1.0"}

    @app.get("/ready")
    def hosted_ready() -> dict[str, Any]:
        if readiness_probe is None:
            raise HTTPException(status_code=503, detail="hosted readiness is not validated")
        try:
            result = readiness_probe()
        except Exception as exc:
            raise HTTPException(status_code=503, detail="hosted readiness probe failed") from exc
        if result.get("status") != "ready":
            raise HTTPException(status_code=503, detail="hosted dependencies are not ready")
        checks = result.get("checks", {})
        return {
            "status": "ready",
            "service": "secscan-platform",
            "configured": runtime_config.dependency_configuration(),
            "checks": {str(name): bool(value) for name, value in checks.items()},
        }

    @app.get("/firm/summary")
    def hosted_summary(identity: VerifiedHumanIdentity = Depends(_human_identity)) -> dict[str, Any]:
        return cast(dict[str, Any], read_model_service.firm_summary(identity=identity).model_dump(mode="json"))

    @app.get("/clients")
    def hosted_clients(
        cursor: str | None = None,
        limit: int = Query(default=50, ge=1, le=100),
        identity: VerifiedHumanIdentity = Depends(_human_identity),
    ) -> dict[str, Any]:
        return cast(dict[str, Any], read_model_service.list_clients(identity=identity, cursor=cursor, limit=limit).model_dump(mode="json"))

    @app.get("/targets")
    def hosted_targets(
        client_id: str | None = None,
        cursor: str | None = None,
        limit: int = Query(default=50, ge=1, le=100),
        identity: VerifiedHumanIdentity = Depends(_human_identity),
    ) -> dict[str, Any]:
        if client_id is not None:
            _require_client_access(identity, client_id)
        return cast(dict[str, Any], read_model_service.list_targets(
            identity=identity, client_id=client_id, cursor=cursor, limit=limit
        ).model_dump(mode="json"))

    @app.get("/engagements")
    def hosted_engagements(
        client_id: str | None = None,
        cursor: str | None = None,
        limit: int = Query(default=50, ge=1, le=100),
        identity: VerifiedHumanIdentity = Depends(_human_identity),
    ) -> dict[str, Any]:
        if client_id is not None:
            _require_client_access(identity, client_id)
        return cast(dict[str, Any], read_model_service.list_engagements(
            identity=identity, client_id=client_id, cursor=cursor, limit=limit
        ).model_dump(mode="json"))

    @app.get("/engagements/{engagement_id}")
    def hosted_engagement(
        engagement_id: str,
        identity: VerifiedHumanIdentity = Depends(_human_identity),
    ) -> dict[str, Any]:
        result = read_model_service.get_engagement(identity=identity, engagement_id=engagement_id)
        if result is None:
            raise HTTPException(status_code=404, detail="engagement not found")
        return cast(dict[str, Any], result.model_dump(mode="json"))

    @app.post("/engagements")
    def hosted_create_engagement(
        payload: HostedCaseRequest,
        identity: VerifiedHumanIdentity = Depends(_human_identity),
    ) -> dict[str, Any]:
        _require_client_access(identity, payload.client_id)
        try:
            engagement = _require_command_service().create_case(
                identity=identity,
                engagement_id=payload.engagement_id,
                client_id=payload.client_id,
                target_ids=payload.target_ids,
                scope=payload.scope,
                pass_type=payload.pass_type,
                constraints=payload.constraints,
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="case scope not found") from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail="case command rejected") from exc
        return _engagement_view(engagement)

    @app.post("/engagements/{engagement_id}/authorize")
    def hosted_authorize_engagement(
        engagement_id: str,
        identity: VerifiedHumanIdentity = Depends(_human_identity),
    ) -> dict[str, Any]:
        try:
            engagement = _require_command_service().authorize_case(
                identity=identity, engagement_id=engagement_id
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="case not found") from exc
        except PermissionError as exc:
            raise HTTPException(status_code=404, detail="case not found") from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail="case authorization rejected") from exc
        return _engagement_view(engagement)

    @app.post("/engagements/{engagement_id}/start-inspection")
    def hosted_start_inspection(
        engagement_id: str,
        payload: HostedInspectionRequest,
        identity: VerifiedHumanIdentity = Depends(_human_identity),
    ) -> dict[str, Any]:
        try:
            workflow = _require_command_service().start_inspection(
                identity=identity,
                engagement_id=engagement_id,
                target_id=payload.target_id,
                target_snapshot_id=payload.target_snapshot_id,
            )
        except HostedWorkflowUnavailable as exc:
            raise HTTPException(status_code=503, detail="hosted workflow is not ready") from exc
        except HostedCommandError as exc:
            raise HTTPException(status_code=409, detail="inspection command rejected") from exc
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="case or target not found") from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail="inspection command rejected") from exc
        return {
            "workflow_run_id": workflow.workflow_run_id,
            "engagement_id": workflow.engagement_id,
            "status": workflow.status,
            "current_phase": workflow.current_phase,
        }

    @app.get("/findings")
    def hosted_findings(
        engagement_id: str | None = None,
        cursor: str | None = None,
        limit: int = Query(default=50, ge=1, le=100),
        identity: VerifiedHumanIdentity = Depends(_human_identity),
    ) -> dict[str, Any]:
        return cast(dict[str, Any], read_model_service.list_findings(
            identity=identity, engagement_id=engagement_id, cursor=cursor, limit=limit
        ).model_dump(mode="json"))

    @app.get("/findings/{finding_id}")
    def hosted_finding(
        finding_id: str,
        identity: VerifiedHumanIdentity = Depends(_human_identity),
    ) -> dict[str, Any]:
        result = read_model_service.get_finding(identity=identity, finding_id=finding_id)
        if result is None:
            raise HTTPException(status_code=404, detail="finding not found")
        return cast(dict[str, Any], result)

    @app.get("/engagements/{engagement_id}/findings")
    def hosted_engagement_findings(
        engagement_id: str,
        identity: VerifiedHumanIdentity = Depends(_human_identity),
    ) -> dict[str, Any]:
        result = read_model_service.list_findings(identity=identity, engagement_id=engagement_id, limit=100)
        return cast(dict[str, Any], result.model_dump(mode="json"))

    @app.get("/engagements/{engagement_id}/runs")
    def hosted_workflow_runs(
        engagement_id: str,
        identity: VerifiedHumanIdentity = Depends(_human_identity),
    ) -> list[dict[str, Any]]:
        return cast(list[dict[str, Any]], read_model_service.list_workflow_runs(
            identity=identity, engagement_id=engagement_id
        ))

    @app.get("/workflow-runs/{workflow_run_id}")
    def hosted_workflow_run(
        workflow_run_id: str,
        identity: VerifiedHumanIdentity = Depends(_human_identity),
    ) -> dict[str, Any]:
        result = read_model_service.get_workflow_run(identity=identity, workflow_run_id=workflow_run_id)
        if result is None:
            raise HTTPException(status_code=404, detail="workflow run not found")
        return cast(dict[str, Any], result)

    @app.get("/evidence")
    def hosted_evidence(
        engagement_id: str | None = None,
        cursor: str | None = None,
        limit: int = Query(default=50, ge=1, le=100),
        identity: VerifiedHumanIdentity = Depends(_human_identity),
    ) -> dict[str, Any]:
        return cast(dict[str, Any], read_model_service.list_evidence(
            identity=identity, engagement_id=engagement_id, cursor=cursor, limit=limit
        ).model_dump(mode="json"))

    @app.get("/evidence/{evidence_id}")
    def hosted_evidence_metadata(
        evidence_id: str,
        identity: VerifiedHumanIdentity = Depends(_human_identity),
    ) -> dict[str, Any]:
        result = read_model_service.get_evidence_storage(identity=identity, evidence_id=evidence_id)
        if result is None:
            raise HTTPException(status_code=404, detail="evidence not found")
        storage_ref, content_type, engagement_id = result
        return {
            "evidence_id": evidence_id,
            "engagement_id": engagement_id,
            "content_type": content_type,
            "retrieval": "authenticated-backend-only",
            "sha256": storage_ref,
        }

    @app.get("/evidence/{evidence_id}/content")
    def hosted_evidence_content(
        evidence_id: str,
        identity: VerifiedHumanIdentity = Depends(_human_identity),
    ) -> Response:
        result = read_model_service.get_evidence_storage(identity=identity, evidence_id=evidence_id)
        if result is None:
            raise HTTPException(status_code=404, detail="evidence not found")
        storage_ref, content_type, _engagement_id = result
        try:
            content = _require_evidence_store().get(storage_ref)
        except Exception as exc:
            raise HTTPException(status_code=503, detail="evidence store unavailable") from exc
        return Response(
            content=content,
            media_type=content_type,
            headers={"Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff"},
        )

    @app.get("/engagements/{engagement_id}/report")
    def hosted_report(
        engagement_id: str,
        identity: VerifiedHumanIdentity = Depends(_human_identity),
    ) -> dict[str, Any]:
        result = read_model_service.get_report(identity=identity, engagement_id=engagement_id)
        if result is None:
            raise HTTPException(status_code=404, detail="report not found")
        return cast(dict[str, Any], result)

    @app.get("/reports/{report_id}")
    def hosted_report_by_id(
        report_id: str,
        identity: VerifiedHumanIdentity = Depends(_human_identity),
    ) -> dict[str, Any]:
        result = read_model_service.get_report_by_id(identity=identity, report_id=report_id)
        if result is None:
            raise HTTPException(status_code=404, detail="report not found")
        return cast(dict[str, Any], result)

    @app.get("/reports/{report_id}/content")
    def hosted_report_content(
        report_id: str,
        identity: VerifiedHumanIdentity = Depends(_human_identity),
    ) -> Response:
        result = read_model_service.get_report_storage(identity=identity, report_id=report_id)
        if result is None:
            raise HTTPException(status_code=404, detail="report not found")
        sha256, _storage_ref, _engagement_id = result
        try:
            content = _require_evidence_store().get(sha256)
        except Exception as exc:
            raise HTTPException(status_code=503, detail="evidence store unavailable") from exc
        return Response(
            content=content,
            media_type="text/markdown",
            headers={"Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff"},
        )

    @app.get("/audit")
    def hosted_audit(
        cursor: str | None = None,
        limit: int = Query(default=50, ge=1, le=100),
        identity: VerifiedHumanIdentity = Depends(_human_identity),
    ) -> dict[str, Any]:
        return cast(dict[str, Any], read_model_service.list_audit(identity=identity, cursor=cursor, limit=limit).model_dump(mode="json"))

    return app


class HostedCaseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    engagement_id: str = Field(min_length=1, max_length=96, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,95}$")
    client_id: str = Field(min_length=1, max_length=64)
    target_ids: list[str] = Field(min_length=1, max_length=16)
    scope: str = Field(min_length=1, max_length=4000)
    pass_type: str = Field(min_length=1, max_length=32)
    constraints: list[str] = Field(default_factory=list, max_length=32)


class HostedInspectionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_id: str = Field(min_length=1, max_length=64)
    target_snapshot_id: str = Field(min_length=1, max_length=128)


class HostedWorkflowExecutionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    engagement_id: str = Field(min_length=1, max_length=96)
    workflow_run_id: str = Field(min_length=1, max_length=128)
    client_id: str = Field(min_length=1, max_length=64)
    target_id: str = Field(min_length=1, max_length=64)
    principal_id: str = Field(min_length=1, max_length=96)
    target_snapshot_id: str = Field(min_length=1, max_length=128)
    target_snapshot_sha256: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")
    target_source_identity: str = Field(min_length=1, max_length=4000)


def _engagement_view(engagement: Engagement) -> dict[str, Any]:
    return {
        "engagement_id": engagement.engagement_id,
        "client_id": engagement.client_id,
        "target_ids": engagement.target_ids,
        "scope": engagement.scope,
        "pass_type": engagement.pass_type.value,
        "authority_level": engagement.authority_level.value,
        "status": engagement.status.value,
        "status_history": engagement.status_history,
    }
