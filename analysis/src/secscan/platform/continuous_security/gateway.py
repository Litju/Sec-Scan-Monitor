"""MCP/A2A security gateway: identity, schema, capability, and OPA gates."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Mapping

from pydantic import BaseModel, ConfigDict, Field, field_validator

from secscan.platform.continuous_security.events import EventClass, SecurityEventPlane
from secscan.platform.domain.authority import PolicyDecision
from secscan.platform.domain.ports import EvidenceStore, PolicyEngine
from secscan.sanitize.filters import scrub_text, stable_json


class _FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ProtocolKind(str, Enum):
    MCP = "MCP"
    A2A = "A2A"


class RegisteredAgent(_FrozenModel):
    agent_id: str
    tenant_id: str
    case_id: str
    allowed_capabilities: tuple[str, ...]


class RegisteredTool(_FrozenModel):
    tool_id: str
    protocol: ProtocolKind
    tenant_id: str
    case_id: str
    server_id: str
    capability_id: str
    schema_digest: str
    allowed_actions: tuple[str, ...]
    privileged: bool = False


class GatewayRequest(_FrozenModel):
    request_id: str
    tenant_id: str
    case_id: str
    protocol: ProtocolKind
    agent_id: str
    server_id: str
    tool_id: str
    declared_capability: str
    schema_digest: str
    requested_action: str
    target_id: str
    principal_id: str
    engagement_id: str
    authority_ref: str
    approval_id: str | None = None
    requested_resources: dict[str, str] = Field(default_factory=dict)
    occurred_at: datetime
    observed_at: datetime

    @field_validator(
        "request_id",
        "tenant_id",
        "case_id",
        "agent_id",
        "server_id",
        "tool_id",
        "declared_capability",
        "schema_digest",
        "requested_action",
        "target_id",
        "principal_id",
        "engagement_id",
        "authority_ref",
    )
    @classmethod
    def _non_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("gateway request identity fields must be non-empty")
        return value


class GatewayResult(_FrozenModel):
    request_id: str
    decision: PolicyDecision
    reason: str
    event_id: str
    output_evidence_ref: str | None = None
    injection_detected: bool = False


class GatewayRegistry:
    """Scope-bound protocol registry; it is not a reverse-proxy route table."""

    def __init__(self) -> None:
        self._agents: dict[str, RegisteredAgent] = {}
        self._tools: dict[str, RegisteredTool] = {}

    def register_agent(self, agent: RegisteredAgent) -> None:
        existing = self._agents.get(agent.agent_id)
        if existing is not None and existing != agent:
            raise ValueError(f"agent {agent.agent_id} already has a different declaration")
        self._agents[agent.agent_id] = agent

    def register_tool(self, tool: RegisteredTool) -> None:
        existing = self._tools.get(tool.tool_id)
        if existing is not None and existing != tool:
            raise ValueError(f"tool {tool.tool_id} already has a different declaration")
        self._tools[tool.tool_id] = tool

    def agent(self, agent_id: str) -> RegisteredAgent | None:
        return self._agents.get(agent_id)

    def tool(self, tool_id: str) -> RegisteredTool | None:
        return self._tools.get(tool_id)


PolicyContextFactory = Callable[[GatewayRequest, RegisteredTool], Mapping[str, Any]]


class AgentSecurityGateway:
    """Fail-closed gateway for MCP/A2A security decisions.

    The context factory is a server-side seam to canonical engagement,
    authority, approval, and graph state. Request payloads never supply the
    grant or policy result, and tool output is handled only as untrusted
    evidence after authorization.
    """

    _CONTROL_KEYS = {
        "authority",
        "policy",
        "registry",
        "approval",
        "finding_state",
        "decision",
        "capability",
    }
    _INJECTION_RE = re.compile(r"(?i)(ignore\s+(?:all\s+)?previous|override\s+policy|approve\s+this|elevate\s+authority)")

    def __init__(
        self,
        *,
        registry: GatewayRegistry,
        policy_engine: PolicyEngine,
        policy_context: PolicyContextFactory,
        events: SecurityEventPlane,
        evidence_store: EvidenceStore | None = None,
    ) -> None:
        self._registry = registry
        self._policy = policy_engine
        self._policy_context = policy_context
        self._events = events
        self._evidence_store = evidence_store
        self._decisions: dict[str, tuple[GatewayRequest, GatewayResult]] = {}

    def authorize(self, request: GatewayRequest) -> GatewayResult:
        tool = self._registry.tool(request.tool_id)
        agent = self._registry.agent(request.agent_id)
        reason = self._validate_identity(request, agent=agent, tool=tool)
        if reason is not None or tool is None:
            result = self._finish(request, PolicyDecision.DENY, reason or "unknown tool")
            self._decisions[request.request_id] = (request, result)
            return result
        try:
            context = dict(self._policy_context(request, tool))
            policy_input = self._policy_input(request, tool, context)
            decision = self._policy.decide(policy_input)
            if not isinstance(decision, PolicyDecision):
                decision = PolicyDecision.DENY
        except Exception:
            # A missing or malformed canonical authority projection is a deny,
            # never a gateway-side fallback to allow.
            decision = PolicyDecision.DENY
            reason = "canonical policy context unavailable"
        else:
            reason = {
                PolicyDecision.ALLOW: "OPA allowed the request",
                PolicyDecision.DENY: "OPA denied the request",
                PolicyDecision.REQUIRE_APPROVAL: "OPA requires request-bound approval",
            }[decision]
        result = self._finish(request, decision, reason)
        self._decisions[request.request_id] = (request, result)
        return result

    def complete(self, request: GatewayRequest, tool_output: Mapping[str, Any]) -> GatewayResult:
        authorized = self._decisions.get(request.request_id)
        if authorized is None:
            return self._finish(request, PolicyDecision.DENY, "request was not authorized")
        authorized_request, decision = authorized
        if authorized_request != request:
            return self._finish(request, PolicyDecision.DENY, "request does not match the authorized request")
        if decision.decision != PolicyDecision.ALLOW:
            return decision
        safe_text, injection_detected = self._sanitize_tool_output(tool_output)
        evidence_ref: str | None = None
        if self._evidence_store is not None:
            evidence_ref = self._evidence_store.put(safe_text.encode("utf-8"), content_type="gateway-tool-output")
        else:
            evidence_ref = hashlib.sha256(safe_text.encode("utf-8")).hexdigest()
        event = self._event(
            request,
            event_class=EventClass.MCP_ACTIVITY if request.protocol == ProtocolKind.MCP else EventClass.A2A_ACTIVITY,
            outcome="completed",
            raw_evidence_ref=evidence_ref,
            attributes={"tool_id": request.tool_id, "injection_detected": injection_detected},
        )
        return GatewayResult(
            request_id=request.request_id,
            decision=decision.decision,
            reason=decision.reason,
            event_id=event,
            output_evidence_ref=evidence_ref,
            injection_detected=injection_detected,
        )

    def _validate_identity(
        self,
        request: GatewayRequest,
        *,
        agent: RegisteredAgent | None,
        tool: RegisteredTool | None,
    ) -> str | None:
        if agent is None:
            return "unknown agent"
        if tool is None:
            return "unknown tool"
        if agent.tenant_id != request.tenant_id or agent.case_id != request.case_id:
            return "agent scope mismatch"
        if tool.tenant_id != request.tenant_id or tool.case_id != request.case_id:
            return "tool scope mismatch"
        if tool.protocol != request.protocol:
            return "protocol identity mismatch"
        if tool.server_id != request.server_id:
            return "server identity mismatch"
        if tool.capability_id != request.declared_capability:
            return "undeclared capability"
        if tool.schema_digest != request.schema_digest:
            return "schema drift"
        if request.requested_action not in tool.allowed_actions:
            return "requested action is not declared by the tool"
        if request.declared_capability not in agent.allowed_capabilities:
            return "agent capability ceiling denied"
        return None

    @staticmethod
    def _policy_input(
        request: GatewayRequest, tool: RegisteredTool, context: dict[str, Any]
    ) -> dict[str, Any]:
        """Build a policy input from canonical context plus validated identity."""
        policy_input = dict(context)
        policy_input["principal"] = {"id": request.principal_id}
        policy_input["target"] = {"id": request.target_id}
        policy_input["capability"] = {
            "id": tool.capability_id,
            "registered": True,
            "risk_class": "high" if tool.privileged else "low",
            "requires_approval": tool.privileged,
            "required_authority": request.requested_action,
        }
        policy_input["action"] = request.requested_action
        policy_input["requested_resources"] = dict(request.requested_resources)
        policy_input["gateway"] = {
            "protocol": request.protocol.value,
            "agent_id": request.agent_id,
            "server_id": request.server_id,
            "tool_id": request.tool_id,
            "schema_digest": request.schema_digest,
        }
        return policy_input

    def _event(
        self,
        request: GatewayRequest,
        *,
        event_class: EventClass,
        outcome: str,
        raw_evidence_ref: str,
        attributes: dict[str, Any],
    ) -> str:
        source_digest = hashlib.sha256(stable_json(attributes).encode("utf-8")).hexdigest()
        result = self._events.ingest_raw(
            {
                "source": "secscan-agent-gateway",
                "source_record_id": f"{request.request_id}:{outcome}",
                "source_digest": source_digest,
                "source_system": "secscan-agent-gateway",
                "collector_version": "gateway-v1",
                "source_type": request.protocol.value,
                "event_class": event_class.value,
                "occurred_at": request.occurred_at,
                "observed_at": request.observed_at,
                "tenant": request.tenant_id,
                "case": request.case_id,
                "target": request.target_id,
                "actor": request.agent_id,
                "object": request.tool_id,
                "action": request.requested_action,
                "outcome": outcome,
                "raw_evidence_ref": raw_evidence_ref,
                "normalization_version": "security-events-v1",
                "attributes": attributes,
            }
        )
        return result.event.event_id

    def _finish(self, request: GatewayRequest, decision: PolicyDecision, reason: str) -> GatewayResult:
        event_id = self._event(
            request,
            event_class=EventClass.CAPABILITY_DECISION,
            outcome=decision.value,
            raw_evidence_ref=f"metadata://gateway/{request.request_id}",
            attributes={"decision": decision.value, "authority_ref": request.authority_ref},
        )
        return GatewayResult(request_id=request.request_id, decision=decision, reason=reason, event_id=event_id)

    @classmethod
    def _sanitize_tool_output(cls, output: Mapping[str, Any]) -> tuple[str, bool]:
        def sanitize(value: Any) -> Any:
            if isinstance(value, Mapping):
                return {str(key): sanitize(item) for key, item in value.items()}
            if isinstance(value, list):
                return [sanitize(item) for item in value]
            if isinstance(value, str):
                return scrub_text(value)[0]
            return value

        serialized = stable_json(sanitize(dict(output)))
        sanitized, _notes = scrub_text(serialized)
        control_attempt = any(
            re.search(rf'(?i)"{re.escape(key)}"\s*:', sanitized) for key in cls._CONTROL_KEYS
        )
        injection_detected = control_attempt or bool(cls._INJECTION_RE.search(sanitized))
        # The output remains evidence. Control-looking keys are not deleted,
        # but the caller receives only a sanitized evidence reference and the
        # boolean flag; no gateway state is updated from this text.
        return sanitized, injection_detected
