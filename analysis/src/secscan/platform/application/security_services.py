"""Release 0.1 deterministic security-service engines and orchestration.

The engines inspect a shared immutable snapshot and return observations plus
claim candidates.  Only the existing adjudication service creates Findings.
"""

from __future__ import annotations

import hashlib
import json
import re
import tomllib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import PurePosixPath
from typing import Any, Callable, Iterable, Mapping, Sequence
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from pydantic import BaseModel, ConfigDict, Field

from secscan.platform.adjudication import AdjudicationService
from secscan.platform.capabilities import CapabilityRegistry
from secscan.platform.domain.agent_security import (
    AgentNode,
    AgentSystemManifest,
    AgentSystemSecurityProfile,
    MemoryBoundary,
    ToolAuthorityEdge,
    ToolNode,
)
from secscan.platform.domain.common import Confidence, Severity, utc_now
from secscan.platform.domain.engagement import AuthorityLevel, Engagement, EngagementStatus
from secscan.platform.domain.evidence import Claim, EvidenceObject, Observation, SanitizationState
from secscan.platform.domain.finding import Adjudication, Finding
from secscan.platform.domain.ids import (
    AgentId,
    AgentRunId,
    CapabilityId,
    ClaimId,
    ClientId,
    EngagementId,
    EvidenceId,
    FindingId,
    ObservationId,
    PrincipalId,
    TargetId,
    ToolInvocationId,
)
from secscan.platform.domain.planning import AssessmentPlan, route_services
from secscan.platform.domain.ports import SecurityServiceRepository
from secscan.platform.domain.profiles import (
    ProfileFact,
    ProfileFactStatus,
    ProfileProvenance,
    TargetSecurityProfile,
)
from secscan.platform.domain.services import (
    SecurityServiceContract,
    SecurityServiceRegistry,
    ServiceRun,
    ServiceRunStatus,
    default_service_registry,
)
from secscan.platform.domain.supply_chain import (
    ControlStatus,
    PackageResolutionAssessment,
    ProvenanceAssessment,
    SbomAssessment,
    SbomComponent,
    SupplyChainAssessment,
    SupplyChainStage,
    WorkflowAssessment,
)
from secscan.platform.domain.vulnerability import (
    ExposureState,
    FeedProvenance,
    FeedState,
    PriorityClass,
    PriorityDecision,
    ReachabilityState,
    VulnerabilityRecord,
    canonical_vulnerability_id,
    normalize_package_name,
)
from secscan.sanitize.filters import scrub_text


@dataclass(frozen=True)
class RepositorySnapshot:
    """Immutable inspection input; raw file content is never put in a profile."""

    target_id: str
    snapshot_id: str
    target_identity: str
    files: Mapping[str, str]
    source_identity: str = "repository"

    @classmethod
    def from_files(
        cls,
        *,
        target_id: str,
        target_identity: str,
        files: Mapping[str, str],
        snapshot_id: str | None = None,
        source_identity: str = "repository",
    ) -> "RepositorySnapshot":
        digest_input = "".join(
            f"{path}\0{files[path]}\0" for path in sorted(files)
        ).encode("utf-8", errors="replace")
        digest = hashlib.sha256(digest_input).hexdigest()
        return cls(
            target_id=target_id,
            snapshot_id=snapshot_id or f"SNAP-{digest[:20]}",
            target_identity=target_identity,
            files=dict(files),
            source_identity=source_identity,
        )


class ServiceObservation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    service_id: str
    code: str
    statement: str
    evidence_refs: list[str] = Field(default_factory=list)
    confidence: Confidence = Confidence.UNKNOWN
    suggested_severity: Severity | None = None
    standard_references: list[str] = Field(default_factory=list)
    status: str = "OBSERVED"
    limitation: str = ""


class ClaimCandidate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    service_id: str
    dedupe_key: str
    statement: str
    evidence_refs: list[str] = Field(min_length=1)
    severity: Severity
    confidence: Confidence = Confidence.MEDIUM
    affected_component: str = ""
    preconditions: list[str] = Field(default_factory=list)
    impact: str = ""
    remediation: str = ""
    verification: str = ""
    standard_references: list[str] = Field(default_factory=list)
    contradicting_evidence_refs: list[str] = Field(default_factory=list)


class ServiceResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    service_id: str
    status: ServiceRunStatus
    observations: list[ServiceObservation] = Field(default_factory=list)
    claim_candidates: list[ClaimCandidate] = Field(default_factory=list)
    evidence_objects: list[EvidenceObject] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    outputs: dict[str, Any] = Field(default_factory=dict)


def _safe_slug(value: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-")
    if len(normalized) > 56:
        # ponytail: bounded IDs with a deterministic suffix; expand only if a
        # persistence key limit above 64 characters becomes a real requirement.
        normalized = f"{normalized[:45]}-{hashlib.sha256(value.encode()).hexdigest()[:10]}"
    return normalized or "root"


def _evidence_id(snapshot: RepositorySnapshot, path: str, kind: str) -> EvidenceId:
    digest = hashlib.sha256(f"{snapshot.snapshot_id}\0{path}\0{kind}".encode()).hexdigest()[:20]
    return EvidenceId(f"EVD-{digest}")


def _fact(
    *,
    snapshot: RepositorySnapshot,
    key: str,
    value: Any,
    path: str,
    status: ProfileFactStatus = ProfileFactStatus.DISCOVERED,
    confidence: Confidence = Confidence.MEDIUM,
    source_kind: str = "code_discovered",
) -> ProfileFact:
    return ProfileFact(
        key=key,
        value=value,
        status=status,
        confidence=confidence,
        provenance=ProfileProvenance(
            source_kind=source_kind,
            source_ref=path,
            snapshot_id=snapshot.snapshot_id,
            evidence_id=str(_evidence_id(snapshot, path, key)),
        ),
    )


class AttackSurfaceMapper:
    """Modular deterministic repository detectors for TargetSecurityProfile."""

    def map(self, snapshot: RepositorySnapshot) -> TargetSecurityProfile:
        files = {str(PurePosixPath(path)): content for path, content in snapshot.files.items()}
        profile = TargetSecurityProfile(
            target_id=snapshot.target_id,
            snapshot_id=snapshot.snapshot_id,
            target_identity=snapshot.target_identity,
            snapshot_identity=snapshot.source_identity,
        )
        self._detect_languages(profile, snapshot, files)
        self._detect_manifests(profile, snapshot, files)
        self._detect_frameworks_and_routes(profile, snapshot, files)
        self._detect_deployment(profile, snapshot, files)
        self._detect_agent_surface(profile, snapshot, files)
        self._detect_secret_references(profile, snapshot, files)
        self._classify(profile)
        if not profile.network_interfaces:
            profile.unknowns.append("runtime network exposure is not established by repository artifacts")
        if not profile.authentication_surfaces:
            profile.unknowns.append("authentication implementation was not identified")
        return profile

    @staticmethod
    def _detect_languages(profile: TargetSecurityProfile, snapshot: RepositorySnapshot, files: Mapping[str, str]) -> None:
        extensions = {
            ".py": "Python", ".ts": "TypeScript", ".tsx": "TypeScript", ".js": "JavaScript",
            ".jsx": "JavaScript", ".go": "Go", ".rs": "Rust", ".java": "Java", ".rb": "Ruby",
        }
        seen: set[str] = set()
        for path in sorted(files):
            language = extensions.get(PurePosixPath(path).suffix.lower())
            if language and language not in seen:
                seen.add(language)
                profile.languages.append(_fact(snapshot=snapshot, key="language", value=language, path=path))

    @staticmethod
    def _detect_manifests(profile: TargetSecurityProfile, snapshot: RepositorySnapshot, files: Mapping[str, str]) -> None:
        manifest_map = {
            "pyproject.toml": ("PyPI", "Python", "package_manifest"),
            "requirements.txt": ("PyPI", "Python", "package_manifest"),
            "poetry.lock": ("PyPI", "Python", "lockfile"),
            "package.json": ("npm", "JavaScript", "package_manifest"),
            "package-lock.json": ("npm", "JavaScript", "lockfile"),
            "pnpm-lock.yaml": ("npm", "JavaScript", "lockfile"),
            "yarn.lock": ("npm", "JavaScript", "lockfile"),
            "go.mod": ("Go", "Go", "package_manifest"),
            "go.sum": ("Go", "Go", "lockfile"),
            "Cargo.toml": ("crates.io", "Rust", "package_manifest"),
            "Cargo.lock": ("crates.io", "Rust", "lockfile"),
            "pom.xml": ("Maven", "Java", "package_manifest"),
            "Gemfile.lock": ("RubyGems", "Ruby", "lockfile"),
        }
        seen_ecosystems: set[str] = set()
        for path in sorted(files):
            name = PurePosixPath(path).name
            if name not in manifest_map:
                continue
            ecosystem, language, kind = manifest_map[name]
            if ecosystem not in seen_ecosystems:
                profile.package_ecosystems.append(_fact(snapshot=snapshot, key="package_ecosystem", value=ecosystem, path=path))
                seen_ecosystems.add(ecosystem)
            profile.build_release.append(_fact(snapshot=snapshot, key=kind, value=path, path=path))
            if language not in {fact.value for fact in profile.languages}:
                profile.languages.append(_fact(snapshot=snapshot, key="language", value=language, path=path))

    @staticmethod
    def _detect_frameworks_and_routes(profile: TargetSecurityProfile, snapshot: RepositorySnapshot, files: Mapping[str, str]) -> None:
        framework_markers = {
            "fastapi": "FastAPI", "flask": "Flask", "django": "Django", "express": "Express",
            "next/": "Next.js", "react": "React", "temporal": "Temporal", "sqlalchemy": "SQLAlchemy",
        }
        seen: set[str] = set()
        for path, content in sorted(files.items()):
            lower = content.lower()
            for marker, framework in framework_markers.items():
                if marker in lower and framework not in seen:
                    profile.frameworks.append(_fact(snapshot=snapshot, key="framework", value=framework, path=path))
                    seen.add(framework)
            route_count = 0
            for line_number, line in enumerate(content.splitlines(), start=1):
                if re.search(r"@(app|router)\.(get|post|put|patch|delete)|app\.(get|post|put|patch|delete)\(", line):
                    route_count += 1
                    profile.api_surfaces.append(
                        _fact(snapshot=snapshot, key="api_route", value={"path": path, "line": line_number}, path=path)
                    )
            if route_count:
                profile.entry_points.append(_fact(snapshot=snapshot, key="application_entry_point", value=path, path=path))
            if any(marker in lower for marker in ("authenticate", "authorization", "permission", "oauth", "jwt", "session")):
                profile.authentication_surfaces.append(_fact(snapshot=snapshot, key="auth_surface", value=path, path=path))
            if any(marker in lower for marker in ("tenant_id", "owner_id", "acl", "is_admin", "role_required")):
                profile.authorization_surfaces.append(_fact(snapshot=snapshot, key="authorization_surface", value=path, path=path))
            if any(marker in lower for marker in ("postgres", "sqlite", "mysql", "redis", "mongodb", "database")):
                profile.database_storage.append(_fact(snapshot=snapshot, key="storage", value=path, path=path))
            if any(marker in lower for marker in ("requests.", "httpx", "urllib", "fetch(", "axios")):
                profile.external_services.append(_fact(snapshot=snapshot, key="outbound_client", value=path, path=path))

    @staticmethod
    def _detect_deployment(profile: TargetSecurityProfile, snapshot: RepositorySnapshot, files: Mapping[str, str]) -> None:
        for path, content in sorted(files.items()):
            name = PurePosixPath(path).name.lower()
            lower = content.lower()
            if name == "dockerfile" or name.startswith("dockerfile."):
                profile.containers.append(_fact(snapshot=snapshot, key="dockerfile", value=path, path=path))
            if name in {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}:
                profile.containers.append(_fact(snapshot=snapshot, key="compose", value=path, path=path))
            if name.endswith((".tf", ".bicep", ".hcl")) or "/terraform/" in f"/{path.lower()}/":
                profile.infrastructure_as_code.append(_fact(snapshot=snapshot, key="iac", value=path, path=path))
            if ".github/workflows/" in f"/{path.lower()}/" or "/.gitlab-ci" in f"/{path.lower()}/":
                profile.cicd.append(_fact(snapshot=snapshot, key="ci_workflow", value=path, path=path))
                profile.build_release.append(_fact(snapshot=snapshot, key="release_automation", value=path, path=path))
            if any(marker in lower for marker in ("listen=0.0.0.0", "host: 0.0.0.0", "bind: 0.0.0.0")):
                profile.network_interfaces.append(_fact(snapshot=snapshot, key="configured_bind", value=path, path=path))

    @staticmethod
    def _detect_agent_surface(profile: TargetSecurityProfile, snapshot: RepositorySnapshot, files: Mapping[str, str]) -> None:
        for path, content in sorted(files.items()):
            lower = content.lower()
            name = PurePosixPath(path).name.lower()
            path_signal = any(token in f"/{path.lower()}/" for token in ("/agent", "/mcp", "/model", "/llm", "/tool"))
            content_signal = any(token in lower for token in ("mcp", "tool_registry", "model_provider", "agent_id", "system_prompt", "memory_store"))
            if path_signal or content_signal:
                profile.agentic_components.append(_fact(snapshot=snapshot, key="agentic_component", value=path, path=path))
            if "mcp" in lower or "mcp" in name:
                profile.mcp_servers.append(_fact(snapshot=snapshot, key="mcp_server_or_config", value=path, path=path))
            if any(token in lower for token in ("openai", "anthropic", "gemini", "model_provider", "llm")):
                profile.model_providers.append(_fact(snapshot=snapshot, key="model_provider_reference", value=path, path=path))
            if any(token in lower for token in ("tool_registry", "allowed_tools", "capabilities", "execute_tool", "function_call")):
                profile.tool_interfaces.append(_fact(snapshot=snapshot, key="tool_interface", value=path, path=path))
            if any(token in lower for token in ("memory_store", "conversation_memory", "vector_store", "retrieval")):
                profile.memory_persistence.append(_fact(snapshot=snapshot, key="agent_memory", value=path, path=path))

    @staticmethod
    def _detect_secret_references(profile: TargetSecurityProfile, snapshot: RepositorySnapshot, files: Mapping[str, str]) -> None:
        name_pattern = re.compile(r"\b(api[_-]?key|token|password|secret|private[_-]?key|credential)\b", re.IGNORECASE)
        for path, content in sorted(files.items()):
            for line_number, line in enumerate(content.splitlines(), start=1):
                match = name_pattern.search(line)
                if match:
                    profile.secret_references.append(
                        _fact(
                            snapshot=snapshot,
                            key="secret_reference",
                            value={"path": path, "line": line_number, "name": match.group(1).lower()},
                            path=path,
                            confidence=Confidence.LOW,
                        )
                    )

    @staticmethod
    def _classify(profile: TargetSecurityProfile) -> None:
        if profile.has_agentic_surface and profile.api_surfaces:
            profile.target_class = "agentic_web_saas"
        elif profile.api_surfaces:
            profile.target_class = "web_application"
        elif profile.package_ecosystems:
            profile.target_class = "static_library"
        else:
            profile.target_class = "unknown"


class TargetProfiler(AttackSurfaceMapper):
    """Compatibility name for the deterministic mapper."""


class AssessmentPlanner:
    def __init__(self, registry: SecurityServiceRegistry | None = None) -> None:
        self.registry = registry or default_service_registry()

    def create(self, *, engagement: Any, profile: TargetSecurityProfile) -> AssessmentPlan:
        return route_services(profile=profile, engagement=engagement, registry=self.registry)


class ApplicationSecurityService:
    service_id = "APPSEC"

    def assess(self, *, snapshot: RepositorySnapshot, profile: TargetSecurityProfile) -> ServiceResult:
        observations: list[ServiceObservation] = []
        candidates: list[ClaimCandidate] = []
        scanner_states = {name: "NOT_QUALIFIED" for name in ("Semgrep", "Gitleaks", "OSV-Scanner", "Trivy")}
        limitations = ["external scanner adapters are not qualified in this deterministic slice"]
        for path, content in sorted(snapshot.files.items()):
            for line_number, line in enumerate(content.splitlines(), start=1):
                line_lower = line.lower()
                evidence = str(_evidence_id(snapshot, path, "appsec"))
                if re.search(r"(api[_-]?key|password|secret|private[_-]?key)\s*[:=]\s*['\"]\S+", line, re.IGNORECASE):
                    observations.append(ServiceObservation(
                        service_id=self.service_id,
                        code="SECRET_VALUE_IN_SOURCE",
                        statement=f"secret-like assignment observed at {path}:{line_number}; value withheld",
                        evidence_refs=[evidence],
                        confidence=Confidence.HIGH,
                        suggested_severity=Severity.HIGH,
                        standard_references=["ASVS v5.0.0-1.2.5"],
                    ))
                    candidates.append(ClaimCandidate(
                        service_id=self.service_id,
                        dedupe_key=f"secret-source:{path}:{line_number}",
                        statement=f"A secret-like value is present in source at {path}:{line_number}; the value was not retained.",
                        evidence_refs=[evidence],
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        affected_component=path,
                        impact="A repository reader may obtain credential material from source history or artifacts.",
                        remediation="Remove the value, rotate it outside the repository, and add a secret-prevention check.",
                        verification="Re-scan the final snapshot and repository history with a redacting detector.",
                        standard_references=["ASVS v5.0.0-1.2.5"],
                    ))
                if any(marker in line_lower for marker in ("verify=false", "skip_auth", "trust_client", "x-user-id")):
                    observations.append(ServiceObservation(
                        service_id=self.service_id,
                        code="TRUST_BOUNDARY_SIGNAL",
                        statement=f"security-sensitive trust signal observed at {path}:{line_number}; runtime exploitability not established",
                        evidence_refs=[evidence],
                        confidence=Confidence.MEDIUM,
                        suggested_severity=Severity.MEDIUM,
                        standard_references=["ASVS 5.0.0", "NIST SSDF 1.1"],
                    ))
                    candidates.append(ClaimCandidate(
                        service_id=self.service_id,
                        dedupe_key=f"trust-signal:{path}:{line_number}",
                        statement=f"The implementation contains a security-sensitive trust-boundary signal at {path}:{line_number}; runtime enforcement is not established.",
                        evidence_refs=[evidence],
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        affected_component=path,
                        preconditions=["the signal is reachable in the deployed path"],
                        impact="An attacker may bypass an intended trust boundary if the signal is active in deployment.",
                        remediation="Replace implicit trust with explicit authenticated and authorized request context.",
                        verification="Exercise the relevant boundary under an authorized test plan and inspect deployed configuration.",
                        standard_references=["ASVS 5.0.0"],
                    ))
                if re.search(r"\bDEBUG\s*=\s*True\b", line, re.IGNORECASE):
                    evidence = str(_evidence_id(snapshot, path, "debug"))
                    candidates.append(ClaimCandidate(
                        service_id=self.service_id,
                        dedupe_key=f"debug-enabled:{path}:{line_number}",
                        statement=f"Debug mode is configured true at {path}:{line_number}; deployment state is not established.",
                        evidence_refs=[evidence],
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        affected_component=path,
                        impact="Verbose errors or debug behavior may disclose implementation details if enabled in deployment.",
                        remediation="Disable debug mode in release configuration and add a deployment assertion.",
                        verification="Inspect release configuration and verify the running service reports debug disabled.",
                        standard_references=["ASVS 5.0.0"],
                    ))
        return ServiceResult(
            service_id=self.service_id,
            status=ServiceRunStatus.DEGRADED if limitations else ServiceRunStatus.COMPLETED,
            observations=observations,
            claim_candidates=candidates,
            limitations=limitations,
            outputs={"scanner_states": scanner_states, "control_status": "NOT_ASSESSED where evidence is absent"},
        )


class AgentSecurityService:
    service_id = "AGENTSEC"

    def build_manifest(self, *, snapshot: RepositorySnapshot, profile: TargetSecurityProfile) -> AgentSystemManifest:
        agents: list[AgentNode] = []
        tools: list[ToolNode] = []
        edges: list[ToolAuthorityEdge] = []
        memory: list[MemoryBoundary] = []
        mcp_servers: list[str] = []
        unknowns: list[str] = []
        for path, content in sorted(snapshot.files.items()):
            lower = content.lower()
            if path.lower().endswith(("agent.json", "agents.json", "agent.yaml", "agent.yml")) or "agent_id" in lower:
                agent_id = _safe_slug(PurePosixPath(path).stem).upper()
                declared = _list_values(content, ("allowed_capabilities", "requested_capabilities", "allowed_tools"))
                effective = _list_values(content, ("effective_capabilities", "effective_tools", "runtime_capabilities"))
                agents.append(AgentNode(
                    agent_id=agent_id,
                    identity=agent_id,
                    model_provider=_first_marker(content, ("openai", "anthropic", "gemini", "model_provider")),
                    declared_capabilities=declared,
                    effective_capabilities=effective or declared,
                    source_ref=path,
                ))
            if "mcp" in lower or "tool_registry" in lower or "allowed_tools" in lower:
                tool_id = f"TOOL-{_safe_slug(PurePosixPath(path).stem).upper()}"
                tools.append(ToolNode(
                    tool_id=tool_id,
                    name=PurePosixPath(path).name,
                    transport="mcp" if "mcp" in lower else "in-process",
                    source_ref=path,
                    dynamic_discovery="dynamic" in lower and "tool" in lower,
                ))
                for capability in _list_values(content, ("allowed_capabilities", "capabilities", "effective_capabilities")):
                    edges.append(ToolAuthorityEdge(
                        agent_id=agents[-1].agent_id if agents else "UNKNOWN_AGENT",
                        capability_id=capability,
                        tool_id=tool_id,
                        target_ref=profile.target_id,
                        authority_ref="declared" if "declared" in lower else "",
                        approval_ref="exact" if "approval" in lower and "exact" in lower else "",
                        declared=capability in _list_values(content, ("allowed_capabilities", "requested_capabilities")),
                        effective=capability in _list_values(content, ("effective_capabilities", "effective_tools", "capabilities")),
                        source_ref=path,
                    ))
            if any(marker in lower for marker in ("memory_store", "conversation_memory", "vector_store")):
                memory.append(MemoryBoundary(
                    memory_id=f"MEM-{_safe_slug(PurePosixPath(path).stem).upper()}",
                    scope="cross-case" if "cross-case" in lower or "global" in lower else "unknown",
                    provenance="explicit" if "provenance" in lower else "",
                    read_authority=_list_values(content, ("memory_readers", "read_authority")),
                    write_authority=_list_values(content, ("memory_writers", "write_authority")),
                    deletion_supported="delete" in lower,
                    source_ref=path,
                ))
            if "mcp server" in lower or "mcp_servers" in lower:
                mcp_servers.append(path)
        if not agents:
            unknowns.append("agent identity is not established")
        if not tools:
            unknowns.append("tool registry is not established")
        return AgentSystemManifest(
            agents=agents,
            tools=tools,
            authority_edges=edges,
            memory=memory,
            mcp_servers=sorted(set(mcp_servers)),
            external_inputs=[path for path, content in snapshot.files.items() if any(x in content.lower() for x in ("prompt", "retrieval", "webhook"))],
            secret_scopes=[path for path, content in snapshot.files.items() if any(x in content.lower() for x in ("api_key", "token", "secret"))],
            approval_boundaries=[path for path, content in snapshot.files.items() if "approval" in content.lower()],
            execution_authority=[path for path, content in snapshot.files.items() if any(x in content.lower() for x in ("shell", "subprocess", "code execution"))],
            unknowns=unknowns,
        )

    def assess(self, *, snapshot: RepositorySnapshot, profile: TargetSecurityProfile) -> ServiceResult:
        if not profile.has_agentic_surface:
            return ServiceResult(
                service_id=self.service_id,
                status=ServiceRunStatus.INCONCLUSIVE,
                limitations=["agentic attack surface is not evidenced; Agent Security not applicable"],
            )
        manifest = self.build_manifest(snapshot=snapshot, profile=profile)
        agent_profile = AgentSystemSecurityProfile(
            target_id=snapshot.target_id,
            snapshot_id=snapshot.snapshot_id,
            manifest=manifest,
            threat_references=["OWASP Agentic Security Initiative 2025", "OWASP LLM Top 10 v2.0"],
            unknowns=manifest.unknowns,
            contradictions=manifest.contradictions,
        )
        observations: list[ServiceObservation] = []
        candidates: list[ClaimCandidate] = []
        for path, content in sorted(snapshot.files.items()):
            lower = content.lower()
            evidence = str(_evidence_id(snapshot, path, "agentsec"))
            if any(marker in lower for marker in ("ignore secscan", "ignore previous instructions", "rewrite authority", "skip adjudication")):
                observations.append(ServiceObservation(
                    service_id=self.service_id,
                    code="UNTRUSTED_INSTRUCTION_CONTENT",
                    statement=f"untrusted content contains an authority-rewrite instruction at {path}; content is treated as data",
                    evidence_refs=[evidence],
                    confidence=Confidence.HIGH,
                    suggested_severity=Severity.MEDIUM,
                    standard_references=["OWASP Agentic Security Initiative 2025"],
                ))
                candidates.append(ClaimCandidate(
                    service_id=self.service_id,
                    dedupe_key=f"agent-instruction:{path}",
                    statement=f"Untrusted content at {path} attempts to change agent authority or adjudication behavior.",
                    evidence_refs=[evidence],
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    affected_component=path,
                    impact="If treated as instructions, external content could redirect the agent outside its contract.",
                    remediation="Frame external content as data and enforce authority in the deterministic policy boundary.",
                    verification="Run the adversarial corpus and confirm the agent refuses authority-changing instructions.",
                    standard_references=["OWASP Agentic Security Initiative 2025", "OWASP LLM Top 10 v2.0"],
                ))
            if "effective_capabilities" in lower and any(
                edge.declared is False and edge.effective is True for edge in manifest.authority_edges
            ):
                candidates.append(ClaimCandidate(
                    service_id=self.service_id,
                    dedupe_key=f"agent-authority-mismatch:{path}",
                    statement=f"Effective tool authority exceeds declared authority in {path}.",
                    evidence_refs=[evidence],
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    affected_component=path,
                    impact="The agent may invoke a capability that the reviewed contract did not declare.",
                    remediation="Resolve capabilities through the canonical registry and deny undeclared effective authority.",
                    verification="Compare manifest, runtime registry, and policy decisions for every capability request.",
                    standard_references=["OWASP Agentic Security Initiative 2025"],
                ))
            if "arbitrary_capability" in lower or "capability_id_from_input" in lower:
                candidates.append(ClaimCandidate(
                    service_id=self.service_id,
                    dedupe_key=f"agent-capability-input:{path}",
                    statement=f"The implementation accepts a capability identifier from untrusted input at {path}.",
                    evidence_refs=[evidence],
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    affected_component=path,
                    impact="An attacker may request an unregistered or over-privileged capability.",
                    remediation="Resolve capability identity only through the canonical registry before policy evaluation.",
                    verification="Submit unknown, forged, and cross-engagement capability identifiers and require DENY.",
                    standard_references=["OWASP Agentic Security Initiative 2025"],
                ))
            if "cross-case" in lower and any(memory.scope == "cross-case" for memory in manifest.memory):
                candidates.append(ClaimCandidate(
                    service_id=self.service_id,
                    dedupe_key=f"agent-memory-cross-case:{path}",
                    statement=f"Agent memory is configured with cross-case scope at {path}.",
                    evidence_refs=[evidence],
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    affected_component=path,
                    impact="Untrusted or unrelated case content may contaminate another engagement's agent context.",
                    remediation="Partition memory by client, engagement, and target; require provenance and deletion semantics.",
                    verification="Attempt cross-case retrieval with isolated fixtures and inspect scope enforcement.",
                    standard_references=["OWASP Agentic Security Initiative 2025"],
                ))
        return ServiceResult(
            service_id=self.service_id,
            status=ServiceRunStatus.COMPLETED,
            observations=observations,
            claim_candidates=candidates,
            outputs={"agent_system_security_profile": agent_profile.model_dump(mode="json")},
            limitations=manifest.unknowns,
        )


class OsVFeedUnavailable(RuntimeError):
    """OSV was not available; the service must report degraded state."""


class VulnerabilityFeedUnavailable(RuntimeError):
    """An official vulnerability enrichment feed could not be read safely."""


class VulnerabilityFeedMalformed(VulnerabilityFeedUnavailable):
    """An official feed returned JSON that does not match its declared schema."""


def _fetch_live_json(
    url: str,
    *,
    method: str = "GET",
    payload: Mapping[str, Any] | None = None,
    timeout: float = 15.0,
) -> Mapping[str, Any]:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8") if payload is not None else None
    request = Request(
        url,
        data=body,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "SecScanMonitor/0.1 vulnerability-feed-qualification",
        },
        method=method,
    )
    try:
        with urlopen(request, timeout=timeout) as response:  # noqa: S310 - endpoints are fixed official feeds
            if not 200 <= response.status < 300:
                raise VulnerabilityFeedUnavailable(f"official feed returned HTTP {response.status}")
            decoded = json.loads(response.read())
    except (HTTPError, URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        raise VulnerabilityFeedUnavailable(f"official feed request failed: {type(exc).__name__}") from exc
    if not isinstance(decoded, Mapping):
        raise VulnerabilityFeedUnavailable("official feed returned a non-object JSON document")
    return decoded


def _feed_content_sha256(payload: Mapping[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _feed_state(data_version: str, retrieved_at: datetime) -> FeedState:
    """Require a parseable source timestamp before calling a feed fresh."""
    if not data_version.strip():
        return FeedState.STALE
    try:
        version_time = datetime.fromisoformat(data_version.replace("Z", "+00:00"))
    except ValueError:
        return FeedState.STALE
    if version_time.tzinfo is None:
        version_time = version_time.replace(tzinfo=UTC)
    return FeedState.STALE if version_time < retrieved_at - timedelta(days=30) else FeedState.FRESH


def _unavailable_provenance(*, source: str, source_url: str, limitation: str) -> FeedProvenance:
    return FeedProvenance(
        source=source,
        source_url=source_url,
        retrieved_at=utc_now(),
        state=FeedState.UNAVAILABLE,
        limitation=limitation,
    )


class OsVFeedAdapter:
    """OSV adapter with an explicit live mode and injected test seam."""

    endpoint = "https://api.osv.dev/v1/query"

    def __init__(
        self,
        fetcher: Callable[[str, dict[str, Any]], Mapping[str, Any]] | None = None,
        *,
        live: bool = False,
        timeout: float = 15.0,
    ) -> None:
        self.fetcher = fetcher
        self.live = live
        self.timeout = timeout

    def query(self, *, ecosystem: str, package_name: str, version: str) -> list[VulnerabilityRecord]:
        query = {"package": {"name": package_name, "ecosystem": ecosystem}, "version": version}
        if self.fetcher is not None:
            payload = self.fetcher(self.endpoint, query)
        elif self.live:
            payload = _fetch_live_json(self.endpoint, method="POST", payload=query, timeout=self.timeout)
        else:
            raise OsVFeedUnavailable("OSV fetcher is not configured; set live=True for the official feed")
        if not isinstance(payload, Mapping):
            raise VulnerabilityFeedMalformed("OSV response is not an object")
        if "vulns" not in payload and payload:
            raise VulnerabilityFeedMalformed("OSV response is missing vulns")
        raw_vulns = payload.get("vulns", [])
        if not isinstance(raw_vulns, list):
            raise VulnerabilityFeedMalformed("OSV vulns must be a list")
        for raw in raw_vulns:
            if not isinstance(raw, Mapping) or not str(raw.get("id", "")).strip():
                raise VulnerabilityFeedMalformed("OSV vulnerability entries must contain an id")
            if "aliases" in raw and not isinstance(raw["aliases"], list):
                raise VulnerabilityFeedMalformed("OSV aliases must be a list")
            if "affected" in raw and not isinstance(raw["affected"], list):
                raise VulnerabilityFeedMalformed("OSV affected must be a list")
            if "references" in raw and not isinstance(raw["references"], list):
                raise VulnerabilityFeedMalformed("OSV references must be a list")
        retrieved_at = utc_now()
        data_version = max(
            (
                str(raw.get("modified", ""))
                for raw in raw_vulns
                if isinstance(raw, Mapping) and str(raw.get("modified", "")).strip()
            ),
            default=str(payload.get("modified", "")),
        )
        provenance = FeedProvenance(
            source="OSV",
            source_url=self.endpoint,
            retrieved_at=retrieved_at,
            data_version=data_version,
            schema_version="1.0",
            content_sha256=_feed_content_sha256(payload),
            state=_feed_state(data_version, retrieved_at),
        )
        records: list[VulnerabilityRecord] = []
        for raw in raw_vulns:
            aliases = [str(value) for value in raw.get("aliases", [])]
            records.append(VulnerabilityRecord(
                package_name=package_name,
                ecosystem=ecosystem,
                installed_version=version,
                vulnerability_id=str(raw.get("id", "")),
                aliases=aliases,
                affected_range=str(raw.get("affected", "")),
                fixed_version=_first_fixed_version(raw),
                advisory_sources=[str(item.get("url", "")) for item in raw.get("references", []) if isinstance(item, Mapping)],
                provenance=[provenance],
                freshness=provenance.state,
            ))
        return records


class CisaKevFeedAdapter:
    """Read the official CISA KEV catalog with provenance and no secret state."""

    endpoint = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def __init__(
        self,
        fetcher: Callable[[str], Mapping[str, Any]] | None = None,
        *,
        live: bool = False,
        timeout: float = 15.0,
    ) -> None:
        self.fetcher = fetcher
        self.live = live
        self.timeout = timeout

    def lookup(self, *, vulnerability_ids: Iterable[str]) -> tuple[bool, FeedProvenance]:
        payload = self._read()
        if not isinstance(payload, Mapping):
            raise VulnerabilityFeedMalformed("CISA KEV response is not an object")
        wanted = {value.strip().upper() for value in vulnerability_ids if value.strip()}
        entries = payload.get("vulnerabilities")
        if not isinstance(entries, list):
            raise VulnerabilityFeedMalformed("CISA KEV vulnerabilities must be a list")
        for entry in entries:
            if not isinstance(entry, Mapping) or not str(entry.get("cveID", "")).strip():
                raise VulnerabilityFeedMalformed("CISA KEV entries must contain cveID")
        matched = any(str(entry["cveID"]).strip().upper() in wanted for entry in entries)
        data_version = str(payload.get("catalogVersion", payload.get("dateReleased", "")))
        retrieved_at = utc_now()
        provenance = FeedProvenance(
            source="CISA-KEV",
            source_url=self.endpoint,
            retrieved_at=retrieved_at,
            data_version=data_version,
            schema_version="CISA-KEV-1.0",
            content_sha256=_feed_content_sha256(payload),
            state=_feed_state(data_version, retrieved_at),
            limitation="CVE not present in the current catalog" if not matched else "",
        )
        return matched, provenance

    def _read(self) -> Mapping[str, Any]:
        if self.fetcher is not None:
            return self.fetcher(self.endpoint)
        if not self.live:
            raise VulnerabilityFeedUnavailable("CISA KEV fetcher is not configured; set live=True for the official feed")
        return _fetch_live_json(self.endpoint, timeout=self.timeout)


class FirstEpssFeedAdapter:
    """Read the official FIRST EPSS score for one CVE identifier."""

    endpoint = "https://api.first.org/data/v1/epss"

    def __init__(
        self,
        fetcher: Callable[[str], Mapping[str, Any]] | None = None,
        *,
        live: bool = False,
        timeout: float = 15.0,
    ) -> None:
        self.fetcher = fetcher
        self.live = live
        self.timeout = timeout

    def lookup(self, *, cve_id: str) -> tuple[float | None, float | None, FeedProvenance]:
        normalized = cve_id.strip().upper()
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", normalized):
            return None, None, FeedProvenance(
                source="FIRST-EPSS",
                source_url=self.endpoint,
                retrieved_at=utc_now(),
                schema_version="FIRST-EPSS-1.0",
                state=FeedState.NOT_RUN,
                limitation="no valid CVE identifier was available for EPSS lookup",
            )
        url = f"{self.endpoint}?{urlencode({'cve': normalized})}"
        if self.fetcher is not None:
            payload = self.fetcher(url)
        elif self.live:
            payload = _fetch_live_json(url, timeout=self.timeout)
        else:
            raise VulnerabilityFeedUnavailable("FIRST EPSS fetcher is not configured; set live=True for the official feed")
        if not isinstance(payload, Mapping):
            raise VulnerabilityFeedMalformed("FIRST EPSS response is not an object")
        rows = payload.get("data")
        if not isinstance(rows, list):
            raise VulnerabilityFeedMalformed("FIRST EPSS data must be a list")
        for candidate in rows:
            if not isinstance(candidate, Mapping) or not str(candidate.get("cve", "")).strip():
                raise VulnerabilityFeedMalformed("FIRST EPSS entries must contain cve")
        row = next(
            (candidate for candidate in rows if isinstance(candidate, Mapping) and str(candidate.get("cve", "")).upper() == normalized),
            None,
        ) if isinstance(rows, list) else None
        probability = _float_or_none(row.get("epss")) if row is not None else None
        percentile = _float_or_none(row.get("percentile")) if row is not None else None
        data_version = str(payload.get("version", ""))
        retrieved_at = utc_now()
        provenance = FeedProvenance(
            source="FIRST-EPSS",
            source_url=url,
            retrieved_at=retrieved_at,
            data_version=str(payload.get("version", "")),
            schema_version="FIRST-EPSS-1.0",
            content_sha256=_feed_content_sha256(payload),
            state=_feed_state(data_version, retrieved_at),
            limitation="CVE not present in the current EPSS response" if row is None else "",
        )
        return probability, percentile, provenance


class VulnerabilityFeedEnricher:
    """Enrich normalized advisories without promoting unknown feed state."""

    def __init__(
        self,
        *,
        kev: CisaKevFeedAdapter | None = None,
        epss: FirstEpssFeedAdapter | None = None,
    ) -> None:
        self.kev = kev
        self.epss = epss

    def enrich(self, record: VulnerabilityRecord) -> VulnerabilityRecord:
        provenance = list(record.provenance)
        unknowns = list(record.unknowns)
        updates: dict[str, Any] = {}
        states: list[FeedState] = [record.freshness]
        identifiers = [record.vulnerability_id, *record.aliases]
        if self.kev is not None:
            try:
                updates["kev_status"], kev_provenance = self.kev.lookup(vulnerability_ids=identifiers)
            except VulnerabilityFeedUnavailable as exc:
                kev_provenance = _unavailable_provenance(
                    source="CISA-KEV", source_url=self.kev.endpoint, limitation=str(exc)
                )
                unknowns.append("CISA KEV enrichment unavailable")
            provenance.append(kev_provenance)
            states.append(kev_provenance.state)
        if self.epss is not None:
            cve_id = canonical_vulnerability_id(record.vulnerability_id, record.aliases)
            try:
                probability, percentile, epss_provenance = self.epss.lookup(cve_id=cve_id)
                updates.update(epss_probability=probability, epss_percentile=percentile)
            except VulnerabilityFeedUnavailable as exc:
                epss_provenance = _unavailable_provenance(
                    source="FIRST-EPSS", source_url=self.epss.endpoint, limitation=str(exc)
                )
                unknowns.append("FIRST EPSS enrichment unavailable")
            provenance.append(epss_provenance)
            states.append(epss_provenance.state)
        if FeedState.UNAVAILABLE in states:
            updates["freshness"] = FeedState.UNAVAILABLE
        elif FeedState.STALE in states:
            updates["freshness"] = FeedState.STALE
        elif FeedState.NOT_RUN in states:
            updates["freshness"] = FeedState.NOT_RUN
        elif states and all(state == FeedState.FRESH for state in states):
            updates["freshness"] = FeedState.FRESH
        updates["provenance"] = provenance
        updates["unknowns"] = unknowns
        return record.model_copy(update=updates)


class VulnerabilityIntelligenceService:
    service_id = "VULNINTEL"

    def __init__(self, enricher: VulnerabilityFeedEnricher | None = None) -> None:
        self.enricher = enricher

    def assess(
        self,
        *,
        snapshot: RepositorySnapshot,
        profile: TargetSecurityProfile,
        advisories: Sequence[VulnerabilityRecord] = (),
        feed_state: FeedState = FeedState.NOT_RUN,
        now: datetime | None = None,
    ) -> ServiceResult:
        now = now or datetime.now(UTC)
        dependencies = _dependency_inventory(snapshot)
        observations: list[ServiceObservation] = []
        candidates: list[ClaimCandidate] = []
        decisions: list[PriorityDecision] = []
        matched: list[VulnerabilityRecord] = []
        for advisory in advisories:
            for dependency in dependencies:
                if normalize_package_name(advisory.package_name, advisory.ecosystem) != normalize_package_name(dependency["name"], dependency["ecosystem"]):
                    continue
                if advisory.installed_version != dependency["version"]:
                    continue
                effective_feed_state = feed_state
                if feed_state == FeedState.FRESH and not all(
                    provenance.source and provenance.source_url and provenance.content_sha256
                    for provenance in advisory.provenance
                ):
                    effective_feed_state = FeedState.NOT_RUN
                record = advisory.model_copy(update={"freshness": effective_feed_state})
                if self.enricher is not None:
                    record = self.enricher.enrich(record)
                decision = self.priority(record)
                matched.append(record)
                decisions.append(decision)
                evidence = str(_evidence_id(snapshot, dependency["path"], "vulnintel"))
                observations.append(ServiceObservation(
                    service_id=self.service_id,
                    code="VULNERABILITY_MATCH",
                    statement=f"{record.vulnerability_id} matches {record.ecosystem}:{record.package_name}@{record.installed_version} from {dependency['path']}",
                    evidence_refs=[evidence],
                    confidence=decision.confidence,
                    suggested_severity=decision.suggested_severity,
                    standard_references=["OSV Schema 1.0 / API 1.0", "CISA KEV", "FIRST EPSS API v1"],
                    status=decision.priority.value,
                ))
                if decision.priority != PriorityClass.MONITOR:
                    candidates.append(ClaimCandidate(
                        service_id=self.service_id,
                        dedupe_key=f"vulnerability:{canonical_vulnerability_id(record.vulnerability_id, record.aliases)}:{normalize_package_name(record.package_name, record.ecosystem)}",
                        statement=f"{record.vulnerability_id} affects {record.ecosystem}:{record.package_name}@{record.installed_version}; priority is {decision.priority.value} because {'; '.join(decision.reasons)}.",
                        evidence_refs=[evidence],
                        severity=decision.suggested_severity or Severity.MEDIUM,
                        confidence=decision.confidence,
                        affected_component=f"{record.ecosystem}:{record.package_name}@{record.installed_version}",
                        preconditions=["the advisory identity and installed version remain applicable"],
                        impact="The affected component may expose the target to the advisory's documented security consequence.",
                        remediation=f"Upgrade to {record.fixed_version} or apply the advisory mitigation." if record.fixed_version else "Review the advisory and establish a supported mitigation.",
                        verification="Re-run the dependency inventory and confirm the installed version is outside the affected range.",
                        standard_references=["OSV Schema 1.0 / API 1.0"],
                    ))
        limitations: list[str] = []
        if feed_state in {FeedState.STALE, FeedState.UNAVAILABLE, FeedState.NOT_RUN}:
            limitations.append(f"vulnerability feed state is {feed_state.value}; live enrichment is not treated as clean")
        if not advisories:
            limitations.append("no advisory records supplied; vulnerability absence is not validated")
        return ServiceResult(
            service_id=self.service_id,
            status=ServiceRunStatus.DEGRADED if limitations else ServiceRunStatus.COMPLETED,
            observations=observations,
            claim_candidates=candidates,
            limitations=limitations,
            outputs={"matched_records": [record.model_dump(mode="json") for record in matched], "priority_decisions": [decision.model_dump(mode="json") for decision in decisions]},
        )

    @staticmethod
    def priority(record: VulnerabilityRecord) -> PriorityDecision:
        reasons: list[str] = []
        unknowns = list(record.unknowns)
        if record.freshness in {FeedState.STALE, FeedState.UNAVAILABLE, FeedState.NOT_RUN}:
            unknowns.append(f"feed state is {record.freshness.value}")
        if record.fixed_version:
            reasons.append(f"fix available at {record.fixed_version}")
        if record.kev_status is True:
            reasons.append("CISA KEV match")
        if record.epss_probability is not None:
            reasons.append(f"EPSS probability supplied ({record.epss_probability:.3f})")
        if record.reachability == ReachabilityState.REACHABLE:
            reasons.append("reachable component established")
        elif record.reachability == ReachabilityState.LIKELY_REACHABLE:
            reasons.append("component likely reachable")
        else:
            unknowns.append(f"reachability is {record.reachability.value}")
        if record.exposure == ExposureState.ESTABLISHED:
            reasons.append("external exposure established")
        else:
            unknowns.append(f"exposure is {record.exposure.value}")
        if record.kev_status is True and record.reachability == ReachabilityState.REACHABLE and record.exposure == ExposureState.ESTABLISHED and not unknowns:
            priority = PriorityClass.URGENT
            severity = Severity.HIGH
            confidence = Confidence.HIGH
        elif record.reachability in {ReachabilityState.REACHABLE, ReachabilityState.LIKELY_REACHABLE} and record.fixed_version:
            priority = PriorityClass.HIGH
            severity = Severity.MEDIUM
            confidence = Confidence.MEDIUM if unknowns else Confidence.HIGH
        elif unknowns:
            priority = PriorityClass.INCONCLUSIVE
            severity = None
            confidence = Confidence.UNKNOWN
        else:
            priority = PriorityClass.ROUTINE
            severity = Severity.LOW
            confidence = Confidence.MEDIUM
        return PriorityDecision(
            vulnerability_id=record.vulnerability_id,
            priority=priority,
            reasons=reasons,
            unknowns=unknowns,
            suggested_severity=severity,
            confidence=confidence,
        )


class SupplyChainSecurityService:
    service_id = "SUPPLYCHAIN"

    def assess(self, *, snapshot: RepositorySnapshot, profile: TargetSecurityProfile) -> ServiceResult:
        sbom = self._parse_sbom(snapshot)
        provenance = self._parse_provenance(snapshot)
        workflows = self._analyze_workflows(snapshot)
        package_resolution = self._analyze_package_resolution(snapshot)
        containers, base_refs, digest_pinned = self._analyze_containers(snapshot)
        assessment = SupplyChainAssessment(
            stages={
                SupplyChainStage.SOURCE: ControlStatus.VERIFIED if snapshot.files else ControlStatus.NOT_ASSESSED,
                SupplyChainStage.DEPENDENCY_RESOLUTION: package_resolution.status,
                SupplyChainStage.BUILD_ENVIRONMENT: ControlStatus.NOT_ASSESSED,
                SupplyChainStage.CICD: ControlStatus.VERIFIED if workflows else ControlStatus.NOT_ASSESSED,
                SupplyChainStage.ARTIFACT: ControlStatus.VERIFIED if containers or sbom.present else ControlStatus.NOT_ASSESSED,
                SupplyChainStage.PROVENANCE: provenance.status,
                SupplyChainStage.RELEASE: ControlStatus.VERIFIED if any("release" in path.lower() for path in snapshot.files) else ControlStatus.NOT_ASSESSED,
            },
            sbom=sbom,
            provenance=provenance,
            workflows=workflows,
            package_resolution=package_resolution,
            containers=containers,
            container_base_refs=base_refs,
            digest_pinned_bases=digest_pinned,
            confidence=Confidence.MEDIUM if snapshot.files else Confidence.UNKNOWN,
        )
        observations: list[ServiceObservation] = []
        candidates: list[ClaimCandidate] = []
        for workflow in workflows:
            evidence = str(_evidence_id(snapshot, workflow.path, "supplychain-workflow"))
            if workflow.mutable_action_refs:
                observations.append(ServiceObservation(
                    service_id=self.service_id,
                    code="MUTABLE_ACTION_REFERENCE",
                    statement=f"workflow {workflow.path} contains mutable third-party action references",
                    evidence_refs=[evidence],
                    confidence=Confidence.HIGH,
                    suggested_severity=Severity.MEDIUM,
                    standard_references=["SCVS 1.0", "SLSA 1.2"],
                ))
                candidates.append(ClaimCandidate(
                    service_id=self.service_id,
                    dedupe_key=f"workflow-mutable-actions:{workflow.path}",
                    statement=f"Workflow {workflow.path} uses third-party actions without immutable commit or digest pins.",
                    evidence_refs=[evidence],
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    affected_component=workflow.path,
                    impact="A changed upstream action could alter the build or release behavior without a source review.",
                    remediation="Pin third-party actions to reviewed immutable commit SHAs and maintain an update process.",
                    verification="Check every `uses:` reference after pinning and review the pinned commit identity.",
                    standard_references=["SCVS 1.0", "SLSA 1.2"],
                ))
            if workflow.dangerous_permissions:
                evidence = str(_evidence_id(snapshot, workflow.path, "supplychain-permissions"))
                candidates.append(ClaimCandidate(
                    service_id=self.service_id,
                    dedupe_key=f"workflow-permissions:{workflow.path}",
                    statement=f"Workflow {workflow.path} grants security-sensitive write permissions: {', '.join(sorted(workflow.dangerous_permissions))}.",
                    evidence_refs=[evidence],
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    affected_component=workflow.path,
                    impact="A compromised workflow step may modify repository, package, or release state.",
                    remediation="Set least-privilege workflow permissions and isolate release jobs behind explicit environments.",
                    verification="Review effective permissions in CI and execute a pull-request/fork negative control.",
                    standard_references=["SCVS 1.0", "SLSA 1.2", "NIST SSDF 1.1"],
                ))
            if workflow.pull_request_target or workflow.script_injection_candidates:
                evidence = str(_evidence_id(snapshot, workflow.path, "supplychain-pr"))
                candidates.append(ClaimCandidate(
                    service_id=self.service_id,
                    dedupe_key=f"workflow-untrusted-pr:{workflow.path}",
                    statement=f"Workflow {workflow.path} combines an untrusted pull-request path with a security-sensitive execution signal.",
                    evidence_refs=[evidence],
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    affected_component=workflow.path,
                    preconditions=["the workflow executes attacker-controlled pull-request content"],
                    impact="A pull-request contributor may influence a privileged workflow step.",
                    remediation="Separate untrusted validation from privileged workflows and avoid interpolating event data in shell commands.",
                    verification="Run a fork/pull-request fixture and verify secrets and write permissions are unavailable.",
                    standard_references=["SCVS 1.0", "SLSA 1.2"],
                ))
        for path, ref in zip(containers, base_refs, strict=False):
            if "@sha256:" not in ref:
                evidence = str(_evidence_id(snapshot, path, "container-base"))
                candidates.append(ClaimCandidate(
                    service_id=self.service_id,
                    dedupe_key=f"container-base:{path}",
                    statement=f"Container {path} uses a mutable base-image reference {ref}.",
                    evidence_refs=[evidence],
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    affected_component=path,
                    impact="A mutable base reference can resolve to different build inputs over time.",
                    remediation="Pin the base image to a reviewed digest and record provenance for the resulting artifact.",
                    verification="Rebuild from the declared digest and compare the recorded source and artifact subjects.",
                    standard_references=["SCVS 1.0", "SLSA 1.2"],
                ))
        limitations = []
        if not sbom.present:
            limitations.append("SBOM was not found; completeness is not validated")
        elif sbom.completeness != ControlStatus.VERIFIED:
            limitations.append("SBOM component integrity is not fully validated")
        if not provenance.present:
            limitations.append("build provenance was not found; SLSA status is not validated")
        elif provenance.status != ControlStatus.VERIFIED:
            limitations.append("build provenance is present but cryptographic binding is not validated")
        if package_resolution.status == ControlStatus.INCONCLUSIVE:
            limitations.append("dependency lockfiles are present but integrity hashes are not validated")
        return ServiceResult(
            service_id=self.service_id,
            status=ServiceRunStatus.DEGRADED if limitations else ServiceRunStatus.COMPLETED,
            observations=observations,
            claim_candidates=candidates,
            limitations=limitations,
            outputs={"assessment": assessment.model_dump(mode="json")},
        )

    @staticmethod
    def _parse_sbom(snapshot: RepositorySnapshot) -> SbomAssessment:
        for path, content in sorted(snapshot.files.items()):
            name = PurePosixPath(path).name.lower()
            if not (name == "bom.json" or name.endswith(".cdx.json")):
                continue
            try:
                raw = json.loads(content)
            except json.JSONDecodeError:
                return SbomAssessment(present=True, format="CycloneDX", source_ref=path, completeness=ControlStatus.INCONCLUSIVE, unknowns=["SBOM JSON is not parseable"])
            if not isinstance(raw, Mapping):
                return SbomAssessment(present=True, format="unknown", source_ref=path, completeness=ControlStatus.INCONCLUSIVE, unknowns=["SBOM JSON root is not an object"])
            if raw.get("bomFormat") != "CycloneDX":
                return SbomAssessment(present=True, format=str(raw.get("bomFormat", "unknown")), source_ref=path, completeness=ControlStatus.INCONCLUSIVE)
            raw_components = raw.get("components", [])
            if not isinstance(raw_components, list):
                return SbomAssessment(present=True, format="CycloneDX", source_ref=path, completeness=ControlStatus.INCONCLUSIVE, unknowns=["SBOM components are not a list"])
            components = [
                SbomComponent(
                    name=str(item.get("name", "")),
                    version=str(item.get("version", "")),
                    ecosystem=str(item.get("group", "")),
                    purl=item.get("purl"),
                    hashes=[
                        str(value.get("content", ""))
                        for value in item.get("hashes", [])
                        if isinstance(value, Mapping) and str(value.get("content", "")).strip()
                    ],
                )
                for item in raw_components
                if isinstance(item, Mapping)
            ]
            integrity_complete = bool(components) and all(component.hashes for component in components)
            return SbomAssessment(
                present=True,
                format="CycloneDX",
                version=str(raw.get("specVersion", "")),
                source_ref=path,
                components=components,
                completeness=ControlStatus.VERIFIED if integrity_complete else ControlStatus.INCONCLUSIVE,
                unknowns=[] if integrity_complete else ["SBOM components do not all carry content hashes"],
            )
        return SbomAssessment(present=False, completeness=ControlStatus.NOT_ASSESSED)

    @staticmethod
    def _parse_provenance(snapshot: RepositorySnapshot) -> ProvenanceAssessment:
        for path, content in sorted(snapshot.files.items()):
            lower = path.lower()
            if not any(token in lower for token in ("provenance", "attestation", "slsa")):
                continue
            try:
                raw = json.loads(content)
            except json.JSONDecodeError:
                return ProvenanceAssessment(present=True, source_ref=path, status=ControlStatus.INCONCLUSIVE)
            if not isinstance(raw, Mapping):
                return ProvenanceAssessment(present=True, source_ref=path, status=ControlStatus.INCONCLUSIVE)
            raw_subjects = raw.get("subject", [])
            if not isinstance(raw_subjects, list):
                return ProvenanceAssessment(present=True, source_ref=path, status=ControlStatus.INCONCLUSIVE)
            subjects = [str(item.get("name", "")) for item in raw_subjects if isinstance(item, Mapping)]
            subject_digests_valid = bool(raw_subjects) and all(
                isinstance(item, Mapping)
                and bool(str(item.get("name", "")).strip())
                and isinstance(item.get("digest"), Mapping)
                and bool(item.get("digest"))
                and all(str(value).strip() for value in item["digest"].values())
                for item in raw_subjects
            )
            predicate = raw.get("predicate", {}) if isinstance(raw.get("predicate", {}), Mapping) else {}
            builder_identity = str(predicate.get("builder", {}).get("id", "")) if isinstance(predicate.get("builder", {}), Mapping) else ""
            source_revision = str(predicate.get("invocation", {}).get("configSource", {}).get("digest", {}).get("sha1", "")) if isinstance(predicate.get("invocation", {}), Mapping) else ""
            return ProvenanceAssessment(
                present=True,
                source_ref=path,
                builder_identity=builder_identity,
                source_revision=source_revision,
                subjects=subjects,
                attestation_type=str(raw.get("predicateType", "")),
                status=ControlStatus.VERIFIED if subject_digests_valid and raw.get("predicateType") and builder_identity and source_revision else ControlStatus.INCONCLUSIVE,
                contradictions=[] if subject_digests_valid and source_revision else ["provenance subjects or source revision are not cryptographically bound"],
            )
        return ProvenanceAssessment(present=False, status=ControlStatus.NOT_ASSESSED)

    @staticmethod
    def _analyze_workflows(snapshot: RepositorySnapshot) -> list[WorkflowAssessment]:
        results: list[WorkflowAssessment] = []
        for path, content in sorted(snapshot.files.items()):
            if ".github/workflows/" not in f"/{path.lower()}/":
                continue
            action_refs = re.findall(r"uses:\s*([^\s#]+)", content)
            mutable = [ref for ref in action_refs if "@sha256:" not in ref and not re.fullmatch(r"[^@]+@[0-9a-fA-F]{40}", ref)]
            permissions: dict[str, str] = {}
            for match in re.finditer(r"^\s{2,}([A-Za-z0-9_-]+):\s*([A-Za-z]+)\s*$", content, re.MULTILINE):
                key, value = match.groups()
                if key in {"contents", "packages", "id-token", "actions", "deployments"}:
                    permissions[key] = value
            dangerous = [f"{key}:{value}" for key, value in permissions.items() if value.lower() == "write"]
            script_candidates = re.findall(r"\$\{\{\s*github\.event\.[^}]+\}\}", content)
            results.append(WorkflowAssessment(
                path=path,
                action_refs=action_refs,
                mutable_action_refs=mutable,
                permissions=permissions,
                dangerous_permissions=dangerous,
                pull_request_target="pull_request_target:" in content,
                script_injection_candidates=script_candidates,
                release_permissions=[item for item in dangerous if any(x in item for x in ("packages", "contents", "id-token"))],
                status=ControlStatus.FAILED if mutable or dangerous else ControlStatus.VERIFIED,
            ))
        return results

    @staticmethod
    def _analyze_package_resolution(snapshot: RepositorySnapshot) -> PackageResolutionAssessment:
        manifests: list[str] = []
        lockfiles: list[str] = []
        for path in sorted(snapshot.files):
            name = PurePosixPath(path).name.lower()
            if name in {"package.json", "pyproject.toml", "requirements.txt", "go.mod", "cargo.toml", "pom.xml", "gemfile"}:
                manifests.append(path)
            if name in {"package-lock.json", "pnpm-lock.yaml", "yarn.lock", "poetry.lock", "requirements.lock", "go.sum", "cargo.lock", "gemfile.lock"}:
                lockfiles.append(path)
        missing = []
        if any(PurePosixPath(path).name.lower() in {"package.json", "pyproject.toml", "go.mod", "cargo.toml"} for path in manifests) and not lockfiles:
            missing.append("a supported lockfile for one or more direct manifests")
        integrity_hashes_present = any(
            re.search(r'"integrity"\s*:\s*"[^" ]+"|--hash=sha256:[0-9a-fA-F]{64}|sha256:[0-9a-fA-F]{64}', snapshot.files[path])
            for path in lockfiles
        )
        status = ControlStatus.FAILED if missing else (
            ControlStatus.VERIFIED
            if lockfiles and integrity_hashes_present
            else ControlStatus.INCONCLUSIVE
            if lockfiles
            else ControlStatus.NOT_ASSESSED
        )
        return PackageResolutionAssessment(
            manifests=manifests,
            lockfiles=lockfiles,
            missing_lockfiles=missing,
            integrity_hashes_present=integrity_hashes_present if lockfiles else None,
            status=status,
            unknowns=[] if lockfiles and integrity_hashes_present else ["dependency lock integrity was not established"],
        )

    @staticmethod
    def _analyze_containers(snapshot: RepositorySnapshot) -> tuple[list[str], list[str], list[str]]:
        paths: list[str] = []
        refs: list[str] = []
        digest_pinned: list[str] = []
        for path, content in sorted(snapshot.files.items()):
            if PurePosixPath(path).name.lower().startswith("dockerfile"):
                for line in content.splitlines():
                    match = re.match(r"\s*FROM\s+([^\s]+)", line, re.IGNORECASE)
                    if match:
                        paths.append(path)
                        refs.append(match.group(1))
                        if "@sha256:" in match.group(1):
                            digest_pinned.append(match.group(1))
        return paths, refs, digest_pinned


class FirmSecurityServices:
    """Plan, execute, adjudicate, deduplicate, and compose one firm result."""

    def __init__(
        self,
        registry: SecurityServiceRegistry | None = None,
        repository: SecurityServiceRepository | None = None,
        vulnerability_enricher: VulnerabilityFeedEnricher | None = None,
    ) -> None:
        self.registry = registry or default_service_registry()
        self.repository = repository
        self.mapper = AttackSurfaceMapper()
        self.planner = AssessmentPlanner(self.registry)
        self.appsec = ApplicationSecurityService()
        self.agentsec = AgentSecurityService()
        self.vulnintel = VulnerabilityIntelligenceService(vulnerability_enricher)
        self.supplychain = SupplyChainSecurityService()

    def profile_and_plan(self, *, engagement: Any, snapshot: RepositorySnapshot) -> tuple[TargetSecurityProfile, AssessmentPlan]:
        profile = self.mapper.map(snapshot)
        return profile, self.planner.create(engagement=engagement, profile=profile)

    def run(
        self,
        *,
        engagement: Any,
        snapshot: RepositorySnapshot,
        principal_id: str,
        advisories: Sequence[VulnerabilityRecord] = (),
        qualification_context: Mapping[str, Any] | None = None,
    ) -> "FirmAssessment":
        provided_context = dict(qualification_context or {})
        authority_id = str(provided_context.get("authority_id", "")).strip()
        opa_decision_refs = provided_context.get("opa_decision_refs")
        sandbox_execution_refs = provided_context.get("sandbox_execution_refs")
        if not authority_id:
            raise PermissionError("canonical authority decision is required")
        if not isinstance(opa_decision_refs, (list, tuple)) or not opa_decision_refs:
            raise PermissionError("canonical OPA decision reference is required")
        if not isinstance(sandbox_execution_refs, (list, tuple)) or not sandbox_execution_refs:
            raise PermissionError("canonical sandbox execution reference is required")
        opa_decision_refs = [str(ref).strip() for ref in opa_decision_refs]
        sandbox_execution_refs = [str(ref).strip() for ref in sandbox_execution_refs]
        if not all(opa_decision_refs) or not all(sandbox_execution_refs):
            raise PermissionError("canonical execution references must be non-empty")
        profile, plan = self.profile_and_plan(engagement=engagement, snapshot=snapshot)
        results: list[ServiceResult] = []
        for service_id in plan.selected_services:
            if service_id == "APPSEC":
                results.append(self.appsec.assess(snapshot=snapshot, profile=profile))
            elif service_id == "AGENTSEC":
                results.append(self.agentsec.assess(snapshot=snapshot, profile=profile))
            elif service_id == "VULNINTEL":
                results.append(self.vulnintel.assess(snapshot=snapshot, profile=profile, advisories=advisories))
            elif service_id == "SUPPLYCHAIN":
                results.append(self.supplychain.assess(snapshot=snapshot, profile=profile))
        findings, claims, evidence, observations, adjudications = self._adjudicate_with_receipts(
            results=results,
            engagement_id=engagement.engagement_id,
            target_id=TargetId(snapshot.target_id),
            principal_id=principal_id,
        )
        runs: list[ServiceRun] = []
        for result in results:
            contract = self.registry.get(result.service_id)
            run = ServiceRun(
                run_id=f"SR-{_safe_slug(f'{engagement.engagement_id}-{snapshot.snapshot_id}-{result.service_id}')}",
                client_id=engagement.client_id,
                engagement_id=engagement.engagement_id,
                target_id=TargetId(snapshot.target_id),
                snapshot_id=snapshot.snapshot_id,
                service_id=result.service_id,
                service_version=contract.version,
                specialist_id=contract.specialist_owner,
                assessment_plan_id=plan.plan_id,
                capabilities=contract.required_capabilities,
            )
            run.assert_engagement_scope(engagement)
            run.bind_contract(contract)
            run.start()
            run.evidence_ids = sorted({
                EvidenceId(ref)
                for candidate in result.claim_candidates
                for ref in candidate.evidence_refs
            }, key=str)
            run.claim_ids = [claim.claim_id for claim in claims if claim.agent_id == AgentId(result.service_id)]
            final_status = result.status if result.status not in {
                ServiceRunStatus.PLANNED,
                ServiceRunStatus.RUNNING,
            } else ServiceRunStatus.INCONCLUSIVE
            run.finish(final_status)
            run.limitations = list(result.limitations)
            runs.append(run)
        report = self._compose_report(engagement=engagement, profile=profile, plan=plan, results=results, findings=findings, evidence=evidence)
        service_contracts = [self.registry.get(service_id) for service_id in plan.selected_services]
        canonical_context = {
            "aqs_version": "AQS-V1",
            "authority_id": authority_id,
            "authority_level": engagement.authority_level.value,
            "client_id": str(engagement.client_id),
            "engagement_id": str(engagement.engagement_id),
            "target_id": snapshot.target_id,
            "snapshot_id": snapshot.snapshot_id,
            "capability_executions": [
                {
                    "capability_id": capability_id,
                    "service_run_id": run.run_id,
                    "execution_kind": "deterministic_service",
                    "outcome": run.status.value,
                    "opa_decision_ref": opa_decision_refs[0],
                    "sandbox_execution_ref": sandbox_execution_refs[0],
                }
                for run in runs
                for capability_id in run.capabilities
            ],
            "opa_decision_refs": opa_decision_refs,
            "sandbox_execution_refs": sandbox_execution_refs,
            "external_intelligence_provenance": [
                provenance.model_dump(mode="json")
                for advisory in advisories
                for provenance in advisory.provenance
            ],
        }
        assessment = FirmAssessment(
            engagement=engagement,
            profile=profile,
            plan=plan,
            service_contracts=service_contracts,
            service_runs=runs,
            results=results,
            observations=observations,
            claims=claims,
            adjudications=adjudications,
            findings=findings,
            evidence=evidence,
            external_intelligence=list(advisories),
            report=report,
            qualification_context=canonical_context,
        )
        if self.repository is not None:
            assessment_chain = assessment.model_dump(mode="json")
            report_sha256 = hashlib.sha256(
                json.dumps(assessment.report, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            profile_id = self.repository.save_profile(profile=profile, client_id=engagement.client_id)
            self.repository.save_plan(plan=plan, client_id=engagement.client_id, profile_id=profile_id)
            results_by_service = {result.service_id: result for result in results}
            for index, run in enumerate(runs):
                result = results_by_service[run.service_id]
                payload = {
                    "status": result.status.value,
                    "limitations": list(result.limitations),
                    "outputs": result.outputs,
                }
                if index == 0:
                    # Store the complete typed chain once, in canonical JSON,
                    # alongside the deterministic service-run receipt.
                    payload["assessment_chain"] = assessment_chain
                    payload["report_sha256"] = report_sha256
                self.repository.save_run(
                    run=run,
                    payload=payload,
                )
            self.repository.commit()
        return assessment

    def reconstruct_assessment(
        self,
        *,
        client_id: ClientId,
        engagement_id: EngagementId,
    ) -> "FirmAssessment":
        """Rehydrate the complete assessment without process-local state."""
        if self.repository is None:
            raise RuntimeError("assessment reconstruction requires the canonical repository")
        payload = self.repository.get_assessment_chain(client_id=client_id, engagement_id=engagement_id)
        if payload is None:
            raise LookupError(f"no persisted assessment chain for {engagement_id}")
        assessment = FirmAssessment.model_validate(payload)
        from secscan.platform.reports.firm_assessment import FirmAssessmentReport

        rebuilt_report = FirmAssessmentReport.from_canonical(
            engagement=assessment.engagement,
            profile=assessment.profile,
            plan=assessment.plan,
            results=assessment.results,
            findings=assessment.findings,
            evidence_count=len(assessment.evidence),
        )
        stored_report = FirmAssessmentReport.model_validate(assessment.report)
        if rebuilt_report.model_dump(mode="json") != stored_report.model_dump(mode="json"):
            raise RuntimeError("persisted report does not match the canonical assessment chain")
        return assessment.model_copy(update={"report": rebuilt_report.model_dump(mode="json")})

    @staticmethod
    def _adjudicate(
        *,
        results: Sequence[ServiceResult],
        engagement_id: EngagementId,
        target_id: TargetId,
        principal_id: str,
    ) -> tuple[list[Finding], list[Claim], list[EvidenceObject]]:
        findings, claims, evidence, _observations, _adjudications = FirmSecurityServices._adjudicate_with_receipts(
            results=results,
            engagement_id=engagement_id,
            target_id=target_id,
            principal_id=principal_id,
        )
        return findings, claims, evidence

    @staticmethod
    def _adjudicate_with_receipts(
        *,
        results: Sequence[ServiceResult],
        engagement_id: EngagementId,
        target_id: TargetId,
        principal_id: str,
    ) -> tuple[list[Finding], list[Claim], list[EvidenceObject], list[Observation], list[Adjudication]]:
        grouped: dict[str, list[ClaimCandidate]] = {}
        for result in results:
            for candidate in result.claim_candidates:
                grouped.setdefault(candidate.dedupe_key, []).append(candidate)
        adjudicator = AdjudicationService()
        findings: list[Finding] = []
        claims: list[Claim] = []
        evidence: list[EvidenceObject] = []
        observations: list[Observation] = []
        adjudications: list[Adjudication] = []
        for dedupe_key in sorted(grouped):
            candidates = grouped[dedupe_key]
            first = candidates[0]
            evidence_ids = sorted({ref for candidate in candidates for ref in candidate.evidence_refs})
            contradicting_ids = sorted({ref for candidate in candidates for ref in candidate.contradicting_evidence_refs})
            def safe_text(value: object) -> str:
                return scrub_text(str(value))[0]

            for evidence_id in evidence_ids:
                sanitized_payload = json.dumps(
                    {
                        "evidence_id": safe_text(evidence_id),
                        "dedupe_key": safe_text(dedupe_key),
                        "service_id": safe_text(first.service_id),
                        "statement": safe_text(first.statement),
                        "severity": first.severity.value,
                        "confidence": first.confidence.value,
                        "affected_component": safe_text(first.affected_component),
                        "impact": safe_text(first.impact),
                        "remediation": safe_text(first.remediation),
                        "verification": safe_text(first.verification),
                        "standard_references": sorted({
                            safe_text(reference)
                            for candidate in candidates
                            for reference in candidate.standard_references
                        }),
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                sanitized_bytes = sanitized_payload.encode("utf-8")
                content_digest = hashlib.sha256(sanitized_bytes).hexdigest()
                evidence.append(EvidenceObject(
                    evidence_id=EvidenceId(evidence_id),
                    engagement_id=engagement_id,
                    target_id=target_id,
                    collector=first.service_id,
                    tool_version="deterministic-service-0.1.0",
                    capability_id=CapabilityId("CAP-REPO-READONLY-INSPECTION"),
                    invocation_id=ToolInvocationId(f"TI-{_safe_slug(evidence_id)}"),
                    content_type="sanitized-observation",
                    byte_size=len(sanitized_bytes),
                    sha256=content_digest,
                    storage_ref=f"canonical://evidence/{content_digest}",
                    sanitization_state=SanitizationState.SANITIZED,
                    source_identity="immutable-snapshot",
                    sanitized_payload=sanitized_payload,
                ))
            observation = Observation(
                observation_id=ObservationId(f"OB-{_safe_slug(dedupe_key)}"),
                engagement_id=engagement_id,
                evidence_ids=[EvidenceId(value) for value in evidence_ids],
                kind="service-claim-candidate",
                statement=first.statement,
                recorded_by_agent_id=AgentId(first.service_id),
            )
            observations.append(observation)
            claim = Claim(
                claim_id=ClaimId(f"CL-{_safe_slug(dedupe_key)}"),
                engagement_id=engagement_id,
                agent_id=AgentId(first.service_id),
                agent_run_id=AgentRunId(f"AR-{_safe_slug(dedupe_key)}"),
                observation_ids=[observation.observation_id],
                evidence_ids=[EvidenceId(value) for value in evidence_ids],
                statement=first.statement,
                confidence=first.confidence,
                uncertainty="; ".join(sorted({candidate.impact for candidate in candidates if candidate.impact})) or "service-specific context is bounded by the recorded snapshot",
                supporting_note=f"contributing services: {', '.join(sorted({candidate.service_id for candidate in candidates}))}",
            )
            claims.append(claim)
            adjudication, finding = adjudicator.adjudicate(
                engagement_id=engagement_id,
                claim=claim,
                supporting_evidence_ids=evidence_ids,
                contradicting_evidence_ids=contradicting_ids,
                specialist_identity=first.service_id,
                scope_note="deduplicated across service outputs",
                severity=first.severity,
                decided_by_principal_id=PrincipalId(principal_id),
            )
            adjudications.append(adjudication)
            if finding is not None:
                finding = finding.model_copy(update={
                    "finding_id": FindingId(f"FIN-{_safe_slug(dedupe_key)}"),
                    "contributing_services": sorted({candidate.service_id for candidate in candidates}),
                    "dedupe_key": dedupe_key,
                    "affected_component": first.affected_component,
                    "preconditions": sorted({precondition for candidate in candidates for precondition in candidate.preconditions}),
                    "standard_references": sorted({reference for candidate in candidates for reference in candidate.standard_references}),
                    "impact": first.impact,
                    "remediation_guidance": first.remediation,
                    "verification_step": first.verification,
                })
                findings.append(finding)
        return findings, claims, evidence, observations, adjudications

    @staticmethod
    def _compose_report(*, engagement: Any, profile: TargetSecurityProfile, plan: AssessmentPlan, results: Sequence[ServiceResult], findings: Sequence[Finding], evidence: Sequence[EvidenceObject]) -> dict[str, Any]:
        from secscan.platform.reports.firm_assessment import FirmAssessmentReport

        return FirmAssessmentReport.from_canonical(
            engagement=engagement,
            profile=profile,
            plan=plan,
            results=results,
            findings=findings,
            evidence_count=len(evidence),
        ).model_dump(mode="json")


class InspectionFirmRequest(BaseModel):
    """Canonical identifiers for one bounded local inspection execution."""

    model_config = ConfigDict(extra="forbid")

    client_id: str
    engagement_id: str
    target_id: str
    snapshot_id: str
    authority_id: str
    assessment_plan_id: str
    principal_id: str


class InspectionAuthorityDecision(BaseModel):
    """Bound OPA decision returned by the canonical authority adapter."""

    model_config = ConfigDict(extra="forbid")

    decision: str
    authority_id: str
    client_id: str
    engagement_id: str
    target_id: str
    principal_id: str
    action: str
    capability_ids: list[str]
    opa_decision_ref: str
    expires_at: datetime
    revoked: bool = False


class InspectionSandboxDecision(BaseModel):
    """Bound sandbox admission receipt for one canonical inspection."""

    model_config = ConfigDict(extra="forbid")

    decision: str
    client_id: str
    engagement_id: str
    target_id: str
    snapshot_id: str
    capability_ids: list[str]
    sandbox_execution_ref: str
    network_policy: str
    read_only: bool


def _without_runtime_timestamps(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _without_runtime_timestamps(item)
            for key, item in value.items()
            if key not in {"created_at", "updated_at"}
        }
    if isinstance(value, list):
        return [_without_runtime_timestamps(item) for item in value]
    return value


class InspectionFirmRunner:
    """Run the existing service stack from persisted, typed identifiers."""

    def __init__(
        self,
        *,
        services: FirmSecurityServices,
        repository: SecurityServiceRepository,
        load_engagement: Callable[[str], Any | None],
        load_snapshot: Callable[[str, str], RepositorySnapshot | None],
        load_authority: Callable[[str], AuthorityLevel | str | None],
        authorize: Callable[[InspectionFirmRequest, Any, AssessmentPlan], Mapping[str, Any]],
        sandbox_validate: Callable[[InspectionFirmRequest, AssessmentPlan], Mapping[str, Any]],
    ) -> None:
        self.services = services
        self.repository = repository
        self.load_engagement = load_engagement
        self.load_snapshot = load_snapshot
        self.load_authority = load_authority
        self.authorize = authorize
        self.sandbox_validate = sandbox_validate

    def run(
        self,
        request: InspectionFirmRequest,
        *,
        advisories: Sequence[VulnerabilityRecord] = (),
    ) -> "FirmAssessment":
        engagement = self.load_engagement(request.engagement_id)
        if engagement is None:
            raise LookupError(f"unknown engagement {request.engagement_id}")
        if str(engagement.client_id) != request.client_id:
            raise PermissionError("engagement/client scope mismatch")
        if str(engagement.requester_principal_id) != request.principal_id:
            raise PermissionError("principal is not the canonical engagement requester")
        if engagement.status not in {
            EngagementStatus.AUTHORIZED,
            EngagementStatus.ACTIVE,
            EngagementStatus.EVIDENCE_COLLECTION,
            EngagementStatus.ANALYSIS,
            EngagementStatus.ADJUDICATION,
            EngagementStatus.REPORTING,
            EngagementStatus.REMEDIATION,
        }:
            raise PermissionError(f"engagement is not executable in status {engagement.status.value}")
        if request.target_id not in {str(target_id) for target_id in engagement.target_ids}:
            raise PermissionError("target is outside the canonical engagement scope")
        if self.load_authority(request.authority_id) != AuthorityLevel.INSPECTION_ONLY:
            raise PermissionError("authority is not the canonical inspection-only grant")

        profile_payload = self.repository.get_profile_for_engagement(
            client_id=ClientId(request.client_id),
            engagement_id=EngagementId(request.engagement_id),
        )
        plan_payload = self.repository.get_plan(
            client_id=ClientId(request.client_id),
            engagement_id=EngagementId(request.engagement_id),
        )
        if profile_payload is None or plan_payload is None:
            raise LookupError("canonical target profile or assessment plan is missing")
        profile = TargetSecurityProfile.model_validate(profile_payload)
        plan_payload = dict(plan_payload)
        plan_payload.pop("profile_id", None)
        plan = AssessmentPlan.model_validate(plan_payload)
        if profile.target_id != request.target_id or profile.snapshot_id != request.snapshot_id:
            raise PermissionError("profile does not match the requested target snapshot")
        if plan.plan_id != request.assessment_plan_id:
            raise PermissionError("assessment plan identifier does not match canonical state")
        if plan.engagement_id != request.engagement_id or plan.target_id != request.target_id:
            raise PermissionError("assessment plan escapes the canonical engagement target")
        if plan.profile_snapshot_id != request.snapshot_id:
            raise PermissionError("assessment plan snapshot does not match the requested snapshot")
        capability_registry = CapabilityRegistry()
        for capability_id in plan.allowed_capabilities:
            capability_registry.get(capability_id)

        snapshot = self.load_snapshot(request.target_id, request.snapshot_id)
        if snapshot is None:
            raise LookupError("unknown immutable target snapshot")
        if snapshot.target_id != request.target_id or snapshot.snapshot_id != request.snapshot_id:
            raise PermissionError("snapshot loader returned a mismatched target or snapshot")

        if self.authorize is None:
            raise PermissionError("canonical OPA authority decision is required")
        try:
            authority = InspectionAuthorityDecision.model_validate(
                self.authorize(request, engagement, plan)
            )
        except (TypeError, ValueError) as exc:
            raise PermissionError("canonical OPA authority decision is malformed") from exc
        expected_capabilities = sorted(str(value) for value in plan.allowed_capabilities)
        if (
            authority.decision != "ALLOW"
            or authority.authority_id != request.authority_id
            or authority.client_id != request.client_id
            or authority.engagement_id != request.engagement_id
            or authority.target_id != request.target_id
            or authority.principal_id != request.principal_id
            or authority.action != "inspect"
            or sorted(authority.capability_ids) != expected_capabilities
            or not authority.opa_decision_ref.strip()
            or authority.revoked
            or authority.expires_at.tzinfo is None
            or authority.expires_at <= datetime.now(UTC)
        ):
            raise PermissionError("canonical OPA authority decision does not bind this inspection")

        if self.sandbox_validate is None:
            raise PermissionError("canonical sandbox admission is required")
        try:
            sandbox = InspectionSandboxDecision.model_validate(
                self.sandbox_validate(request, plan)
            )
        except (TypeError, ValueError) as exc:
            raise PermissionError("canonical sandbox admission is malformed") from exc
        if (
            sandbox.decision != "ALLOW"
            or sandbox.client_id != request.client_id
            or sandbox.engagement_id != request.engagement_id
            or sandbox.target_id != request.target_id
            or sandbox.snapshot_id != request.snapshot_id
            or sorted(sandbox.capability_ids) != expected_capabilities
            or not sandbox.sandbox_execution_ref.strip()
            or sandbox.network_policy != "NONE"
            or not sandbox.read_only
        ):
            raise PermissionError("canonical sandbox admission does not bind this inspection")

        expected_profile, expected_plan = self.services.profile_and_plan(engagement=engagement, snapshot=snapshot)
        if _without_runtime_timestamps(expected_profile.model_dump(mode="json")) != _without_runtime_timestamps(
            profile.model_dump(mode="json")
        ):
            raise PermissionError("persisted profile does not match the immutable snapshot")
        if _without_runtime_timestamps(expected_plan.model_dump(mode="json")) != _without_runtime_timestamps(
            plan.model_dump(mode="json")
        ):
            raise PermissionError("persisted plan does not match the immutable snapshot")
        plan.validate_plan(self.services.registry, engagement)
        return self.services.run(
            engagement=engagement,
            snapshot=snapshot,
            principal_id=request.principal_id,
            advisories=advisories,
            qualification_context={
                "authority_id": request.authority_id,
                "opa_decision_refs": [authority.opa_decision_ref],
                "sandbox_execution_refs": [sandbox.sandbox_execution_ref],
            },
        )


class FirmAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    engagement: Engagement
    profile: TargetSecurityProfile
    plan: AssessmentPlan
    service_contracts: list[SecurityServiceContract]
    service_runs: list[ServiceRun]
    results: list[ServiceResult]
    observations: list[Observation]
    claims: list[Claim]
    adjudications: list[Adjudication]
    findings: list[Finding]
    evidence: list[EvidenceObject]
    external_intelligence: list[VulnerabilityRecord] = Field(default_factory=list)
    report: dict[str, Any]
    qualification_context: dict[str, Any] = Field(default_factory=dict)


def _list_values(content: str, keys: Iterable[str]) -> list[str]:
    values: list[str] = []
    key_pattern = "|".join(re.escape(key) for key in keys)
    for match in re.finditer(rf"(?:{key_pattern})\s*[:=]\s*([^\n]+)", content, re.IGNORECASE):
        raw = match.group(1).strip().strip("[]{}()\"'")
        for value in re.split(r"[,\s]+", raw):
            value = value.strip("\"'[]{}(),")
            if value and value.lower() not in {"true", "false", "null"} and value not in values:
                values.append(value)
    return values[:32]


def _first_marker(content: str, markers: Iterable[str]) -> str:
    lower = content.lower()
    return next((marker for marker in markers if marker.lower() in lower), "")


def _dependency_inventory(snapshot: RepositorySnapshot) -> list[dict[str, str]]:
    dependencies: list[dict[str, str]] = []
    for path, content in sorted(snapshot.files.items()):
        name = PurePosixPath(path).name.lower()
        if name == "package.json":
            try:
                raw = json.loads(content)
            except json.JSONDecodeError:
                continue
            for section in ("dependencies", "devDependencies"):
                for package_name, version in raw.get(section, {}).items():
                    dependencies.append({"name": str(package_name), "version": str(version).lstrip("^~>=< "), "ecosystem": "npm", "path": path})
        elif name == "pyproject.toml":
            try:
                raw = tomllib.loads(content)
            except tomllib.TOMLDecodeError:
                continue
            project = raw.get("project", {})
            for requirement in project.get("dependencies", []):
                match = re.match(r"\s*([A-Za-z0-9_.-]+)\s*(?:==\s*([0-9][^; ]*))?", str(requirement))
                if match:
                    dependencies.append({"name": match.group(1), "version": match.group(2) or "unknown", "ecosystem": "PyPI", "path": path})
    return dependencies


def _first_fixed_version(raw: Mapping[str, Any]) -> str | None:
    for affected in raw.get("affected", []) if isinstance(raw.get("affected", []), list) else []:
        for range_item in affected.get("ranges", []) if isinstance(affected, Mapping) else []:
            for event in range_item.get("events", []) if isinstance(range_item, Mapping) else []:
                if isinstance(event, Mapping) and event.get("fixed"):
                    return str(event["fixed"])
    return None


def _float_or_none(value: Any) -> float | None:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    return parsed if 0.0 <= parsed <= 1.0 else None


__all__ = [
    "AgentSecurityService",
    "ApplicationSecurityService",
    "AssessmentPlanner",
    "AttackSurfaceMapper",
    "ClaimCandidate",
    "CisaKevFeedAdapter",
    "FirmAssessment",
    "FirmSecurityServices",
    "FirstEpssFeedAdapter",
    "InspectionAuthorityDecision",
    "InspectionFirmRequest",
    "InspectionFirmRunner",
    "InspectionSandboxDecision",
    "OsVFeedAdapter",
    "OsVFeedUnavailable",
    "RepositorySnapshot",
    "ServiceObservation",
    "ServiceResult",
    "SupplyChainSecurityService",
    "TargetProfiler",
    "VulnerabilityFeedEnricher",
    "VulnerabilityFeedMalformed",
    "VulnerabilityFeedUnavailable",
    "VulnerabilityIntelligenceService",
]
