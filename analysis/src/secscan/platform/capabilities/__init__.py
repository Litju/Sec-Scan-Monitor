"""Capability registry (ADR-0007).

Agents request registered capabilities; they never execute arbitrary
binaries. Safe foundation capabilities and explicitly approval-gated response
control capabilities are registered separately.
Future aggressive engines (Semgrep, OSV-Scanner, Gitleaks, Trivy, PyRIT,
garak, PentAGI, Caldera/OpenAEV, OpenCTI, Velociraptor, Volatility, Falco,
Tetragon) become adapters that fit this registry without core changes.
"""

from __future__ import annotations

from secscan.platform.domain.authority import Action
from secscan.platform.domain.capability import (
    CapabilityManifest,
    NetworkPolicy,
    RiskClass,
    SandboxRequirement,
)
from secscan.platform.domain.ids import CapabilityId

FOUNDATION_CAPABILITIES: list[CapabilityManifest] = [
    CapabilityManifest(
        capability_id=CapabilityId("CAP-REPO-INVENTORY"),
        version="1.0.0",
        description="Enumerate repository structure: files, sizes, type counts. Read-only metadata.",
        risk_class=RiskClass.INFO,
        accepted_inputs=["repo_path"],
        produced_outputs=["file_inventory"],
        required_authority=Action.INSPECT.value,
        requires_approval=False,
        sandbox_profile="default",
        sandbox_requirement=SandboxRequirement.NONE,
        network_policy=NetworkPolicy.NONE,
        timeout_seconds=60,
        resource_limits={"cpu": "1", "memory": "256m", "pids": "64"},
        tool_identity="secscan-internal",
        tool_version="1.0.0",
        evidence_type="repository-inventory",
        command_allowlist=["python", "dir"],
    ),
    CapabilityManifest(
        capability_id=CapabilityId("CAP-REPO-READONLY-INSPECTION"),
        version="1.0.0",
        description="Read files and metadata inside the declared target scope. The inspector never executes target code and reads an immutable snapshot through a bounded host-side reader.",
        risk_class=RiskClass.LOW,
        accepted_inputs=["file_paths", "patterns"],
        produced_outputs=["file_contents", "file_metadata"],
        required_authority=Action.INSPECT.value,
        requires_approval=False,
        sandbox_profile="default",
        sandbox_requirement=SandboxRequirement.NONE,
        network_policy=NetworkPolicy.NONE,
        timeout_seconds=120,
        resource_limits={"cpu": "1", "memory": "256m", "pids": "64"},
        tool_identity="secscan-internal",
        tool_version="1.0.0",
        evidence_type="file-read",
        command_allowlist=["python", "cat"],
    ),
    CapabilityManifest(
        capability_id=CapabilityId("CAP-FIRM-REPORT-RENDER"),
        version="1.0.0",
        description="Render a sanitized firm report from adjudicated findings via the case engine.",
        risk_class=RiskClass.INFO,
        accepted_inputs=["engagement_id"],
        produced_outputs=["firm_report"],
        required_authority=Action.INSPECT.value,
        requires_approval=False,
        sandbox_profile="default",
        sandbox_requirement=SandboxRequirement.NONE,
        network_policy=NetworkPolicy.NONE,
        timeout_seconds=60,
        resource_limits={"cpu": "1", "memory": "256m", "pids": "64"},
        tool_identity="secscan-internal",
        tool_version="1.0.0",
        evidence_type="report",
        command_allowlist=["python"],
    ),
    CapabilityManifest(
        capability_id=CapabilityId("CAP-EVIDENCE-NORMALIZE"),
        version="1.0.0",
        description="Normalize captured raw output into typed observations with provenance.",
        risk_class=RiskClass.INFO,
        accepted_inputs=["evidence_ids"],
        produced_outputs=["observations"],
        required_authority=Action.COLLECT.value,
        requires_approval=False,
        sandbox_profile="default",
        sandbox_requirement=SandboxRequirement.NONE,
        network_policy=NetworkPolicy.NONE,
        timeout_seconds=60,
        resource_limits={"cpu": "1", "memory": "256m", "pids": "64"},
        tool_identity="secscan-internal",
        tool_version="1.0.0",
        evidence_type="observation",
        command_allowlist=["python"],
    ),
]

RESPONSE_CONTROL_CAPABILITIES: list[CapabilityManifest] = [
    CapabilityManifest(
        capability_id=CapabilityId("CAP-V03-RESPONSE-PROPOSAL"),
        version="1.0.0",
        description="Create an evidence-bound response proposal for human review; never executes an action.",
        risk_class=RiskClass.HIGH,
        accepted_inputs=["confirmed_incident", "evidence_refs"],
        produced_outputs=["response_proposal", "human_approval_request"],
        required_authority=Action.REMEDIATE.value,
        requires_approval=True,
        sandbox_profile="none",
        sandbox_requirement=SandboxRequirement.NONE,
        network_policy=NetworkPolicy.NONE,
        timeout_seconds=60,
        resource_limits={"cpu": "1", "memory": "256m", "pids": "32"},
        tool_identity="secscan-v03-response-control-plane",
        tool_version="1.0.0",
        evidence_type="response-proposal",
        failure_semantics="OPA denial or missing human approval never executes an action",
        command_allowlist=[],
    ),
]


# F-200 adapters are registered separately from the low-risk foundation set.
# Their tool images are pinned by digest and all four require the sandbox.
F200_SCANNER_CAPABILITIES: list[CapabilityManifest] = [
    CapabilityManifest(
        capability_id=CapabilityId("CAP-SAST-SEMGREP"),
        version="1.0.0",
        description="Offline Semgrep Community static analysis against an immutable source snapshot.",
        risk_class=RiskClass.MEDIUM,
        accepted_inputs=["immutable_source_snapshot"],
        produced_outputs=["semgrep_json"],
        required_authority=Action.INSPECT.value,
        sandbox_profile="scanner-default",
        sandbox_requirement=SandboxRequirement.REQUIRED,
        network_policy=NetworkPolicy.NONE,
        timeout_seconds=300,
        resource_limits={"cpu": "1", "memory": "512m", "pids": "64"},
        tool_identity="semgrep/semgrep",
        tool_version="1.173.0",
        tool_license="LGPL-2.1",
        source_url="https://github.com/semgrep/semgrep",
        release_url="https://github.com/semgrep/semgrep/releases/tag/v1.173.0",
        artifact_ref="docker.io/semgrep/semgrep@sha256:44dd022c29d4f881a939f7281b4ba8855cb940a2dd272883908d8947325a4ba7",
        artifact_digest="sha256:44dd022c29d4f881a939f7281b4ba8855cb940a2dd272883908d8947325a4ba7",
        evidence_type="semgrep-json",
        normalizer="secscan.platform.capabilities.scanner_adapters._safe_payload",
        failure_semantics="non-zero is preserved as evidence; findings do not become findings without adjudication",
        command_allowlist=["semgrep"],
    ),
    CapabilityManifest(
        capability_id=CapabilityId("CAP-SCA-OSV"),
        version="1.0.0",
        description="Offline OSV-Scanner dependency inspection against an immutable source snapshot.",
        risk_class=RiskClass.MEDIUM,
        accepted_inputs=["immutable_source_snapshot"],
        produced_outputs=["osv_json"],
        required_authority=Action.INSPECT.value,
        sandbox_profile="scanner-default",
        sandbox_requirement=SandboxRequirement.REQUIRED,
        network_policy=NetworkPolicy.NONE,
        timeout_seconds=300,
        resource_limits={"cpu": "1", "memory": "512m", "pids": "64"},
        tool_identity="ghcr.io/google/osv-scanner",
        tool_version="2.5.0",
        tool_license="Apache-2.0",
        source_url="https://github.com/google/osv-scanner",
        release_url="https://github.com/google/osv-scanner/releases/tag/v2.5.0",
        artifact_ref="ghcr.io/google/osv-scanner@sha256:ed5c1cda47b439a9bf0b010d2f0920b70d6cf2e003fe1774c0e4c405e5747213",
        artifact_digest="sha256:ed5c1cda47b439a9bf0b010d2f0920b70d6cf2e003fe1774c0e4c405e5747213",
        evidence_type="osv-json",
        normalizer="secscan.platform.capabilities.scanner_adapters._safe_payload",
        failure_semantics="offline database absence is NOT_QUALIFIED; no network fallback is permitted",
        command_allowlist=["scan", "osv-scanner"],
    ),
    CapabilityManifest(
        capability_id=CapabilityId("CAP-SECRETS-GITLEAKS"),
        version="1.0.0",
        description="Redacted Gitleaks secret detection against an immutable source snapshot.",
        risk_class=RiskClass.MEDIUM,
        accepted_inputs=["immutable_source_snapshot"],
        produced_outputs=["gitleaks_json_redacted"],
        required_authority=Action.INSPECT.value,
        sandbox_profile="scanner-default",
        sandbox_requirement=SandboxRequirement.REQUIRED,
        network_policy=NetworkPolicy.NONE,
        timeout_seconds=300,
        resource_limits={"cpu": "1", "memory": "512m", "pids": "64"},
        tool_identity="zricethezav/gitleaks",
        tool_version="8.30.1",
        tool_license="MIT",
        source_url="https://github.com/gitleaks/gitleaks",
        release_url="https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1",
        artifact_ref="docker.io/zricethezav/gitleaks@sha256:b109bc5f8f76a38196a3e413704fc5b9e3c32360bce4e4b603bd6f45b3721dbb",
        artifact_digest="sha256:b109bc5f8f76a38196a3e413704fc5b9e3c32360bce4e4b603bd6f45b3721dbb",
        evidence_type="gitleaks-json-redacted",
        normalizer="secscan.platform.capabilities.scanner_adapters._safe_payload",
        failure_semantics="exit 1 with redacted detections is successful evidence collection; values are never persisted",
        command_allowlist=["detect", "gitleaks"],
    ),
    CapabilityManifest(
        capability_id=CapabilityId("CAP-REPO-TRIVY"),
        version="1.0.0",
        description="Offline Trivy filesystem vulnerability, misconfiguration, and secret inspection.",
        risk_class=RiskClass.MEDIUM,
        accepted_inputs=["immutable_source_snapshot"],
        produced_outputs=["trivy_json"],
        required_authority=Action.INSPECT.value,
        sandbox_profile="scanner-default",
        sandbox_requirement=SandboxRequirement.REQUIRED,
        network_policy=NetworkPolicy.NONE,
        timeout_seconds=300,
        resource_limits={"cpu": "1", "memory": "1g", "pids": "64"},
        tool_identity="aquasec/trivy",
        tool_version="0.74.0",
        tool_license="Apache-2.0",
        source_url="https://github.com/aquasecurity/trivy",
        release_url="https://github.com/aquasecurity/trivy/releases/tag/v0.74.0",
        artifact_ref="docker.io/aquasec/trivy@sha256:ee940acbf1f58ebadb42d01434ce4609530bf1b52536afbd1eee66cd7123c5c9",
        artifact_digest="sha256:ee940acbf1f58ebadb42d01434ce4609530bf1b52536afbd1eee66cd7123c5c9",
        evidence_type="trivy-json",
        normalizer="secscan.platform.capabilities.scanner_adapters._safe_payload",
        failure_semantics="missing offline advisory DB is NOT_QUALIFIED; skip-db-update never authorizes network fallback",
        command_allowlist=["fs", "trivy"],
    ),
]


class UnknownCapabilityError(KeyError):
    """Raised when a capability id is not registered."""


class CapabilityRegistry:
    """Version-aware registry of CapabilityManifests."""

    def __init__(self, manifests: list[CapabilityManifest] | None = None) -> None:
        self._manifests: dict[tuple[CapabilityId, str], CapabilityManifest] = {}
        for manifest in manifests or [
            *FOUNDATION_CAPABILITIES,
            *RESPONSE_CONTROL_CAPABILITIES,
            *F200_SCANNER_CAPABILITIES,
        ]:
            self.register(manifest)

    def register(self, manifest: CapabilityManifest) -> None:
        key = (manifest.capability_id, manifest.version)
        if key in self._manifests:
            raise ValueError(f"capability {manifest.capability_id}@{manifest.version} already registered")
        self._manifests[key] = manifest

    def get(self, capability_id: CapabilityId | str, version: str | None = None) -> CapabilityManifest:
        capability = CapabilityId(capability_id)
        if version is not None:
            key = (capability, version)
            if key not in self._manifests:
                raise UnknownCapabilityError(f"capability {capability}@{version} is not registered")
            return self._manifests[key]
        versions = [m for (c, _), m in self._manifests.items() if c == capability]
        if not versions:
            raise UnknownCapabilityError(f"capability {capability} is not registered")
        return sorted(versions, key=lambda m: _version_key(m.version))[-1]

    def list(self) -> list[CapabilityManifest]:
        return sorted(self._manifests.values(), key=lambda m: (str(m.capability_id), _version_key(m.version)))


def _version_key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split(".") if part.isdigit())
