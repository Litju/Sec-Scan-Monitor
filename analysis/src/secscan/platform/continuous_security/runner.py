"""Signed, bounded reference edge runner built on the existing sandbox port."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime
from typing import Mapping, Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from secscan.platform.continuous_security.events import EventClass, SecurityEventPlane
from secscan.platform.domain.authority import PolicyDecision
from secscan.platform.domain.capability import CapabilityManifest
from secscan.platform.domain.ports import EvidenceStore
from secscan.platform.sandbox import SandboxExecutionService
from secscan.sanitize.filters import scrub_text, stable_json


class _FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class CanonicalJob(_FrozenModel):
    """Only canonical IDs and an opaque signature cross the runner seam."""

    job_id: str
    tenant_id: str
    case_id: str
    target_id: str
    snapshot_id: str
    capability_id: str
    authority_decision: PolicyDecision
    input_digest: str
    tool_identity: str
    timeout_seconds: int
    network_policy: str
    resource_policy: dict[str, str]
    signing_key_id: str
    signed_at: datetime
    signature: str

    @field_validator(
        "job_id",
        "tenant_id",
        "case_id",
        "target_id",
        "snapshot_id",
        "capability_id",
        "input_digest",
        "tool_identity",
        "network_policy",
        "signing_key_id",
        "signature",
    )
    @classmethod
    def _non_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("canonical job identity fields must be non-empty")
        return value

    @field_validator("timeout_seconds")
    @classmethod
    def _positive_timeout(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("job timeout must be positive")
        return value

    @field_validator("signed_at")
    @classmethod
    def _timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("signed_at must be timezone-aware")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def _canonical_authority(self) -> CanonicalJob:
        if self.authority_decision != PolicyDecision.ALLOW:
            raise ValueError("runner accepts only an explicit ALLOW authority decision")
        if self.network_policy != "none":
            raise ValueError("runner network policy must be deny-by-default (none)")
        return self

    def unsigned_bytes(self) -> bytes:
        payload = self.model_dump(mode="json", exclude={"signature"})
        return stable_json(payload).encode("utf-8")

    @property
    def job_digest(self) -> str:
        return hashlib.sha256(self.unsigned_bytes()).hexdigest()


class JobSignatureVerifier(Protocol):
    def verify(self, message: bytes, *, signature: str, key_id: str) -> bool: ...


class Ed25519JobSignatureVerifier:
    """Vetted-library verifier; private signing material never enters the runner."""

    def __init__(self, public_keys: Mapping[str, bytes]) -> None:
        self._public_keys = dict(public_keys)

    def verify(self, message: bytes, *, signature: str, key_id: str) -> bool:
        key_bytes = self._public_keys.get(key_id)
        if key_bytes is None:
            return False
        try:
            public_key = Ed25519PublicKey.from_public_bytes(key_bytes)
            public_key.verify(base64.b64decode(signature, validate=True), message)
        except Exception:
            return False
        return True


class WorkloadIdentity(_FrozenModel):
    workload_id: str
    tenant_id: str
    case_id: str


class WorkloadIdentityPort(Protocol):
    """Future SPIFFE/SPIRE seam; this reference implementation uses a local adapter."""

    def resolve(self, job: CanonicalJob) -> WorkloadIdentity: ...


class StaticWorkloadIdentityAdapter:
    def __init__(self, identity: WorkloadIdentity) -> None:
        self._identity = identity

    def resolve(self, _job: CanonicalJob) -> WorkloadIdentity:
        return self._identity


class RunnerCapability(_FrozenModel):
    capability_id: str
    manifest: CapabilityManifest
    command: tuple[str, ...]
    workload_id: str
    target_id: str
    resource_policy: dict[str, str]

    @model_validator(mode="after")
    def _internal_contract(self) -> RunnerCapability:
        if not self.command or any(not part for part in self.command):
            raise ValueError("runner capability command must be a non-empty registered tuple")
        if str(self.manifest.capability_id) != self.capability_id:
            raise ValueError("runner capability id must match its manifest")
        if not self.manifest.command_allowlist or self.command[0] not in self.manifest.command_allowlist:
            raise ValueError("registered runner command must be allowed by the capability manifest")
        return self


class ResultReceipt(_FrozenModel):
    job_id: str
    tenant_id: str
    case_id: str
    target_id: str
    snapshot_id: str
    capability_id: str
    status: str
    job_digest: str
    evidence_ref: str | None
    output_digest: str | None
    timed_out: bool
    network_policy: str
    cleanup_confirmed: bool
    telemetry: dict[str, str] = Field(default_factory=dict)


class RunnerRefusalError(RuntimeError):
    """A canonical job failed closed before or during bounded execution."""


class EdgeRunnerPort(Protocol):
    def submit(self, job: CanonicalJob) -> ResultReceipt: ...


class ReferenceEdgeRunner:
    """One local reference runner with no listener, polling, or arbitrary command input."""

    def __init__(
        self,
        *,
        execution: SandboxExecutionService,
        evidence_store: EvidenceStore,
        signature_verifier: JobSignatureVerifier,
        workload_identity: WorkloadIdentityPort,
        capabilities: Mapping[str, RunnerCapability],
        events: SecurityEventPlane | None = None,
    ) -> None:
        self._execution = execution
        self._evidence = evidence_store
        self._signatures = signature_verifier
        self._identity = workload_identity
        self._capabilities = dict(capabilities)
        self._events = events
        self._receipts: dict[tuple[str, str, str], ResultReceipt] = {}

    def submit(self, job: CanonicalJob) -> ResultReceipt:
        receipt_key = (job.tenant_id, job.case_id, job.job_id)
        # ``model_copy(update=...)`` does not re-run Pydantic validators; keep
        # the security invariants at the execution seam as well.
        if job.authority_decision != PolicyDecision.ALLOW:
            raise RunnerRefusalError("runner accepts only an explicit ALLOW authority decision")
        if job.network_policy != "none":
            raise RunnerRefusalError("runner network policy must be deny-by-default (none)")
        if not self._signatures.verify(job.unsigned_bytes(), signature=job.signature, key_id=job.signing_key_id):
            raise RunnerRefusalError("unsigned or unverifiable job refused")
        previous = self._receipts.get(receipt_key)
        if previous is not None:
            if previous.job_digest != job.job_digest:
                raise RunnerRefusalError("job identity was reused for different signed content")
            return previous
        capability = self._capabilities.get(job.capability_id)
        if capability is None:
            raise RunnerRefusalError("unknown capability refused")
        if job.tool_identity != capability.manifest.tool_identity:
            raise RunnerRefusalError("tool identity substitution refused")
        if job.target_id != capability.target_id:
            raise RunnerRefusalError("target binding mismatch")
        if job.timeout_seconds > capability.manifest.timeout_seconds:
            raise RunnerRefusalError("job timeout exceeds the registered capability bound")
        if job.resource_policy != capability.resource_policy:
            raise RunnerRefusalError("caller-supplied resource policy differs from the registered policy")
        identity = self._identity.resolve(job)
        if (
            identity.workload_id != capability.workload_id
            or identity.tenant_id != job.tenant_id
            or identity.case_id != job.case_id
        ):
            raise RunnerRefusalError("workload identity or scope mismatch")

        try:
            result = self._execution.execute(
                capability=capability.manifest,
                command=list(capability.command),
                timeout_seconds=job.timeout_seconds,
                environment={"SECSCAN_RUNNER": "1"},
            )
        except Exception as exc:
            raise RunnerRefusalError(f"bounded execution refused: {type(exc).__name__}") from exc

        safe_output = self._sanitize_output(result.stdout, result.stderr)
        output_bytes = safe_output.encode("utf-8")
        output_digest = hashlib.sha256(output_bytes).hexdigest()
        evidence_ref = self._evidence.put(output_bytes, content_type="edge-runner-result")
        status = "timed_out" if result.timed_out else ("completed" if result.exit_code == 0 else "failed")
        receipt = ResultReceipt(
            job_id=job.job_id,
            tenant_id=job.tenant_id,
            case_id=job.case_id,
            target_id=job.target_id,
            snapshot_id=job.snapshot_id,
            capability_id=job.capability_id,
            status=status,
            job_digest=job.job_digest,
            evidence_ref=evidence_ref,
            output_digest=output_digest,
            timed_out=result.timed_out,
            network_policy=job.network_policy,
            cleanup_confirmed=True,
            telemetry={
                "sandbox_id": result.sandbox_id,
                "profile": result.profile_name,
                "exit_code": str(result.exit_code),
            },
        )
        self._receipts[receipt_key] = receipt
        if self._events is not None:
            self._events.ingest_raw(
                {
                    "source": "secscan-edge-runner",
                    "source_record_id": job.job_id,
                    "source_digest": output_digest,
                    "source_system": "secscan-edge-runner",
                    "collector_version": "edge-runner-v1",
                    "source_type": "runner",
                    "event_class": EventClass.SCANNER_ACTIVITY.value,
                    "occurred_at": job.signed_at,
                    "observed_at": job.signed_at,
                    "tenant": job.tenant_id,
                    "case": job.case_id,
                    "target": job.target_id,
                    "actor": identity.workload_id,
                    "object": job.tool_identity,
                    "action": "execute",
                    "outcome": status,
                    "raw_evidence_ref": evidence_ref,
                    "normalization_version": "security-events-v1",
                    "attributes": {"job_digest": job.job_digest, "network_policy": job.network_policy},
                }
            )
        return receipt

    @staticmethod
    def _sanitize_output(stdout: str, stderr: str) -> str:
        safe_stdout, _stdout_notes = scrub_text(stdout)
        safe_stderr, _stderr_notes = scrub_text(stderr)
        return json.dumps({"stdout": safe_stdout, "stderr": safe_stderr}, ensure_ascii=False, sort_keys=True)
