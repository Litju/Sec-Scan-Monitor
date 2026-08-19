"""Evidence application service: ingestion with no-secrets enforcement.

Captured raw content becomes an EvidenceObject with full provenance and is
stored content-addressed. Secret-bearing content is NEVER persisted in full:
the service records safe metadata only and stores the redacted remainder.
"""

from __future__ import annotations

import re

from secscan.platform.domain.audit import AuditEvent, AuditEventKind
from secscan.platform.domain.evidence import (
    EvidenceObject,
    SanitizationState,
    SecretClass,
    SecretObservation,
)
from secscan.platform.domain.ids import (
    AuditEventId,
    CapabilityId,
    EngagementId,
    EvidenceId,
    PrincipalId,
    TargetId,
    ToolInvocationId,
    new_id,
)
from secscan.platform.domain.ports import AuditSink, EvidenceStore
from secscan.sanitize.filters import payload_contains_secret_like_content, scrub_text

# Secret-like patterns for adversarial detection in ingested content. These
# mirror .secscan/drift-rules.yaml forbidden_patterns but use lower bounds so
# truncated/partial matches are also caught and fully redacted. The set
# covers the full private-key BLOCK (header through footer), AWS access
# keys, JWTs, Slack tokens, and generic credential assignments.
_SECRET_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----.*?-----END [A-Z ]+PRIVATE KEY-----", re.DOTALL),
    re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    re.compile(r"\bxox[bap]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"AIza[0-9A-Za-z_-]{20,}"),
    re.compile(r"(?i)github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"(?i)bitlocker[^\n]*recovery[^\n]{0,80}"),
    re.compile(r"(?i)\bsk-[A-Za-z0-9]{20,}"),
    re.compile(r"(?i)\bghp_[A-Za-z0-9]{20,}"),
    re.compile(r"(?i)\b[a-z0-9_]*(password|passwd|pwd|api[_-]?key|apikey|secret|token)\s*[:=]\s*[\"']?[A-Za-z0-9+/._-]{12,}[\"']?"),
]

_SECRET_CLASS_HINTS = [
    (re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----"), SecretClass.PRIVATE_KEY),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), SecretClass.API_KEY),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\."), SecretClass.TOKEN),
    (re.compile(r"\bxox[bap]-"), SecretClass.TOKEN),
    (re.compile(r"AIza[0-9A-Za-z_-]{20,}"), SecretClass.API_KEY),
    (re.compile(r"(?i)github_pat_"), SecretClass.TOKEN),
    (re.compile(r"(?i)bitlocker[^\n]*recovery"), SecretClass.PASSWORD),
    (re.compile(r"(?i)\bsk-"), SecretClass.API_KEY),
    (re.compile(r"(?i)\bghp_"), SecretClass.TOKEN),
    (re.compile(r"(?i)\b[a-z0-9_]*(password|passwd|pwd)\s*[:=]"), SecretClass.PASSWORD),
    (re.compile(r"(?i)\b[a-z0-9_]*(api[_-]?key|apikey|secret|token)\s*[:=]"), SecretClass.API_KEY),
]

# Aggressive REDACTION-only patterns, applied exclusively in the redaction
# pass (which runs only after detection already fired). These catch what the
# conservative detection set deliberately misses: private-key block bodies,
# the END footer line, and long base64 body lines.
_REDACTION_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----.*?-----END [A-Z ]+PRIVATE KEY-----", re.DOTALL),
    re.compile(r"-----END [A-Z ]+PRIVATE KEY-----"),
    re.compile(r"^[A-Za-z0-9+/=]{40,}$", re.MULTILINE),
]


class EvidenceService:
    """Ingests raw evidence; guarantees no-secret persistence."""

    def __init__(self, store: EvidenceStore, audit: AuditSink) -> None:
        self._store = store
        self._audit = audit

    def ingest(
        self,
        *,
        engagement_id: EngagementId,
        target_id: TargetId,
        principal_id: PrincipalId,
        collector: str,
        tool_version: str,
        capability_id: CapabilityId,
        invocation_id: ToolInvocationId,
        content: bytes,
        content_type: str,
        sandbox_id: str | None = None,
        source_identity: str = "",
    ) -> EvidenceObject:
        """Store content; if it contains secret-like material, store the
        REDACTED remainder and safe metadata only (never the plaintext)."""
        text = content.decode("utf-8", errors="replace")
        evidence_id = EvidenceId(new_id("EV"))
        secret_observations = _detect_secrets(text, evidence_id=evidence_id)
        contains_secret_like = bool(secret_observations) or payload_contains_secret_like_content(text)

        if contains_secret_like:
            scrubbed, _notes = scrub_text(text)
            # Defense in depth: the case-engine scrubber's pattern set is
            # narrower than the platform detector's. Apply a platform-level
            # full-value redaction over anything still matching, so the
            # stored remainder can never retain a plaintext secret.
            stored_content = _redact_secret_values(scrubbed).encode("utf-8")
            sanitization_state = SanitizationState.REDACTED
        else:
            stored_content = content
            sanitization_state = SanitizationState.SANITIZED if _looks_textual(content_type) else SanitizationState.UNSANITIZED

        storage_ref = self._store.put(stored_content, content_type=content_type)

        evidence = EvidenceObject(
            evidence_id=evidence_id,
            engagement_id=engagement_id,
            target_id=target_id,
            collector=collector,
            tool_version=tool_version,
            capability_id=capability_id,
            invocation_id=invocation_id,
            sandbox_id=sandbox_id,
            content_type=content_type,
            byte_size=len(stored_content),
            sha256=storage_ref,
            storage_ref=storage_ref,
            sanitization_state=sanitization_state,
            source_identity=source_identity,
            secret_observations=secret_observations,
        )
        self._audit.append(
            AuditEvent(
                audit_event_id=AuditEventId(new_id("AE")),
                engagement_id=engagement_id,
                principal_id=principal_id,
                kind=AuditEventKind.EVIDENCE_INGESTION,
                summary=f"evidence {evidence.evidence_id} ingested ({sanitization_state.value})",
                details={
                    "sha256": storage_ref,
                    "byte_size": str(evidence.byte_size),
                    "collector": collector,
                    "tool_version": tool_version,
                    "sanitization_state": sanitization_state.value,
                    "secret_observations": str(len(secret_observations)),
                },
            )
        )
        # Observability: the ONLY span-attribute write site in the
        # ingestion path goes through the policy (safe keys + secret
        # rejection). Raw content never reaches a span.
        _trace_evidence_ingestion(
            engagement_id=engagement_id,
            target_id=target_id,
            capability_id=capability_id,
            invocation_id=invocation_id,
            evidence_id=evidence.evidence_id,
            sanitization_state=sanitization_state.value,
        )
        return evidence


def _detect_secrets(text: str, *, evidence_id: EvidenceId) -> list[SecretObservation]:
    """Detect secret-like material; produce safe metadata ONLY."""
    observations: list[SecretObservation] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        for pattern, secret_class in _SECRET_CLASS_HINTS:
            if pattern.search(line):
                redacted_location = f"line:{line_no} [REDACTED]"
                observations.append(
                    SecretObservation(
                        secret_class=secret_class,
                        redacted_location=redacted_location,
                        evidence_id=evidence_id,
                        detection_source="secscan-platform-secret-detector",
                    )
                )
                break
    return observations


def _redact_secret_values(text: str) -> str:
    """Replace any remaining secret-like values with <REDACTED:secret>.

    Runs only after detection fired (the caller guarantees this), so the
    aggressive block/body/base64 patterns cannot over-redact clean files.
    """
    redacted = text
    for pattern in _SECRET_PATTERNS:
        redacted = pattern.sub("<REDACTED:secret>", redacted)
    for pattern in _REDACTION_PATTERNS:
        redacted = pattern.sub("<REDACTED:secret>", redacted)
    return redacted


def _looks_textual(content_type: str) -> bool:
    return content_type.startswith("text/") or "json" in content_type or "yaml" in content_type


def _trace_evidence_ingestion(
    *,
    engagement_id: EngagementId,
    target_id: TargetId,
    capability_id: CapabilityId,
    invocation_id: ToolInvocationId,
    evidence_id: EvidenceId,
    sanitization_state: str,
) -> None:
    """Span for evidence ingestion. ONLY safe identifiers; no content."""
    from secscan.platform.observability import safe_attributes, setup_tracing

    tracer = setup_tracing()
    with tracer.start_as_current_span("evidence.ingest") as span:
        for key, value in safe_attributes(
            engagement_id=engagement_id,
            target_id=target_id,
            capability_id=capability_id,
            tool_invocation_id=invocation_id,
            evidence_id=evidence_id,
        ).items():
            span.set_attribute(key, value)
        span.set_attribute("sanitization_state", sanitization_state)
