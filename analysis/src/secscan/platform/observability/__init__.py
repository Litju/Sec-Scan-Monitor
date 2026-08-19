"""OpenTelemetry instrumentation (ADR-0010).

Span attribute policy: only safe identifiers (engagement_id, target_id,
workflow_run_id, agent_run_id, capability_id, tool_invocation_id,
evidence_id) plus bounded scalar metadata. Secrets, raw file contents, raw
prompts, and credential values NEVER enter spans — enforced by
`safe_attributes` (rejects secret-like values) and a leakage test.

OTLP export is configured from environment (OTEL_EXPORTER_OTLP_ENDPOINT);
default is no-op export for tests. Phoenix is an optional development
profile, never a canonical dependency.
"""

from __future__ import annotations

import os
import re

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter

SAFE_ATTRIBUTE_KEYS = frozenset(
    {
        "engagement_id",
        "target_id",
        "workflow_run_id",
        "agent_run_id",
        "capability_id",
        "tool_invocation_id",
        "evidence_id",
        "approval_id",
        "adjudication_id",
        "finding_id",
        "sandbox_id",
        "principal_id",
        "severity",
        "decision",
        "verdict",
        "status",
    }
)

_SECRET_LIKE = re.compile(
    r"-----BEGIN [A-Z ]+PRIVATE KEY-----|AIza[0-9A-Za-z_-]{20,}|"
    r"(?i:github_pat_[A-Za-z0-9_]{20,})|(?i:sk-[A-Za-z0-9]{20,})|(?i:ghp_[A-Za-z0-9]{20,})"
)


class SpanAttributePolicyError(ValueError):
    """Raised when a span attribute violates the observability policy."""


def safe_attributes(**attributes: str | int | float | bool) -> dict[str, str | int | float | bool]:
    """Validate and normalize span attributes.

    Unknown keys and secret-like values are rejected — spans are an
    exfiltration channel and the policy is deny-by-default.
    """
    for key, value in attributes.items():
        if key not in SAFE_ATTRIBUTE_KEYS:
            raise SpanAttributePolicyError(f"span attribute {key!r} is not on the safe-identifier allowlist")
        if isinstance(value, str) and _SECRET_LIKE.search(value):
            raise SpanAttributePolicyError(f"span attribute {key!r} contains secret-like content; rejected")
    return dict(attributes)


def _exporter_from_env() -> "OTLPSpanExporter | ConsoleSpanExporter | None":
    endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT") or os.environ.get("SECSCAN_OTLP_ENDPOINT")
    if endpoint:
        return OTLPSpanExporter(endpoint=endpoint)
    if os.environ.get("SECSCAN_OTEL_CONSOLE") == "1":
        return ConsoleSpanExporter()
    return None


def setup_tracing(service_name: str = "secscan-platform") -> trace.Tracer:
    provider = TracerProvider(resource=Resource.create({"service.name": service_name}))
    exporter = _exporter_from_env()
    if exporter is not None:
        provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)
    return trace.get_tracer(service_name)


TRACE_HIERARCHY = (
    "engagement",
    "workflow",
    "agent_run",
    "capability_execution",
    "tool_invocation",
    "sandbox_execution",
    "evidence_ingestion",
    "claim",
    "adjudication",
)
