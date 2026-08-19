"""Explicit runtime configuration with fail-closed hosted validation.

Local and preview composition may use the existing development defaults. A
hosted composition must provide every dependency boundary explicitly; this
module never resolves missing hosted values to localhost or process memory.
"""

from __future__ import annotations

import os
from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class RuntimeMode(StrEnum):
    LOCAL_INTEGRATED = "LOCAL_INTEGRATED"
    PREVIEW = "PREVIEW"
    HOSTED_INTEGRATED = "HOSTED_INTEGRATED"
    TEST = "TEST"


class HostedConfigurationError(RuntimeError):
    """Raised when a hosted composition is missing a required boundary."""


class RuntimeConfig(BaseModel):
    """Sanitized runtime settings; values are never included in error text."""

    model_config = ConfigDict(extra="forbid")

    mode: RuntimeMode
    database_runtime_url: str | None = None
    database_migration_url: str | None = None
    auth_issuer: str | None = None
    auth_audience: str | None = None
    auth_jwks_url: str | None = None
    auth_session_url: str | None = None
    temporal_address: str | None = None
    temporal_namespace: str | None = None
    workflow_start_url: str | None = None
    workflow_secret_configured: bool = False
    opa_url: str | None = None
    opa_policy_digest: str | None = None
    evidence_store_provider: str | None = None
    evidence_store_id: str | None = None
    sandbox_provider: str | None = None
    frontend_origin: str | None = None
    service_environment: str | None = None
    observability_endpoint: str | None = None

    @property
    def is_hosted(self) -> bool:
        return self.mode is RuntimeMode.HOSTED_INTEGRATED

    @classmethod
    def from_env(cls) -> "RuntimeConfig":
        raw_mode = os.environ.get("SECSCAN_MODE", RuntimeMode.LOCAL_INTEGRATED.value).strip()
        try:
            mode = RuntimeMode(raw_mode)
        except ValueError as exc:
            raise HostedConfigurationError("SECSCAN_MODE is invalid") from exc

        config = cls(
            mode=mode,
            database_runtime_url=os.environ.get("DATABASE_RUNTIME_URL"),
            database_migration_url=os.environ.get("DATABASE_MIGRATION_URL"),
            auth_issuer=os.environ.get("AUTH_ISSUER"),
            auth_audience=os.environ.get("AUTH_AUDIENCE"),
            auth_jwks_url=os.environ.get("AUTH_JWKS_URL"),
            auth_session_url=os.environ.get("AUTH_SESSION_URL"),
            temporal_address=os.environ.get("TEMPORAL_ADDRESS"),
            temporal_namespace=os.environ.get("TEMPORAL_NAMESPACE"),
            workflow_start_url=os.environ.get("WORKFLOW_START_URL"),
            workflow_secret_configured=bool(os.environ.get("WORKFLOW_SHARED_SECRET")),
            opa_url=os.environ.get("OPA_URL"),
            opa_policy_digest=os.environ.get("OPA_POLICY_DIGEST"),
            evidence_store_provider=os.environ.get("EVIDENCE_STORE_PROVIDER"),
            evidence_store_id=os.environ.get("EVIDENCE_STORE_ID"),
            sandbox_provider=os.environ.get("SANDBOX_PROVIDER"),
            frontend_origin=os.environ.get("FRONTEND_ORIGIN"),
            service_environment=os.environ.get("SERVICE_ENVIRONMENT"),
            observability_endpoint=os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT"),
        )
        config.require_hosted_boundaries()
        return config

    def require_hosted_boundaries(self) -> None:
        if not self.is_hosted:
            return
        values = self._hosted_values()
        missing = [
            name
            for name, value in values.items()
            if name
            not in {
                "TEMPORAL_ADDRESS",
                "TEMPORAL_NAMESPACE",
                "WORKFLOW_START_URL",
                "WORKFLOW_SHARED_SECRET",
                "OTEL_EXPORTER_OTLP_ENDPOINT",
            }
            and not value
        ]
        temporal_ready = bool(self.temporal_address and self.temporal_namespace)
        workflow_ready = bool(self.workflow_start_url and self.workflow_secret_configured)
        if not temporal_ready and not workflow_ready:
            missing.append("TEMPORAL_ADDRESS/TEMPORAL_NAMESPACE or WORKFLOW_START_URL/WORKFLOW_SHARED_SECRET")
        if missing:
            raise HostedConfigurationError(
                "HOSTED_INTEGRATED requires configured boundaries: " + ", ".join(missing)
            )

    def dependency_configuration(self) -> dict[str, bool]:
        """Return presence only; never expose connection strings or tokens."""

        return {name: bool(value) for name, value in self._hosted_values().items()}

    def _hosted_values(self) -> dict[str, str | None]:
        return {
            "DATABASE_RUNTIME_URL": self.database_runtime_url,
            "DATABASE_MIGRATION_URL": self.database_migration_url,
            "AUTH_ISSUER": self.auth_issuer,
            "AUTH_AUDIENCE": self.auth_audience,
            "AUTH_JWKS_URL": self.auth_jwks_url,
            "AUTH_SESSION_URL": self.auth_session_url,
            "TEMPORAL_ADDRESS": self.temporal_address,
            "TEMPORAL_NAMESPACE": self.temporal_namespace,
            "WORKFLOW_START_URL": self.workflow_start_url,
            "WORKFLOW_SHARED_SECRET": "configured" if self.workflow_secret_configured else None,
            "OPA_URL": self.opa_url,
            "OPA_POLICY_DIGEST": self.opa_policy_digest,
            "EVIDENCE_STORE_PROVIDER": self.evidence_store_provider,
            "EVIDENCE_STORE_ID": self.evidence_store_id,
            "SANDBOX_PROVIDER": self.sandbox_provider,
            "FRONTEND_ORIGIN": self.frontend_origin,
            "SERVICE_ENVIRONMENT": self.service_environment,
            "OTEL_EXPORTER_OTLP_ENDPOINT": self.observability_endpoint,
        }
