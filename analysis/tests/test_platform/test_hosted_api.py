from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from secscan.platform.api import AppState, create_app
from secscan.platform.hosted.config import HostedConfigurationError, RuntimeConfig, RuntimeMode
from secscan.platform.hosted.identity import (
    ClientMembership,
    HumanAccessService,
    HumanRole,
    InMemoryHumanMembershipStore,
    VerifiedHumanIdentity,
)
from secscan.platform.read_models import (
    CursorPage,
    DetectionSignalReadModel,
    FirmSummaryReadModel,
    HuntReadModel,
    IncidentReadModel,
    ResponseProposalReadModel,
)


def _config() -> RuntimeConfig:
    return RuntimeConfig(
        mode=RuntimeMode.HOSTED_INTEGRATED,
        database_runtime_url="postgresql://placeholder-runtime",
        database_migration_url="postgresql://placeholder-migration",
        auth_issuer="https://issuer.example",
        auth_audience="secscanmonitor",
        auth_jwks_url="https://issuer.example/.well-known/jwks.json",
        auth_session_url="https://issuer.example/api/get-session",
        temporal_address="temporal.example:7233",
        temporal_namespace="secscan-staging",
        opa_url="https://opa.example",
        opa_policy_digest="sha256:" + "a" * 64,
        evidence_store_provider="s3-compatible",
        evidence_store_id="staging-evidence",
        sandbox_provider="isolated-staging-sandbox",
        frontend_origin="https://preview.example",
        service_environment="staging",
        observability_endpoint="https://otel.example",
        live_recovery_access_principal_id="PRN-HOSTED-LIVE-RECOVERY",
    )


class _Verifier:
    def __init__(self, revoked: set[str] | None = None) -> None:
        self.revoked = revoked if revoked is not None else set()

    def verify_bearer_token(self, token: str) -> VerifiedHumanIdentity:
        assert token == "test-token"
        if token in self.revoked:
            raise PermissionError("human session is revoked")
        return VerifiedHumanIdentity("human-1", "https://issuer.example", "subject-1")

    def verify_session_cookie(self, cookie: str) -> str:
        assert cookie == "session=active"
        return "subject-1"


class _Reads:
    def firm_summary(self, *, identity: VerifiedHumanIdentity) -> FirmSummaryReadModel:
        assert identity.human_principal_id == "human-1"
        return FirmSummaryReadModel(
            clients=0,
            targets=0,
            engagements=0,
            findings=0,
            evidence_items=0,
            audit_events=0,
            data_mode="HOSTED_INTEGRATED",
        )

    def list_detection_signals(self, *, identity: VerifiedHumanIdentity, cursor: str | None = None, limit: int = 50):
        assert identity.human_principal_id == "human-1"
        return CursorPage[DetectionSignalReadModel](items=[], next_cursor=None, limit=limit)

    def list_hunts(self, *, identity: VerifiedHumanIdentity, cursor: str | None = None, limit: int = 50):
        assert identity.human_principal_id == "human-1"
        return CursorPage[HuntReadModel](items=[], next_cursor=None, limit=limit)

    def list_incidents(self, *, identity: VerifiedHumanIdentity, cursor: str | None = None, limit: int = 50):
        assert identity.human_principal_id == "human-1"
        return CursorPage[IncidentReadModel](items=[], next_cursor=None, limit=limit)

    def list_response_proposals(self, *, identity: VerifiedHumanIdentity, cursor: str | None = None, limit: int = 50):
        assert identity.human_principal_id == "human-1"
        return CursorPage[ResponseProposalReadModel](items=[], next_cursor=None, limit=limit)


class _Revocations:
    def __init__(self) -> None:
        self.tokens: set[str] = set()

    def is_revoked(self, token: str) -> bool:
        return token in self.tokens

    def revoke(self, token: str, _human_principal_id: str) -> None:
        self.tokens.add(token)


def test_hosted_api_requires_bearer_identity_and_never_claims_unprobed_readiness() -> None:
    memberships = InMemoryHumanMembershipStore(
        [ClientMembership("human-1", "client-a", HumanRole.CLIENT_VIEWER)]
    )
    client = TestClient(
        create_app(
            runtime_config=_config(),
            identity_verifier=_Verifier(),
            read_model_service=_Reads(),
            human_access_service=HumanAccessService(memberships),
        )
    )

    assert client.get("/health").status_code == 200
    assert client.get("/ready").status_code == 503
    assert client.get("/firm/summary").status_code == 401
    assert client.get("/firm/summary", headers={"X-Secscan-Principal": "operator-local"}).status_code == 401
    response = client.get("/firm/summary", headers={"Authorization": "Bearer test-token"})
    assert response.status_code == 200
    response = client.get(
        "/firm/summary",
        headers={"Authorization": "Bearer test-token", "Cookie": "session=active"},
    )
    assert response.status_code == 200
    assert response.json()["data_mode"] == "HOSTED_INTEGRATED"
    assert client.get(
        "/firm/summary",
        headers={"Authorization": "Bearer test-token", "Cookie": "session=wrong"},
    ).status_code == 401
    assert client.get(
        "/targets?client_id=client-b",
        headers={"Authorization": "Bearer test-token", "Cookie": "session=active"},
    ).status_code == 404


def test_hosted_api_revocation_blocks_the_same_protected_api_token() -> None:
    revoked = _Revocations()
    client = TestClient(
        create_app(
            runtime_config=_config(),
            identity_verifier=_Verifier(revoked.tokens),
            read_model_service=_Reads(),
            human_access_service=HumanAccessService(
                InMemoryHumanMembershipStore(
                    [ClientMembership("human-1", "client-a", HumanRole.CLIENT_VIEWER)]
                )
            ),
            hosted_token_revocation_store=revoked,
        )
    )
    headers = {"Authorization": "Bearer test-token"}

    assert client.get("/firm/summary", headers=headers).status_code == 200
    assert client.post("/auth/revoke", headers=headers).status_code == 200
    assert client.get("/firm/summary", headers=headers).status_code == 401


def test_hosted_api_rejects_local_composition() -> None:
    with pytest.raises(HostedConfigurationError):
        create_app(runtime_config=_config(), state=AppState())


def test_hosted_api_requires_application_tenant_access_service() -> None:
    with pytest.raises(HostedConfigurationError):
        create_app(runtime_config=_config(), identity_verifier=_Verifier(), read_model_service=_Reads())


def test_hosted_v03_projection_routes_require_identity_and_use_canonical_reader() -> None:
    client = TestClient(
        create_app(
            runtime_config=_config(),
            identity_verifier=_Verifier(),
            read_model_service=_Reads(),
            human_access_service=HumanAccessService(
                InMemoryHumanMembershipStore(
                    [ClientMembership("human-1", "client-a", HumanRole.CLIENT_VIEWER)]
                )
            ),
        )
    )
    for path in ("/detection/signals", "/hunts", "/incidents", "/response-proposals"):
        assert client.get(path).status_code == 401
        response = client.get(path, headers={"Authorization": "Bearer test-token"})
        assert response.status_code == 200, response.text
        assert response.json() == {"items": [], "next_cursor": None, "limit": 50}
