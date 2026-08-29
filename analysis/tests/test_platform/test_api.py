"""Firm API tests (G13): endpoints, dev auth, security semantics.

Authorization at the application boundary: no anonymous mutations; dev auth
refuses non-loopback binding and non-loopback clients. Raw evidence bytes
are never served.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from secscan.platform.api import AppState, DevAuthInactiveError, create_app

HEADERS = {"X-Secscan-Principal": "PRN-OPERATOR"}


@pytest.fixture()
def client():
    return TestClient(create_app(AppState(), bind_host="127.0.0.1"))


def _create_engagement(client: TestClient) -> dict:
    response = client.post(
        "/engagements",
        json={
            "engagement_id": "ENG-API-1",
            "client_id": "CLI-API-1",
            "target_ids": ["TGT-API-1"],
            "scope": "api test fixture",
            "pass_type": "posture",
        },
        headers=HEADERS,
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_health_anonymous(client) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_mutations_require_principal(client) -> None:
    response = client.post("/engagements", json={"engagement_id": "X"}, headers={})
    assert response.status_code == 401
    response = client.get("/engagements/ENG-API-1", headers={})
    assert response.status_code == 401


def test_engagement_lifecycle_endpoints(client) -> None:
    engagement = _create_engagement(client)
    assert engagement["status"] == "draft"
    # authorize walks the state machine
    authorized = client.post("/engagements/ENG-API-1/authorize", headers=HEADERS)
    assert authorized.status_code == 200
    assert authorized.json()["status"] == "authorized"
    # suspend / resume
    suspended = client.post("/engagements/ENG-API-1/suspend", headers=HEADERS)
    assert suspended.json()["status"] == "suspended"
    resumed = client.post("/engagements/ENG-API-1/resume", headers=HEADERS)
    assert resumed.json()["status"] == "authorized"


def test_invalid_state_transition_rejected(client) -> None:
    _create_engagement(client)
    # draft -> suspend is invalid: deterministic 409, not a state change
    response = client.post("/engagements/ENG-API-1/suspend", headers=HEADERS)
    assert response.status_code == 409


def test_clients_and_targets(client) -> None:
    assert client.post("/clients", json={"client_id": "CLI-1", "name": "acme"}, headers=HEADERS).status_code == 200
    assert client.get("/clients/CLI-1", headers=HEADERS).json()["name"] == "acme"
    assert client.post("/targets", json={"target_id": "TGT-1", "name": "repo-a"}, headers=HEADERS).status_code == 200
    assert client.get("/targets/TGT-1", headers=HEADERS).json()["name"] == "repo-a"


def test_capabilities_listed(client) -> None:
    response = client.get("/capabilities", headers=HEADERS)
    assert response.status_code == 200
    ids = {capability["capability_id"] for capability in response.json()}
    assert "CAP-REPO-READONLY-INSPECTION" in ids
    assert "CAP-REPO-INVENTORY" in ids


def test_evidence_endpoint_metadata_only(client) -> None:
    # register metadata through the state directly (no ingestion endpoint in
    # the minimal API); the endpoint must serve metadata and never bytes.
    state = client.app  # type: ignore[attr-defined]
    from secscan.platform.api import AppState

    assert isinstance(state, AppState) is False  # app attribute is the FastAPI instance
    # Use a fresh app with a known state to seed metadata.
    app_state = AppState()
    app_state.evidence_metadata["EV-1"] = {
        "evidence_id": "EV-1",
        "sha256": "a" * 64,
        "sanitization_state": "redacted",
        "secret_observations": [{"secret_class": "api_key", "redacted_location": "line:1 [REDACTED]"}],
    }
    test_client = TestClient(create_app(app_state, bind_host="127.0.0.1"))
    response = test_client.get("/evidence/EV-1/metadata", headers=HEADERS)
    assert response.status_code == 200
    body = response.json()
    assert "raw_content" not in body  # no byte-serving field exists
    assert "REDACTED" in str(body)


def test_findings_endpoints(client) -> None:
    _create_engagement(client)
    assert client.get("/findings/NOPE", headers=HEADERS).status_code == 404
    assert client.get("/engagements/ENG-API-1/findings", headers=HEADERS).json() == []


def test_approval_endpoints(client) -> None:
    from secscan.platform.domain.authority import Action, Approval
    from secscan.platform.domain.ids import ApprovalId, CapabilityId, EngagementId, PrincipalId, TargetId

    approval = Approval(
        approval_id=ApprovalId("AP-1"),
        engagement_id=EngagementId("ENG-API-1"),
        requested_by_principal_id=PrincipalId("PRN-AGENT"),
        request_ref="TE-1",
        target_id=TargetId("TGT-1"),
        capability_id=CapabilityId("CAP-1"),
        action=Action.INSPECT,
    )
    state_holder = AppState()
    state_holder.approvals["AP-1"] = approval
    test_client = TestClient(create_app(state_holder, bind_host="127.0.0.1"))
    approved = test_client.post("/approvals/AP-1/approve", headers=HEADERS)
    assert approved.json()["decision"] == "approved"


def test_dev_auth_refuses_non_loopback_binding() -> None:
    with pytest.raises(DevAuthInactiveError):
        create_app(AppState(), bind_host="0.0.0.0")
    with pytest.raises(DevAuthInactiveError):
        create_app(AppState(), bind_host="192.168.1.10")


def test_dev_auth_refuses_non_loopback_client_scope() -> None:
    """Real refusal path: an ASGI request from a non-loopback address gets 403."""
    import asyncio

    app = create_app(AppState(), bind_host="127.0.0.1")

    async def _scoped_request() -> dict:
        messages: list[dict] = []

        async def receive() -> dict:
            return {"type": "http.request", "body": b"", "more_body": False}

        scope: dict = {
            "type": "http",
            "method": "GET",
            "path": "/engagements/ENG-API-1",
            "headers": [(b"x-secscan-principal", b"PRN-OPERATOR")],
            "query_string": b"",
            "client": ("203.0.113.7", 12345),
            "server": ("127.0.0.1", 8000),
        }

        async def _send(message: dict) -> None:
            messages.append(message)

        await app(scope, receive, _send)
        status = next(m["status"] for m in messages if m["type"] == "http.response.start")
        return {"status": status}

    result = asyncio.run(_scoped_request())
    assert result["status"] == 403


def test_report_endpoint_404_when_absent(client) -> None:
    _create_engagement(client)
    assert client.get("/engagements/ENG-API-1/report", headers=HEADERS).status_code == 404


def test_local_v03_projection_is_read_only_and_scope_explicit() -> None:
    state = AppState(
        detection_signals={
            "SIG-LOCAL-1": {
                "signal_id": "SIG-LOCAL-1",
                "tenant_id": "tenant-local",
                "case_id": "case-local",
                "rule_id": "rule-local",
                "rule_version": 1,
                "severity": "HIGH",
                "confidence": "HIGH",
                "status": "NEW",
                "event_ids": ["SE-LOCAL-1"],
                "evidence_refs": ["metadata://SE-LOCAL-1"],
                "source": "local qualification",
            }
        }
    )
    test_client = TestClient(create_app(state, bind_host="127.0.0.1"))

    for path in ("/detection/signals", "/hunts", "/incidents", "/response-proposals"):
        response = test_client.get(path, headers=HEADERS)
        assert response.status_code == 200, response.text
        assert "items" in response.json()
    snapshot = test_client.get("/experience", headers=HEADERS)
    assert snapshot.status_code == 200
    body = snapshot.json()
    assert body["detectionSignals"][0]["signalId"] == "SIG-LOCAL-1"
    assert body["detectionSignals"][0]["scope"] == {"tenantId": "tenant-local", "caseId": "case-local"}
    assert body["incidents"] == []
    assert body["responseProposals"] == []
