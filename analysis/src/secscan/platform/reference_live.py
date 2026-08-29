"""Local reference composition for the v0.3 live control plane.

This module is intentionally a qualification composition, not a deployment
entrypoint.  It keeps canonical state in PostgreSQL and evaluates response
authority with the pinned OPA subprocess.
"""

from __future__ import annotations

import os

from fastapi import FastAPI

from secscan.platform.api import AppState, create_app
from secscan.platform.domain.engagement import AuthorityLevel, Engagement, EngagementStatus, PassType
from secscan.platform.domain.ids import ClientId, EngagementId, PrincipalId, TargetId
from secscan.platform.hosted.identity import VerifiedHumanIdentity
from secscan.platform.live import build_live_control_plane
from secscan.platform.persistence.repositories import PostgresReadModelService
from secscan.platform.persistence.session import make_sessions
from secscan.platform.policy import OpaSubprocessClient

REFERENCE_CLIENT_ID = "CLI-LIVE-V03"
REFERENCE_CASE_ID = "ENG-LIVE-V03"
REFERENCE_TARGET_ID = "TGT-LIVE-V03"
REFERENCE_OPERATOR_ID = "PRN-LIVE-V03-OP"


def reference_state() -> AppState:
    """Return only the UI shell metadata; live security records stay in PG."""

    state = AppState()
    state.clients[ClientId(REFERENCE_CLIENT_ID)] = {
        "client_id": REFERENCE_CLIENT_ID,
        "name": "SecScanMonitor live control-plane fixture",
    }
    state.targets[TargetId(REFERENCE_TARGET_ID)] = {
        "target_id": REFERENCE_TARGET_ID,
        "client_id": REFERENCE_CLIENT_ID,
        "kind": "agent_system",
        "name": "controlled live source target",
    }
    state.engagements[EngagementId(REFERENCE_CASE_ID)] = Engagement(
        engagement_id=EngagementId(REFERENCE_CASE_ID),
        client_id=ClientId(REFERENCE_CLIENT_ID),
        requester_principal_id=PrincipalId(REFERENCE_OPERATOR_ID),
        target_ids=[TargetId(REFERENCE_TARGET_ID)],
        scope="v0.3 live control-plane implementation acceptance",
        pass_type=PassType.POSTURE,
        authority_level=AuthorityLevel.REMEDIATION,
        status=EngagementStatus.ADJUDICATION,
    )
    return state


def build_reference_app() -> FastAPI:
    """Build the loopback app from explicit PostgreSQL/OPA configuration."""

    database_url = os.environ.get("SECSCAN_DB_URL") or os.environ.get("SECSCAN_TEST_DB_URL")
    if not database_url:
        raise RuntimeError("reference live composition requires SECSCAN_DB_URL")
    _, sessions = make_sessions(database_url)
    read_models = PostgresReadModelService(sessions)

    def read_experience(principal_id: str) -> dict[str, object]:
        snapshot = read_models.experience(
            identity=VerifiedHumanIdentity(
                human_principal_id=principal_id,
                issuer="local://secscanmonitor",
                subject=principal_id,
            )
        )
        snapshot["mode"] = "LOCAL_INTEGRATED"
        snapshot["sourceLabel"] = "LOCAL / LOOPBACK / CANONICAL_POSTGRESQL"
        return snapshot

    live = build_live_control_plane(
        sessions,
        policy_client=OpaSubprocessClient(),
        experience_reader=read_experience,
        recovery_access_principal_id=REFERENCE_OPERATOR_ID,
    )
    return create_app(
        state=reference_state(),
        bind_host="127.0.0.1",
        live_control_plane=live,
    )


app = build_reference_app()


__all__ = [
    "REFERENCE_CASE_ID",
    "REFERENCE_CLIENT_ID",
    "REFERENCE_OPERATOR_ID",
    "REFERENCE_TARGET_ID",
    "app",
    "build_reference_app",
    "reference_state",
]
