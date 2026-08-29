"""Reference live control-plane composition root."""

from __future__ import annotations

from typing import Any, Callable

from sqlalchemy.orm import Session

from secscan.platform.application.live_control_plane import LiveControlPlaneService
from secscan.platform.persistence.live_control_plane import PostgresLiveControlPlaneRepository


def build_live_control_plane(
    session_factory: Callable[[], Session],
    *,
    policy_client: Any,
    experience_reader: Callable[[str], dict[str, Any]] | None = None,
    recovery_access_principal_id: str,
) -> LiveControlPlaneService:
    """Build the canonical PostgreSQL-backed live services explicitly."""

    if not recovery_access_principal_id.strip():
        raise ValueError("live startup recovery requires an access principal")
    repository = PostgresLiveControlPlaneRepository(session_factory)
    service = LiveControlPlaneService(
        repository,
        policy_client=policy_client,
        experience_reader=experience_reader,
    )
    service.incidents.recover_pending_hunts(access_principal_id=recovery_access_principal_id)
    return service


__all__ = ["build_live_control_plane"]
