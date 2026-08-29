"""Single application composition for the live v0.3 control-plane path."""

from __future__ import annotations

from typing import Any, Callable, cast

from secscan.platform.application.detection_response_orchestration import (
    DetectionResponseOrchestrationService,
)
from secscan.platform.application.live_incident_control_plane import LiveIncidentControlPlaneService
from secscan.platform.application.live_ingest import SecurityEventIngestService


class LiveControlPlaneService:
    """Expose the three explicit application boundaries as one API dependency."""

    def __init__(
        self,
        repository: Any,
        *,
        policy_client: Any | None = None,
        experience_reader: Callable[[str], dict[str, Any]] | None = None,
    ) -> None:
        self.repository = repository
        self.ingest = SecurityEventIngestService(repository)
        self.detection = DetectionResponseOrchestrationService(repository)
        self.incidents = LiveIncidentControlPlaneService(repository, policy_client)
        self._experience_reader = experience_reader

    def read_detection_signals(self, *, access_principal_id: str | None = None) -> list[dict[str, Any]]:
        return cast(list[dict[str, Any]], self.repository.read_detection_signals(access_principal_id=access_principal_id))

    def read_hunts(self, *, access_principal_id: str | None = None) -> list[dict[str, Any]]:
        return cast(list[dict[str, Any]], self.repository.read_hunts(access_principal_id=access_principal_id))

    def read_incidents(self, *, access_principal_id: str | None = None) -> list[dict[str, Any]]:
        return cast(list[dict[str, Any]], self.repository.read_incidents(access_principal_id=access_principal_id))

    def read_response_proposals(self, *, access_principal_id: str | None = None) -> list[dict[str, Any]]:
        return cast(list[dict[str, Any]], self.repository.read_response_proposals(access_principal_id=access_principal_id))

    def read_approvals(self, *, access_principal_id: str | None = None) -> list[dict[str, Any]]:
        return cast(list[dict[str, Any]], self.repository.read_approvals(access_principal_id=access_principal_id))

    def experience_overlay(
        self,
        base_snapshot: dict[str, Any],
        *,
        access_principal_id: str | None = None,
    ) -> dict[str, Any]:
        """Replace local preview-shaped detection fields with canonical rows."""

        signals = self.read_detection_signals(access_principal_id=access_principal_id)
        hunts = self.read_hunts(access_principal_id=access_principal_id)
        incidents = self.read_incidents(access_principal_id=access_principal_id)
        proposals = self.read_response_proposals(access_principal_id=access_principal_id)

        def status(value: str, fallback: str = "UNKNOWN") -> str:
            return {
                "SUPPORTS": "VERIFIED",
                "REFUTES": "CONTRADICTED",
                "REQUIRE_APPROVAL": "APPROVAL_REQUIRED",
                "ALLOW": "VERIFIED",
                "DENY": "DENIED",
            }.get(value.upper(), value.upper() or fallback)

        live_tenant = next(
            (
                str(item[key])
                for items, key in (
                    (signals, "tenant_id"),
                    (hunts, "tenant_id"),
                    (incidents, "tenant_id"),
                    (proposals, "tenant_id"),
                )
                for item in items
                if item.get(key)
            ),
            str(base_snapshot.get("tenantId", "operator-scope")),
        )
        result = (
            dict(self._experience_reader(access_principal_id or ""))
            if self._experience_reader is not None
            else dict(base_snapshot)
        )
        result.update(
            {
                "connectionState": "CONNECTED",
                "sourceLabel": "LOCAL / LOOPBACK / CANONICAL_POSTGRESQL",
                "tenantId": live_tenant,
                "detectionSignals": [
                    {
                        "id": item["signal_id"],
                        "signalId": item["signal_id"],
                        "caseId": item["case_id"],
                        "ruleId": item["rule_id"],
                        "ruleVersion": item["rule_version"],
                        "severity": item["severity"],
                        "confidence": item["confidence"],
                        "state": status(item["status"]),
                        "eventIds": item["event_ids"],
                        "evidenceRefs": item["evidence_refs"],
                        "scope": {"tenantId": item["tenant_id"], "caseId": item["case_id"]},
                        "source": item["source"],
                    }
                    for item in signals
                ],
                "hunts": [
                    {
                        "id": item["hunt_id"],
                        "huntId": item["hunt_id"],
                        "hypothesisId": item["hypothesis_id"],
                        "caseId": item["case_id"],
                        "disposition": status(item["disposition"], "INCONCLUSIVE"),
                        "state": status(item["status"], "INCONCLUSIVE"),
                        "evidenceRefs": item["evidence_refs"],
                        "scope": {"tenantId": item["tenant_id"], "caseId": item["case_id"]},
                        "source": item["source"],
                    }
                    for item in hunts
                ],
                "incidents": [
                    {
                        "id": item["incident_id"],
                        "incidentId": item["incident_id"],
                        "caseId": item["case_id"],
                        "state": status(item["status"]),
                        "severity": item["severity"],
                        "confidence": item["confidence"],
                        "signalIds": item["signal_ids"],
                        "evidenceRefs": item["evidence_refs"],
                        "scope": {"tenantId": item["tenant_id"], "caseId": item["case_id"]},
                        "provenance": {
                            "source": item["provenance_source"],
                            "sourceType": item["provenance_source_type"],
                            "observedAt": item["adjudicated_at"],
                            "evidenceRefs": item["evidence_refs"],
                            "status": status(item["status"]),
                        },
                    }
                    for item in incidents
                ],
                "responseProposals": [
                    {
                        "id": item["proposal_id"],
                        "proposalId": item["proposal_id"],
                        "incidentId": item["incident_id"],
                        "caseId": item["case_id"],
                        "targetId": item["target_id"],
                        "action": item["action"],
                        "opaDecision": status(item["opa_decision"]),
                        "humanApprovalState": status(item["human_approval_state"]),
                        "state": status(item["status"]),
                        "evidenceRefs": item["evidence_refs"],
                        "scope": {"tenantId": item["tenant_id"], "caseId": item["case_id"]},
                        "source": item["source"],
                    }
                    for item in proposals
                ],
            }
        )
        return result


__all__ = ["LiveControlPlaneService"]
