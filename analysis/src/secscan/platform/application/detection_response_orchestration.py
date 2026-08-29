"""Durable event-to-detection orchestration around the existing engine."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict

from secscan.platform.continuous_security.events import SecurityEventPlane
from secscan.platform.detection_response.domain import (
    DetectionWorkItem,
    DetectionWorkStatus,
    Scope,
)
from secscan.platform.detection_response.engine import (
    BoundedSecurityEventIngestor,
    DetectionEngine,
)
from secscan.platform.domain.ids import new_id


class DetectionDispatchReceipt(BaseModel):
    model_config = ConfigDict(frozen=True)

    work_id: str
    status: str
    attempts: int
    run_ids: tuple[str, ...]
    signal_ids: tuple[str, ...]


class DetectionResponseOrchestrationService:
    """Claim durable work, reconstruct canonical inputs, and persist outputs."""

    def __init__(self, repository: Any) -> None:
        self._repository = repository

    def register_owned_rule(
        self,
        rule: Any,
        plan: Any | None = None,
        *,
        access_principal_id: str | None = None,
    ) -> Any:
        """Register repository-owned content; no live API exposes this method."""

        return self._repository.register_rule(
            rule,
            plan,
            access_principal_id=access_principal_id,
        )

    @staticmethod
    def _receipt(work: DetectionWorkItem) -> DetectionDispatchReceipt:
        return DetectionDispatchReceipt(
            work_id=work.work_id,
            status=work.status.value,
            attempts=work.attempts,
            run_ids=work.run_ids,
            signal_ids=work.signal_ids,
        )

    def dispatch_pending(
        self,
        *,
        scope: Scope | None = None,
        limit: int = 20,
        worker_id: str | None = None,
        access_principal_id: str | None = None,
    ) -> tuple[DetectionDispatchReceipt, ...]:
        worker = worker_id or new_id("WORKER-")
        claimed = self._repository.claim_work(
            worker_id=worker,
            limit=limit,
            scope=scope,
            access_principal_id=access_principal_id,
        )
        return tuple(
            self._process_claimed(
                item,
                access_principal_id=access_principal_id,
            )
            for item in claimed
        )

    def dispatch_one(
        self,
        work_id: str,
        *,
        worker_id: str | None = None,
        access_principal_id: str | None = None,
    ) -> DetectionDispatchReceipt:
        worker = worker_id or new_id("WORKER-")
        current = self._repository.get_work(work_id, access_principal_id=access_principal_id)
        if current is None:
            raise KeyError("detection work item not found")
        if current.status == DetectionWorkStatus.COMPLETED:
            return self._receipt(current)
        claimed = self._repository.claim_one(
            work_id,
            worker_id=worker,
            access_principal_id=access_principal_id,
        )
        if claimed is None:
            raise RuntimeError("detection work item is currently leased by another worker")
        return self._process_claimed(claimed, access_principal_id=access_principal_id)

    def _process_claimed(
        self,
        work: DetectionWorkItem,
        *,
        access_principal_id: str | None,
    ) -> DetectionDispatchReceipt:
        try:
            events = self._repository.load_events(
                work.scope,
                access_principal_id=access_principal_id,
            )
            plane = SecurityEventPlane()
            ingestor = BoundedSecurityEventIngestor(plane, scope=work.scope)
            for event in events:
                ingestor.ingest(event, scope=work.scope)
            detector = DetectionEngine(ingestor, scope=work.scope)
            rules = self._repository.active_rules(access_principal_id=access_principal_id)
            run_ids: list[str] = []
            signal_ids: list[str] = []
            for rule, plan in rules:
                detector.register_rule(rule, plan=plan)
                run = detector.run(rule, scope=work.scope)
                evaluations = tuple(
                    item for item in detector.evaluations(scope=work.scope) if item.run_id == run.run_id
                )
                signals = tuple(
                    detector.get_signal(signal_id, scope=work.scope)
                    for signal_id in run.signal_ids
                )
                self._repository.persist_detection_outputs(
                    rule,
                    plan,
                    run,
                    evaluations,
                    signals,
                    access_principal_id=access_principal_id,
                )
                run_ids.append(run.run_id)
                signal_ids.extend(run.signal_ids)
            completed = self._repository.complete_work(
                work.work_id,
                worker_id=work.worker_id or "",
                run_ids=run_ids,
                signal_ids=tuple(dict.fromkeys(signal_ids)),
                access_principal_id=access_principal_id,
            )
            return self._receipt(completed)
        except Exception as exc:
            self._repository.fail_work(
                work.work_id,
                worker_id=work.worker_id or "",
                error_type=type(exc).__name__,
                access_principal_id=access_principal_id,
            )
            raise


__all__ = ["DetectionDispatchReceipt", "DetectionResponseOrchestrationService"]
