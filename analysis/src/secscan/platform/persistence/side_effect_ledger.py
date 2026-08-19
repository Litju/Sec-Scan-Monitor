"""PostgreSQL-backed side-effect ledger (canonical idempotency state).

Implements the same record/count/snapshot interface as the in-memory
SideEffectLedger, backed by the workflow_side_effects table whose PRIMARY
KEY is the idempotency key: exactly-once at the database level, across
restarts, workers, and failovers. record() replays (returns the stored
effect) instead of raising.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from secscan.platform.persistence.models import WorkflowSideEffectRow


class PostgresSideEffectLedger:
    def __init__(self, bind: Any) -> None:
        """bind: a SQLAlchemy Engine or sessionmaker."""
        self._bind = bind

    def record(self, key: str, effect: dict[str, Any]) -> dict[str, Any]:
        with Session(self._bind) as session:
            statement = (
                pg_insert(WorkflowSideEffectRow)
                .values(idempotency_key=key, effect=effect)
                .on_conflict_do_nothing(index_elements=[WorkflowSideEffectRow.idempotency_key])
            )
            session.execute(statement)
            session.commit()
        # replay semantics: read back whatever row won (ours or a prior one)
        with Session(self._bind) as session:
            row = session.get(WorkflowSideEffectRow, key)
        if row is None:  # pragma: no cover - cannot happen after upsert
            raise RuntimeError(f"side-effect ledger lost record for key {key}")
        return dict(row.effect)

    def count(self, prefix: str = "") -> int:
        with Session(self._bind) as session:
            query = select(WorkflowSideEffectRow.idempotency_key)
            if prefix:
                query = query.where(WorkflowSideEffectRow.idempotency_key.like(f"{prefix}%"))
            return len(session.execute(query).scalars().all())

    def snapshot(self) -> dict[str, dict[str, Any]]:
        with Session(self._bind) as session:
            rows = session.execute(select(WorkflowSideEffectRow)).scalars().all()
        return {row.idempotency_key: dict(row.effect) for row in rows}
