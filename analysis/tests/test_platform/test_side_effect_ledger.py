"""Optional PostgreSQL side-effect ledger checks for local self-hosting."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from secscan.platform.persistence.models import Base, WorkflowSideEffectRow
from secscan.platform.persistence.side_effect_ledger import PostgresSideEffectLedger

TEST_URL = "postgresql+psycopg://secscan@127.0.0.1:5433/secscanmonitor"


@pytest.fixture()
def ledger():
    engine = create_engine(TEST_URL, pool_pre_ping=True)
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except Exception as exc:  # pragma: no cover
        pytest.skip(f"PostgreSQL unavailable ({type(exc).__name__}); recorded as limitation")
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    yield PostgresSideEffectLedger(engine)
    Base.metadata.drop_all(engine)
    engine.dispose()


def test_record_replays_on_duplicate_key(ledger) -> None:
    effect = {"findings": 3}
    assert ledger.record("adjudicate:ENG-PUBLIC", effect) == effect
    assert ledger.record("adjudicate:ENG-PUBLIC", effect) == effect
    assert ledger.count("adjudicate:") == 1
    assert ledger.snapshot()["adjudicate:ENG-PUBLIC"] == effect


def test_unique_constraint_is_database_enforced(ledger) -> None:
    engine = create_engine(TEST_URL)
    with Session(engine) as session:
        session.add(WorkflowSideEffectRow(idempotency_key="close:ENG-PUBLIC", effect={"status": "closed"}))
        session.commit()
    with pytest.raises(IntegrityError):
        with Session(engine) as session:
            session.add(WorkflowSideEffectRow(idempotency_key="close:ENG-PUBLIC", effect={"status": "open"}))
            session.commit()
    engine.dispose()
