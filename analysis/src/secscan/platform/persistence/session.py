"""Persistence adapter wiring: engine/session factory + repositories.

Adapters only. The domain never imports this module; application services
receive repositories through their ports.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker


def database_url_from_env(default: str | None = None) -> str:
    url = os.environ.get("SECSCAN_DB_URL") or default
    if not url:
        raise RuntimeError(
            "SECSCAN_DB_URL is not set. Example: "
            "postgresql+psycopg://user:password@localhost:5432/secscanmonitor"
        )
    return url


def create_engine_from_url(url: str, *, echo: bool = False) -> Engine:
    return create_engine(url, echo=echo, pool_pre_ping=True)


def session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False)


def make_sessions(url: str | None = None) -> tuple[Engine, sessionmaker[Session]]:
    engine = create_engine_from_url(url or database_url_from_env())
    return engine, session_factory(engine)


def set_human_context(session: Session, human_principal_id: str) -> None:
    """Set transaction-scoped RLS context; never uses a session-wide value."""

    if session.bind is None or session.bind.dialect.name != "postgresql":
        return
    session.execute(
        text("SELECT set_config('secscan.human_principal_id', :principal_id, true)"),
        {"principal_id": human_principal_id},
    )


@contextmanager
def human_context(session: Session, human_principal_id: str) -> Iterator[Session]:
    """Apply and clear verified human identity inside one transaction."""

    with session.begin():
        set_human_context(session, human_principal_id)
        yield session
