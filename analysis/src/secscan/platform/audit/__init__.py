"""Audit ledger (in-memory sink for canonical tests; PostgreSQL sink in
persistence.repositories). Append-oriented: no update/delete paths exist."""

from __future__ import annotations

from datetime import datetime

from secscan.platform.domain.audit import AuditEvent


class InMemoryAuditSink:
    """Append-only audit ledger for unit tests and in-process runs."""

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []
        self._deleted = 0

    def append(self, event: AuditEvent) -> None:
        previous = self._events[-1] if self._events else None
        event.link(previous)
        self._events.append(event)

    def read_since(self, since: datetime | None = None) -> list[AuditEvent]:
        if since is None:
            return list(self._events)
        return [event for event in self._events if event.occurred_at >= since]

    def count(self) -> int:
        return len(self._events)


def reconstruct_timeline(events: list[AuditEvent]) -> str:
    """Operator-facing reconstruction: who did what, under what authority,
    what executed, what evidence resulted, and why the firm concluded as it
    did. Returns a deterministic, secret-free text timeline."""
    lines: list[str] = []
    for event in events:
        principal = event.principal_id or "system"
        engagement = event.engagement_id or "-"
        lines.append(
            f"[{event.occurred_at.isoformat()}] {event.audit_event_id} | {engagement} | "
            f"{principal} | {event.kind.value} | {event.summary}"
        )
    return "\n".join(lines)
