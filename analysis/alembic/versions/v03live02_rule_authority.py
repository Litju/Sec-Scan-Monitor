"""Persist live rule ownership and backfill canonical rule bindings."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

import sqlalchemy as sa

from alembic import op

revision = "v03live02"
down_revision = "v03live01"
branch_labels = None
depends_on = None


_RULE_FIELDS = (
    "rule_id",
    "version",
    "title",
    "rule_type",
    "content_digest",
    "source",
    "source_reference",
    "event_schema",
    "ocsf_version",
    "supported_source_families",
    "severity",
    "confidence",
    "confidence_metadata",
    "attack_mappings",
    "atlas_mappings",
    "references",
    "predicates",
    "correlation_keys",
    "window_seconds",
    "threshold",
    "status",
    "evaluation_metadata",
)


def _digest(row: Mapping[str, Any], *, owner: str | None = None) -> str:
    values = {field: row[field] for field in _RULE_FIELDS}
    if owner is not None:
        values["owner"] = owner
    return hashlib.sha256(
        json.dumps(values, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()


def _backfill(*, include_owner: bool) -> None:
    bind = op.get_bind()
    columns = ", ".join(
        f'"{field}"' for field in ((*_RULE_FIELDS, "owner") if include_owner else _RULE_FIELDS)
    )
    rows = bind.execute(sa.text(f"SELECT {columns} FROM detection_rule_versions")).mappings().all()
    for row in rows:
        digest = _digest(row, owner=str(row["owner"]) if include_owner else None)
        bind.execute(
            sa.text(
                "UPDATE detection_rule_versions "
                "SET canonical_digest = :canonical_digest "
                "WHERE rule_id = :rule_id AND version = :version"
            ),
            {"canonical_digest": digest, "rule_id": row["rule_id"], "version": row["version"]},
        )


def upgrade() -> None:
    op.add_column(
        "detection_rule_versions",
        sa.Column("owner", sa.String(64), nullable=False, server_default="SecScanMonitor"),
    )
    _backfill(include_owner=True)


def downgrade() -> None:
    _backfill(include_owner=False)
    op.drop_column("detection_rule_versions", "owner")
