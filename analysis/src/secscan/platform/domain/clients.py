"""Firm, client, target, principal aggregates."""

from __future__ import annotations

from enum import Enum

from pydantic import Field

from secscan.platform.domain.common import DomainModel
from secscan.platform.domain.ids import ClientId, PrincipalId, TargetId


class TargetKind(str, Enum):
    REPOSITORY = "repository"
    WORKSPACE = "workspace"
    ARTIFACT_SET = "artifact-set"
    SYSTEM = "system"
    DESIGN = "design"


class Firm(DomainModel):
    """The firm itself (singleton). Charter pin and severity scale are fixed."""

    charter_version: str = "firm-v1"
    platform_version: str = "platform-v1"


class Client(DomainModel):
    """External party hiring the firm."""

    client_id: ClientId
    name: str
    contact: str | None = None


class Target(DomainModel):
    """Repository/workspace/artifact set under review. Declared in contract scope."""

    target_id: TargetId
    kind: TargetKind
    name: str
    description: str = ""


class Principal(DomainModel):
    """WHO acts: operator, agent persona, or workflow."""

    principal_id: PrincipalId
    kind: str = Field(description="operator | agent | workflow | system")
    name: str
    manifest_ref: str | None = None
