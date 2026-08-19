"""Capability registry tests: registration, versioning, unknown-capability denial."""

from __future__ import annotations

import pytest

from secscan.platform.capabilities import (
    FOUNDATION_CAPABILITIES,
    CapabilityRegistry,
    UnknownCapabilityError,
)
from secscan.platform.domain.authority import Action
from secscan.platform.domain.capability import (
    CapabilityManifest,
    RiskClass,
)
from secscan.platform.domain.ids import CapabilityId


def test_foundation_capabilities_are_safe_by_construction() -> None:
    for manifest in FOUNDATION_CAPABILITIES:
        assert manifest.risk_class in {RiskClass.INFO, RiskClass.LOW}
        assert manifest.required_authority in {Action.INSPECT.value, Action.COLLECT.value}
        assert manifest.required_authority not in {Action.MUTATE.value, Action.REMEDIATE.value, Action.ACTIVE_TEST.value}
        assert manifest.tool_identity
        assert manifest.tool_version


def test_unknown_capability_denied() -> None:
    registry = CapabilityRegistry()
    with pytest.raises(UnknownCapabilityError):
        registry.get(CapabilityId("CAP-NOT-REGISTERED"))


def test_version_resolution() -> None:
    registry = CapabilityRegistry()
    registry.register(
        CapabilityManifest(
            capability_id=CapabilityId("CAP-TEST"),
            version="2.0.0",
            description="newer",
            risk_class=RiskClass.INFO,
            required_authority=Action.INSPECT.value,
        )
    )
    newest = registry.get(CapabilityId("CAP-TEST"))
    assert newest.version == "2.0.0"
    with pytest.raises(UnknownCapabilityError):
        registry.get(CapabilityId("CAP-TEST"), version="1.0.0")
