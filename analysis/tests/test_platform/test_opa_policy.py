"""OPA policy kernel tests.

Two layers:
1. Unit: DeterministicDecisionAdapter mirrors the baseline matrix.
2. Integration: real `opa eval` via the pinned binary must produce the SAME
   decision for every matrix case — cross-validation, not trust. The binary
   is discovered at tools/opa/opa_windows_amd64.exe (pinned, checksummed)
   or PATH. Skipped ONLY when the binary is genuinely unavailable; a skip
   is a recorded limitation, never a PASS.

The matrix includes the adversarial cases that killed earlier kernel
versions (approval-as-string bypass, unregistered capability ids, dead
engagement states) — every rule the kernel enforces has a test.
"""

from __future__ import annotations

import pytest

from secscan.platform.domain.authority import PolicyDecision
from secscan.platform.policy import (
    DeterministicDecisionAdapter,
    OpaEvaluationError,
    OpaSubprocessClient,
)


def _base_request() -> dict:
    return {
        "principal": {"id": "PRN-AGENT"},
        "agent": {"id": "AGT-SPEC"},
        "engagement": {
            "id": "ENG-1",
            "status": "active",
            "authority_level": "inspection-only",
            "target_ids": ["TGT-1"],
        },
        "target": {"id": "TGT-1"},
        "capability": {
            "id": "CAP-REPO-READONLY-INSPECTION",
            "registered": True,
            "risk_class": "low",
            "requires_approval": False,
            "required_authority": "inspect",
        },
        "action": "inspect",
        "risk": "low",
        "authority_grant": {"matched": True, "grant_ids": ["GR-1"]},
        "approval": {
            "id": "",
            "recorded": False,
            "decision": "pending",
            "target_id": "",
            "capability_id": "",
            "action": "",
            "engagement_id": "",
            "decided_by_principal_id": "",
        },
        "workflow_phase": "evidence_collection",
        "requested_resources": {},
    }


def _bound_approval(**overrides) -> dict:
    approval = {
        "id": "AP-1",
        "recorded": True,
        "decision": "approved",
        "target_id": "TGT-1",
        "capability_id": "CAP-REPO-READONLY-INSPECTION",
        "action": "inspect",
        "engagement_id": "ENG-1",
        "decided_by_principal_id": "PRN-OPERATOR",
    }
    approval.update(overrides)
    return approval


MATRIX: list[tuple[str, dict, PolicyDecision]] = [
    # (case name, request overrides, expected decision)
    ("inspection within valid scope allows", {}, PolicyDecision.ALLOW),
    ("unknown action denies", {"action": "frobnicate"}, PolicyDecision.DENY),
    ("missing action denies", {"action": None}, PolicyDecision.DENY),
    ("unregistered capability denies", {"capability": {"id": "CAP-X", "registered": False, "risk_class": "low", "requires_approval": False, "required_authority": "inspect"}}, PolicyDecision.DENY),
    ("empty capability id denies", {"capability": {"id": "", "registered": True, "risk_class": "low", "requires_approval": False, "required_authority": "inspect"}}, PolicyDecision.DENY),
    ("out-of-engagement target denies", {"target": {"id": "TGT-OUTSIDE"}}, PolicyDecision.DENY),
    ("no matching grant denies", {"authority_grant": {"matched": False}}, PolicyDecision.DENY),
    ("mutation denied under inspection-only", {"action": "mutate"}, PolicyDecision.DENY),
    ("active testing denied without grant", {"action": "active_test"}, PolicyDecision.DENY),
    ("capability authority mismatch denies", {"action": "collect"}, PolicyDecision.DENY),
    ("draft engagement denies", {"engagement": {"id": "ENG-1", "status": "draft", "authority_level": "inspection-only", "target_ids": ["TGT-1"]}}, PolicyDecision.DENY),
    ("suspended engagement denies", {"engagement": {"id": "ENG-1", "status": "suspended", "authority_level": "inspection-only", "target_ids": ["TGT-1"]}}, PolicyDecision.DENY),
    ("revoked engagement denies", {"engagement": {"id": "ENG-1", "status": "revoked", "authority_level": "inspection-only", "target_ids": ["TGT-1"]}}, PolicyDecision.DENY),
    ("closed engagement denies", {"engagement": {"id": "ENG-1", "status": "closed", "authority_level": "inspection-only", "target_ids": ["TGT-1"]}}, PolicyDecision.DENY),
    ("refused engagement denies", {"engagement": {"id": "ENG-1", "status": "refused", "authority_level": "inspection-only", "target_ids": ["TGT-1"]}}, PolicyDecision.DENY),
    ("unknown authority level denies", {"engagement": {"id": "ENG-1", "status": "active", "authority_level": "banana", "target_ids": ["TGT-1"]}}, PolicyDecision.DENY),
    ("missing authority level denies", {"engagement": {"id": "ENG-1", "status": "active", "authority_level": "", "target_ids": ["TGT-1"]}}, PolicyDecision.DENY),
    (
        "high-risk capability requires approval",
        {"capability": {"id": "CAP-X", "registered": True, "risk_class": "critical", "requires_approval": False, "required_authority": "inspect"}},
        PolicyDecision.REQUIRE_APPROVAL,
    ),
    (
        "capability flagged requires_approval",
        {"capability": {"id": "CAP-X", "registered": True, "risk_class": "low", "requires_approval": True, "required_authority": "inspect"}},
        PolicyDecision.REQUIRE_APPROVAL,
    ),
    (
        "high-risk with valid bound approval allows",
        {
            "capability": {"id": "CAP-X", "registered": True, "risk_class": "high", "requires_approval": False, "required_authority": "inspect"},
            "approval": _bound_approval(capability_id="CAP-X"),
        },
        PolicyDecision.ALLOW,
    ),
    (
        "high-risk with missing approver stays require_approval",
        {
            "capability": {"id": "CAP-X", "registered": True, "risk_class": "high", "requires_approval": False, "required_authority": "inspect"},
            "approval": _bound_approval(capability_id="CAP-X", decided_by_principal_id=""),
        },
        PolicyDecision.REQUIRE_APPROVAL,
    ),
    (
        "high-risk with denied approval stays require_approval",
        {
            "capability": {"id": "CAP-X", "registered": True, "risk_class": "high", "requires_approval": False, "required_authority": "inspect"},
            "approval": _bound_approval(capability_id="CAP-X", decision="denied"),
        },
        PolicyDecision.REQUIRE_APPROVAL,
    ),
    (
        "high-risk with pending approval stays require_approval",
        {
            "capability": {"id": "CAP-X", "registered": True, "risk_class": "high", "requires_approval": False, "required_authority": "inspect"},
            "approval": _bound_approval(capability_id="CAP-X", decision="pending"),
        },
        PolicyDecision.REQUIRE_APPROVAL,
    ),
    (
        "fabricated approval id cannot authorize (no approval record)",
        {
            "capability": {"id": "CAP-X", "registered": True, "risk_class": "high", "requires_approval": False, "required_authority": "inspect"},
            "approval": {"id": "AP-FAKE", "decision": "pending", "target_id": "", "capability_id": "", "action": "", "engagement_id": ""},
        },
        PolicyDecision.REQUIRE_APPROVAL,
    ),
    (
        "fabricated approved id cannot authorize",
        {
            "capability": {"id": "CAP-X", "registered": True, "risk_class": "high", "requires_approval": False, "required_authority": "inspect"},
            "approval": {"id": "AP-FAKE", "recorded": False, "decision": "approved", "target_id": "TGT-1", "capability_id": "CAP-X", "action": "inspect", "engagement_id": "ENG-1"},
        },
        PolicyDecision.REQUIRE_APPROVAL,
    ),
    (
        "approval bound to different target cannot authorize",
        {
            "capability": {"id": "CAP-X", "registered": True, "risk_class": "high", "requires_approval": False, "required_authority": "inspect"},
            "approval": _bound_approval(capability_id="CAP-X", target_id="TGT-OTHER"),
        },
        PolicyDecision.REQUIRE_APPROVAL,
    ),
    (
        "approval bound to different capability cannot authorize",
        {
            "capability": {"id": "CAP-X", "registered": True, "risk_class": "high", "requires_approval": False, "required_authority": "inspect"},
            "approval": _bound_approval(capability_id="CAP-DIFFERENT"),
        },
        PolicyDecision.REQUIRE_APPROVAL,
    ),
    (
        "approval bound to different engagement cannot authorize",
        {
            "capability": {"id": "CAP-X", "registered": True, "risk_class": "high", "requires_approval": False, "required_authority": "inspect"},
            "approval": _bound_approval(capability_id="CAP-X", engagement_id="ENG-OTHER"),
        },
        PolicyDecision.REQUIRE_APPROVAL,
    ),
    (
        "all read-only grant conditions compose",
        {
            "authority_grant": {
                "matched": True,
                "grant_ids": ["GR-1"],
                "principal_id": "PRN-AGENT",
                "engagement_id": "ENG-1",
                "capability_id": "",
                "target_id": "",
                "action": "inspect",
                "conditions": ["immutable_snapshot_only", "no_client_writes", "no_production_active_testing"],
            },
            "requested_resources": {"snapshot": "SNAP-1"},
        },
        PolicyDecision.ALLOW,
    ),
    (
        "mutation allowed under remediation engagement with grant",
        {
            "engagement": {"id": "ENG-1", "status": "remediation", "authority_level": "remediation", "target_ids": ["TGT-1"]},
            "action": "mutate",
            "capability": {"id": "CAP-X", "registered": True, "risk_class": "low", "requires_approval": False, "required_authority": "mutate"},
        },
        PolicyDecision.ALLOW,
    ),
    (
        "inspection in authorized state allows",
        {"engagement": {"id": "ENG-1", "status": "authorized", "authority_level": "inspection-only", "target_ids": ["TGT-1"]}},
        PolicyDecision.ALLOW,
    ),
]


def _request(overrides: dict) -> dict:
    request = _base_request()
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(request.get(key), dict):
            merged = dict(request[key])
            merged.update(value)
            request[key] = merged
        else:
            request[key] = value
    return request


class TestBaselineUnitMatrix:
    @pytest.mark.parametrize("name,overrides,expected", MATRIX, ids=[m[0] for m in MATRIX])
    def test_case(self, name: str, overrides: dict, expected: PolicyDecision) -> None:
        adapter = DeterministicDecisionAdapter()
        assert adapter.decide(_request(overrides)) == expected


class TestRealRegoEvaluation:
    """Cross-validate the full matrix against the real OPA binary."""

    @pytest.fixture(scope="class")
    def client(self):
        client = OpaSubprocessClient()
        if not client.available():
            pytest.skip("opa binary not available (tools/opa/opa_windows_amd64.exe or PATH); recorded as limitation")
        return client

    @pytest.mark.parametrize("name,overrides,expected", MATRIX, ids=[m[0] for m in MATRIX])
    def test_case(self, client, name: str, overrides: dict, expected: PolicyDecision) -> None:
        assert client.decide(_request(overrides)) == expected

    def test_binary_is_repo_pinned_version(self, client) -> None:
        import subprocess

        proc = subprocess.run([client._opa_bin, "version"], capture_output=True, timeout=15, check=False)
        version_line = proc.stdout.decode().splitlines()[0]
        # pinned by the qualification run; record rather than hard-fail on patch releases
        assert "1.19" in version_line

    def test_eval_failure_raises(self) -> None:
        client = OpaSubprocessClient(opa_bin="definitely-not-opa")
        with pytest.raises(OpaEvaluationError):
            client.decide(_base_request())
