"""OPA policy kernel adapters.

- `OpaSubprocessClient`: real Rego evaluation via the pinned `opa` binary.
  This is the integration adapter; it is what qualification must exercise.
- `DeterministicDecisionAdapter`: in-memory mirror of the baseline rules,
  for unit tests ONLY. It never counts as OPA integration PASS.

Decision envelope: PolicyDecision (allow/deny/require_approval).
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import httpx

from secscan.platform.domain.authority import PolicyDecision

_PINNED_MINOR = "1.19"  # tools/opa/PIN.txt
KERNEL_PATH = Path(__file__).parent / "kernel.rego"

DEFAULT_OPA_BIN = "opa"


class OpaEvaluationError(RuntimeError):
    """The opa binary could not produce a decision."""


class OpaSubprocessClient:
    """Real OPA evaluation via `opa eval` subprocess."""

    def __init__(self, opa_bin: str | None = None, kernel_path: Path | str | None = None) -> None:
        self._opa_bin = opa_bin or _discover_opa()
        self._kernel_path = Path(kernel_path) if kernel_path else KERNEL_PATH

    def available(self) -> bool:
        opa = self._opa_bin
        if opa is None:
            return False
        try:
            proc = subprocess.run(
                [opa, "version"],
                capture_output=True,
                timeout=15,
                check=False,
            )
            return proc.returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    def decide(self, request: dict[str, Any]) -> PolicyDecision:
        if not self.available():
            raise OpaEvaluationError("opa binary unavailable")
        opa = self._opa_bin
        if opa is None:
            raise OpaEvaluationError("opa binary unavailable")
        input_json = json.dumps(request)
        try:
            proc = subprocess.run(
                [
                    opa,
                    "eval",
                    "--stdin-input",
                    "--format",
                    "json",
                    "-d",
                    str(self._kernel_path),
                    "data.secscan.authorize.result",
                ],
                input=input_json.encode("utf-8"),
                capture_output=True,
                timeout=30,
                check=False,
            )
        except OSError as exc:
            raise OpaEvaluationError(f"failed to run opa: {exc}") from exc
        if proc.returncode != 0:
            raise OpaEvaluationError(f"opa eval failed: {proc.stderr.decode(errors='replace')[:400]}")
        try:
            payload = json.loads(proc.stdout)
            result = payload["result"][0]["expressions"][0]["value"]
        except (KeyError, IndexError, json.JSONDecodeError) as exc:
            # Undefined envelope or malformed output: fail closed.
            if proc.returncode == 0:
                return PolicyDecision.DENY
            raise OpaEvaluationError(f"unexpected opa output: {proc.stdout[:200]!r}") from exc
        decision = str(result.get("decision", "deny")).lower()
        try:
            return PolicyDecision(decision)
        except ValueError:
            return PolicyDecision.DENY  # unknown decision output fails closed


class HostedOpaHttpClient:
    """Fail-closed HTTP adapter for the hosted OPA decision endpoint."""

    def __init__(
        self,
        endpoint: str,
        *,
        policy_digest: str,
        shared_secret: str,
        timeout_seconds: float = 10.0,
        client: httpx.Client | None = None,
    ) -> None:
        if not endpoint.strip() or not policy_digest.strip() or not shared_secret.strip():
            raise ValueError("hosted OPA requires endpoint, policy digest, and server credential")
        self._endpoint = endpoint.rstrip("/")
        self._policy_digest = policy_digest.strip()
        self._headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Secscan-OPA-Secret": shared_secret,
            "X-Secscan-OPA-Policy-Digest": self._policy_digest,
        }
        self._timeout = timeout_seconds
        self._client = client

    def available(self) -> bool:
        return True

    def decide(self, request: dict[str, Any]) -> PolicyDecision:
        client = self._client or httpx.Client(timeout=self._timeout)
        close_client = self._client is None
        try:
            response = client.post(self._endpoint, json={"input": request}, headers=self._headers)
            if response.status_code != 200:
                raise OpaEvaluationError("hosted OPA returned a non-success response")
            body = response.json()
            response_digest = response.headers.get("X-Secscan-OPA-Policy-Digest", "")
            if isinstance(body, dict):
                response_digest = response_digest or str(body.get("policy_digest", ""))
            if response_digest != self._policy_digest:
                raise OpaEvaluationError("hosted OPA policy digest mismatch")
            value = body.get("result") if isinstance(body, dict) else None
            if isinstance(value, list):
                value = value[0].get("result") if value and isinstance(value[0], dict) else None
            if isinstance(value, dict) and "expressions" in value:
                expressions = value.get("expressions")
                value = expressions[0].get("value") if expressions and isinstance(expressions[0], dict) else None
            if not isinstance(value, dict):
                raise OpaEvaluationError("hosted OPA returned an invalid decision envelope")
            try:
                return PolicyDecision(str(value.get("decision", "deny")).lower())
            except ValueError:
                return PolicyDecision.DENY
        except httpx.HTTPError as exc:
            raise OpaEvaluationError("hosted OPA request failed") from exc
        except (ValueError, TypeError, KeyError) as exc:
            raise OpaEvaluationError("hosted OPA returned invalid JSON") from exc
        finally:
            if close_client:
                client.close()


def _discover_opa() -> str | None:
    """Find the pinned repo binary (tools/opa/opa_windows_amd64.exe) or PATH opa."""
    repo_tools = Path(__file__).resolve().parents[5] / "tools" / "opa" / "opa_windows_amd64.exe"
    if repo_tools.is_file():
        return str(repo_tools)
    found = shutil.which("opa")
    return found


class DeterministicDecisionAdapter:
    """In-memory baseline mirror — unit-test double ONLY.

    Mirrors kernel.rego semantics for tests that must not depend on the
    binary. Qualification requires real Rego evaluation; this adapter never
    constitutes an integration PASS.
    """

    _KNOWN_ACTIONS = {"inspect", "collect", "active_test", "mutate", "remediate"}
    _MUTATION = {"mutate", "remediate", "active_test"}
    _HIGH_RISK = {"critical", "high"}
    _WORKING_STATUSES = {
        "authorized",
        "active",
        "evidence_collection",
        "analysis",
        "adjudication",
        "reporting",
        "remediation",
    }

    def decide(self, request: dict[str, Any]) -> PolicyDecision:
        action = request.get("action")
        capability = request.get("capability", {})
        engagement = request.get("engagement", {})
        target = request.get("target", {})
        grant = request.get("authority_grant", {})
        approval = request.get("approval", {})

        # unknown action / unregistered capability => DENY
        if not action or action not in self._KNOWN_ACTIONS:
            return PolicyDecision.DENY
        if not capability.get("id") or capability.get("registered") is not True:
            return PolicyDecision.DENY
        # non-working engagement status or unknown authority level => DENY
        if engagement.get("status") not in self._WORKING_STATUSES:
            return PolicyDecision.DENY
        if engagement.get("authority_level") not in {"inspection-only", "remediation"}:
            return PolicyDecision.DENY
        # out-of-engagement target => DENY
        if target.get("id") not in engagement.get("target_ids", []):
            return PolicyDecision.DENY
        # no matching active grant or malformed grant binding => DENY
        if not grant.get("matched"):
            return PolicyDecision.DENY
        grant_ids = grant.get("grant_ids", [])
        if not isinstance(grant_ids, list) or len(grant_ids) != 1 or not grant_ids[0]:
            return PolicyDecision.DENY
        if grant.get("principal_id") and grant.get("principal_id") != request.get("principal", {}).get("id"):
            return PolicyDecision.DENY
        if grant.get("engagement_id") and grant.get("engagement_id") != engagement.get("id"):
            return PolicyDecision.DENY
        if grant.get("capability_id") and grant.get("capability_id") != capability.get("id"):
            return PolicyDecision.DENY
        if grant.get("target_id") and grant.get("target_id") != target.get("id"):
            return PolicyDecision.DENY
        if grant.get("action") and grant.get("action") != action:
            return PolicyDecision.DENY
        conditions = set(grant.get("conditions", []))
        if "immutable_snapshot_only" in conditions and not request.get("requested_resources", {}).get("snapshot"):
            return PolicyDecision.DENY
        if "no_client_writes" in conditions and action in self._MUTATION:
            return PolicyDecision.DENY
        if "no_production_active_testing" in conditions and action == "active_test":
            return PolicyDecision.DENY
        # mutation without remediation engagement authority => DENY        if action in self._MUTATION and engagement.get("authority_level") != "remediation":
            return PolicyDecision.DENY
        # capability authority mismatch => DENY
        required = capability.get("required_authority") or ""
        if required and action != required:
            return PolicyDecision.DENY
        # a valid approval is recorded, decided "approved", and bound to this exact request
        approved = (
            approval.get("recorded") is True
            and bool(approval.get("id"))
            and approval.get("decision") == "approved"
            and bool(approval.get("decided_by_principal_id"))
            and approval.get("target_id") == target.get("id")
            and approval.get("capability_id") == capability.get("id")
            and approval.get("action") == action
            and approval.get("engagement_id") == engagement.get("id")
        )
        high_risk = (
            capability.get("risk_class") in self._HIGH_RISK
            or request.get("risk") in self._HIGH_RISK
            or bool(capability.get("requires_approval"))
        )
        if high_risk and not approved:
            return PolicyDecision.REQUIRE_APPROVAL
        return PolicyDecision.ALLOW
