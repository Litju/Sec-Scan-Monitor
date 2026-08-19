"""Pinned scanner capability adapters for the first external engagement.

The adapters are intentionally small: they translate a typed capability
manifest into a command accepted by the sandbox port, then turn untrusted
stdout/stderr into sanitized, content-addressable evidence. They never create
observations or findings and they never execute on the host.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from secscan.platform.capabilities import CapabilityRegistry
from secscan.platform.domain.capability import CapabilityManifest
from secscan.platform.sandbox import SandboxExecutionService
from secscan.sanitize.filters import scrub_text


@dataclass(frozen=True)
class ScannerTelemetry:
    """Bounded, secret-safe telemetry for one controlled scanner attempt."""

    capability_id: str
    service_run_id: str
    scanner_identity: str
    scanner_version: str
    sandbox_backend: str
    started_at: str
    ended_at: str
    duration_ms: int
    exit_code: int
    outcome: str
    timeout: bool
    error_class: str | None
    input_digest: str
    output_digest: str
    result_count: int
    cache_manifest_digest: str | None = None
    cache_provenance: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "capability_id": self.capability_id,
            "service_run_id": self.service_run_id,
            "scanner_identity": self.scanner_identity,
            "scanner_version": self.scanner_version,
            "sandbox_backend": self.sandbox_backend,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "duration_ms": self.duration_ms,
            "exit_code": self.exit_code,
            "outcome": self.outcome,
            "timeout": self.timeout,
            "error_class": self.error_class,
            "input_digest": self.input_digest,
            "output_digest": self.output_digest,
            "result_count": self.result_count,
            "cache_manifest_digest": self.cache_manifest_digest,
            "cache_provenance": self.cache_provenance,
        }


@dataclass(frozen=True)
class ScannerExecution:
    """Safe result of one sandboxed scanner invocation."""

    capability: CapabilityManifest
    sandbox_id: str
    exit_code: int
    status: str
    evidence_bytes: bytes
    secret_observations: list[dict[str, str]]
    stderr_redacted: bool
    telemetry: ScannerTelemetry


_SECRET_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----.*?-----END [A-Z ]+PRIVATE KEY-----", re.S),
    re.compile(r"(?i)(?:api[_-]?key|access[_-]?token|client[_-]?secret|password|secret|authorization)\s*[:=]\s*['\"]?[^\s,'\"}]+"),
    re.compile(r"\b(?:sk|pk|ghp|github_pat|glpat|xoxb|xoxp)[_-][A-Za-z0-9_\-]{12,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
)
_ANSI_ESCAPE_PATTERN = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")

_MAX_SCANNER_OUTPUT_BYTES = 1024 * 1024


def _bounded_text(value: str) -> str:
    raw = value.encode("utf-8", errors="replace")
    if len(raw) <= _MAX_SCANNER_OUTPUT_BYTES:
        return value
    return raw[:_MAX_SCANNER_OUTPUT_BYTES].decode("utf-8", errors="replace") + "\n[scanner output truncated]"


def _redact_text(value: str) -> tuple[str, list[str]]:
    sanitized = _ANSI_ESCAPE_PATTERN.sub("", value)
    notes = ["terminal control sequence redacted"] if sanitized != value else []
    sanitized, scrub_notes = scrub_text(sanitized)
    notes.extend(scrub_notes)
    for pattern in _SECRET_PATTERNS:
        sanitized, count = pattern.subn("[REDACTED]", sanitized)
        if count:
            notes.append("scanner secret-like content redacted")
    return sanitized, notes


def _redact_json(value: Any, notes: list[str]) -> Any:
    if isinstance(value, dict):
        return {str(key): _redact_json(item, notes) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_json(item, notes) for item in value]
    if isinstance(value, str):
        redacted, found = _redact_text(value)
        notes.extend(found)
        return redacted.replace("/src", "[target]")
    return value


def _safe_payload(
    stdout: str,
    stderr: str,
    exit_code: int,
) -> tuple[dict[str, Any], list[dict[str, str]], bool, bool]:
    notes: list[str] = []
    bounded_stdout = _bounded_text(stdout)
    bounded_stderr = _bounded_text(stderr)
    malformed = bool(bounded_stdout.strip())
    try:
        parsed: Any = json.loads(bounded_stdout) if bounded_stdout.strip() else None
    except json.JSONDecodeError:
        parsed = None
    if parsed is None:
        safe_stdout, stdout_notes = _redact_text(bounded_stdout)
        safe_stderr, stderr_notes = _redact_text(bounded_stderr)
        notes.extend(stdout_notes)
        notes.extend(stderr_notes)
        payload: dict[str, Any] = {
            "stdout": safe_stdout,
            "stderr": safe_stderr,
        }
    else:
        malformed = False
        payload = {"result": _redact_json(parsed, notes)}
        safe_stderr, stderr_notes = _redact_text(bounded_stderr)
        notes.extend(stderr_notes)
        if safe_stderr:
            payload["stderr"] = safe_stderr
    secret_observations = [
        {
            "secret_class": "scanner-redacted-content",
            "redacted_location": "scanner output",
            "detection_source": "SecScanMonitor sanitizer",
        }
    ] if notes else []
    payload["exit_code"] = exit_code
    payload["sanitization_notes"] = sorted(set(notes))
    serialized = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    # A second pass is a hard stop: no evidence bytes are persisted if the
    # sanitizer still recognizes a forbidden value.
    for pattern in _SECRET_PATTERNS:
        if pattern.search(serialized):
            raise ValueError("scanner output still contains secret-like content after sanitization")
    return payload, secret_observations, bool(notes), malformed


def _snapshot_digest(snapshot_path: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(item for item in snapshot_path.rglob("*") if item.is_file()):
        digest.update(path.relative_to(snapshot_path).as_posix().encode("utf-8", errors="replace"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _result_count(payload: dict[str, Any]) -> int:
    result = payload.get("result")
    if isinstance(result, list):
        return len(result)
    if isinstance(result, dict):
        if "results" in result and isinstance(result.get("results"), list):
            results = result["results"]
            if any(isinstance(group, dict) and "packages" in group for group in results):
                return sum(
                    len(package.get("vulnerabilities") or [])
                    for group in results
                    if isinstance(group, dict)
                    for package in (group.get("packages") or [])
                    if isinstance(package, dict)
                )
            return len(results)
        for key in ("results", "findings", "Results"):
            values = result.get(key)
            if isinstance(values, list):
                if key == "Results":
                    return sum(
                        sum(
                            len(item.get(name) or [])
                            for name in ("Vulnerabilities", "Misconfigurations", "Secrets", "Licenses")
                            if isinstance(item, dict)
                        )
                        for item in values
                    )
                return len(values)
    return 0


def _normalize_scanner_result(capability_id: str, result: Any) -> Any:
    """Canonicalize nullable clean-result arrays without accepting bad shapes."""
    normalized = deepcopy(result)
    if capability_id == "CAP-SECRETS-GITLEAKS":
        if not isinstance(normalized, list) or not all(isinstance(item, dict) for item in normalized):
            raise ValueError("Gitleaks output must be a list of objects")
        return normalized
    if capability_id == "CAP-REPO-TRIVY":
        if not isinstance(normalized, dict):
            raise ValueError("Trivy output must be an object")
        # Trivy omits Results entirely for a clean filesystem scan when no
        # report sections were emitted. That is a valid clean result, not a
        # malformed payload, but an arbitrary object is still malformed.
        if "Results" not in normalized and not any(
            key in normalized for key in ("SchemaVersion", "Trivy", "ReportID", "CreatedAt", "ArtifactName", "ArtifactType")
        ):
            raise ValueError("Trivy output lacks a recognized clean-result envelope")
        results = normalized.setdefault("Results", [])
        if results is None:
            normalized["Results"] = []
            results = normalized["Results"]
        if not isinstance(results, list) or not all(isinstance(item, dict) for item in results):
            raise ValueError("Trivy Results must be a list of objects")
        for item in results:
            for key in ("Vulnerabilities", "Misconfigurations", "Secrets", "Licenses"):
                if key not in item or item[key] is None:
                    item[key] = []
                elif not isinstance(item[key], list):
                    raise ValueError(f"Trivy {key} must be a list")
        return normalized
    if capability_id == "CAP-SCA-OSV":
        if not isinstance(normalized, dict) or "results" not in normalized:
            raise ValueError("OSV output must contain results")
        results = normalized["results"]
        if results is None:
            normalized["results"] = []
            results = normalized["results"]
        if not isinstance(results, list) or not all(isinstance(item, dict) for item in results):
            raise ValueError("OSV results must be a list of objects")
        for item in results:
            if "packages" in item and item["packages"] is None:
                item["packages"] = []
            if "packages" in item and not isinstance(item["packages"], list):
                raise ValueError("OSV packages must be a list")
            for package in item.get("packages") or []:
                if not isinstance(package, dict):
                    raise ValueError("OSV packages must contain objects")
                if "vulnerabilities" in package and package["vulnerabilities"] is None:
                    package["vulnerabilities"] = []
                if "vulnerabilities" in package and not isinstance(package["vulnerabilities"], list):
                    raise ValueError("OSV vulnerabilities must be a list")
        return normalized
    if capability_id == "CAP-SAST-SEMGREP":
        if not isinstance(normalized, dict) or "results" not in normalized:
            raise ValueError("Semgrep output must contain results")
        if normalized["results"] is None:
            normalized["results"] = []
        if not isinstance(normalized["results"], list):
            raise ValueError("Semgrep results must be a list")
        return normalized
    return normalized


def _scanner_output_schema_valid(capability_id: str, payload: dict[str, Any]) -> bool:
    """Validate the small output envelope each pinned scanner promises."""
    try:
        _normalize_scanner_result(capability_id, payload.get("result"))
    except (TypeError, ValueError):
        return False
    return True


def _cache_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(item for item in root.rglob("*") if item.is_file() and item.name != "manifest.json"):
        digest.update(path.relative_to(root).as_posix().encode("utf-8", errors="replace"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _read_cache_manifest(root: Path) -> tuple[str, str]:
    manifest_path = root / "manifest.json"
    if not root.is_dir() or not manifest_path.is_file():
        raise ValueError("scanner cache requires a canonical manifest.json")
    try:
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("scanner cache manifest is unreadable") from exc
    expected_digest = str(raw.get("root_digest", "")) if isinstance(raw, dict) else ""
    provenance = str(raw.get("provenance", "")) if isinstance(raw, dict) else ""
    if not re.fullmatch(r"[0-9a-f]{64}", expected_digest) or not provenance:
        raise ValueError("scanner cache manifest lacks digest or provenance")
    if _cache_digest(root) != expected_digest:
        raise ValueError("scanner cache digest does not match its manifest")
    return expected_digest, provenance


@dataclass(frozen=True)
class ScannerAdapter:
    """One registered scanner bound to a sandbox execution service."""

    manifest: CapabilityManifest
    sandbox: SandboxExecutionService
    command: tuple[str, ...]
    environment: dict[str, str]
    config_path: Path | None = None
    extra_mounts: tuple[tuple[Path, str], ...] = ()
    cache_root: Path | None = None
    cache_manifest_digest: str | None = None
    cache_provenance: str = ""

    def execute(self, snapshot_path: Path, *, service_run_id: str = "") -> ScannerExecution:
        if not snapshot_path.is_dir():
            raise FileNotFoundError(f"immutable snapshot does not exist: {snapshot_path}")
        mounts: list[tuple[str, str, bool]] = [(str(snapshot_path.resolve()), "/src", True)]
        if self.config_path is not None:
            if not self.config_path.is_file():
                raise FileNotFoundError(f"scanner configuration does not exist: {self.config_path}")
            mounts.append((str(self.config_path.resolve()), "/cfg/scanner.yml", True))
        for host_path, container_path in self.extra_mounts:
            if not host_path.exists():
                raise FileNotFoundError(f"scanner data cache does not exist: {host_path}")
            mounts.append((str(host_path.resolve()), container_path, True))
        if self.extra_mounts:
            if self.cache_root is None or not self.cache_manifest_digest or not self.cache_provenance:
                raise ValueError("scanner cache mount is missing canonical provenance")
            if _cache_digest(self.cache_root) != self.cache_manifest_digest:
                raise ValueError("scanner cache changed after manifest validation")
        input_digest = _snapshot_digest(snapshot_path)
        started_at = datetime.now(UTC)
        started_monotonic = time.monotonic()
        result = self.sandbox.execute(
            capability=self.manifest,
            command=list(self.command),
            mounts=mounts,
            environment=self.environment,
            working_dir="/src",
        )
        ended_at = datetime.now(UTC)
        payload, secret_observations, redacted, malformed = _safe_payload(
            result.stdout,
            result.stderr,
            result.exit_code,
        )
        try:
            payload["result"] = _normalize_scanner_result(
                str(self.manifest.capability_id),
                payload.get("result"),
            )
        except (TypeError, ValueError):
            payload["sanitization_notes"] = sorted({
                *payload.get("sanitization_notes", []),
                "scanner output schema mismatch",
            })
            malformed = True
        result_count = _result_count(payload)
        if result.timed_out:
            status = "timed_out"
            outcome = "TIMEOUT"
            error_class = "sandbox_timeout"
        elif malformed:
            status = "malformed_output"
            outcome = "MALFORMED_OUTPUT"
            error_class = "malformed_scanner_output"
        elif result.exit_code != 0 and result_count > 0:
            status = "succeeded_with_findings"
            outcome = "FINDINGS"
            error_class = None
        elif result.exit_code == 0:
            status = "succeeded"
            outcome = "SUCCESS"
            error_class = None
        else:
            status = "not_qualified"
            outcome = "FAILED"
            error_class = "scanner_nonzero_exit"
        payload.update(
            {
                "capability_id": str(self.manifest.capability_id),
                "capability_version": self.manifest.version,
                "tool_identity": self.manifest.tool_identity,
                "tool_version": self.manifest.tool_version,
                "artifact_ref": self.manifest.artifact_ref,
                "sandbox_id": result.sandbox_id,
                "sandbox_profile": result.profile_name,
                "status": status,
                "result_count": result_count,
                "cache_manifest_digest": self.cache_manifest_digest,
                "cache_provenance": self.cache_provenance,
            }
        )
        if str(self.manifest.capability_id) == "CAP-REPO-TRIVY" and "vuln" not in self.command:
            payload["scope_limitations"] = [
                "Trivy vulnerability scanning was not executed because no validated offline advisory database was supplied; misconfiguration and secret scanning remain in scope."
            ]
        evidence_bytes = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        telemetry = ScannerTelemetry(
            capability_id=str(self.manifest.capability_id),
            service_run_id=service_run_id,
            scanner_identity=self.manifest.tool_identity,
            scanner_version=self.manifest.tool_version,
            sandbox_backend=result.backend_name,
            started_at=started_at.isoformat(),
            ended_at=ended_at.isoformat(),
            duration_ms=max(0, int((time.monotonic() - started_monotonic) * 1000)),
            exit_code=result.exit_code,
            outcome=outcome,
            timeout=result.timed_out,
            error_class=error_class,
            input_digest=input_digest,
            output_digest=hashlib.sha256(evidence_bytes).hexdigest(),
            result_count=result_count,
            cache_manifest_digest=self.cache_manifest_digest,
            cache_provenance=self.cache_provenance,
        )
        return ScannerExecution(
            capability=self.manifest,
            sandbox_id=result.sandbox_id,
            exit_code=result.exit_code,
            status=status,
            evidence_bytes=evidence_bytes,
            secret_observations=secret_observations,
            stderr_redacted=redacted,
            telemetry=telemetry,
        )


def f200_scanner_adapters(
    registry: CapabilityRegistry,
    sandbox_by_capability: dict[str, SandboxExecutionService],
    *,
    semgrep_config: Path,
    scanner_cache_root: Path | None = None,
) -> list[ScannerAdapter]:
    """Build the four justified F-200 adapters from the registry."""

    cache_manifest_digest: str | None = None
    cache_provenance = ""
    if scanner_cache_root is not None:
        cache_manifest_digest, cache_provenance = _read_cache_manifest(scanner_cache_root)

    def adapter(
        capability_id: str,
        command: tuple[str, ...],
        environment: dict[str, str] | None = None,
        config: Path | None = None,
        extra_mounts: tuple[tuple[Path, str], ...] = (),
    ) -> ScannerAdapter:
        manifest = registry.get(capability_id)
        return ScannerAdapter(
            manifest=manifest,
            sandbox=sandbox_by_capability[capability_id],
            command=command,
            environment=environment or {},
            config_path=config,
            extra_mounts=extra_mounts,
            cache_root=scanner_cache_root if extra_mounts else None,
            cache_manifest_digest=cache_manifest_digest if extra_mounts else None,
            cache_provenance=cache_provenance if extra_mounts else "",
        )

    osv_cache = ((scanner_cache_root / "osv", "/root/.cache"),) if scanner_cache_root else ()
    trivy_cache = ((scanner_cache_root / "trivy", "/root/.cache/trivy"),) if scanner_cache_root else ()

    hosted = os.environ.get("SECSCAN_MODE", "").strip().upper() == "HOSTED_INTEGRATED"
    osv_command = "osv-scanner" if hosted else "scan"
    gitleaks_command = "gitleaks" if hosted else "detect"
    trivy_command = "trivy" if hosted else "fs"
    trivy_scanners = "vuln,misconfig,secret"
    if hosted and scanner_cache_root is None:
        # The hosted image is deliberately offline. Do not let Trivy attempt
        # a first-run vulnerability DB update; OSV owns dependency coverage
        # until a validated Trivy DB cache is supplied.
        trivy_scanners = "misconfig,secret"

    return [
        adapter(
            "CAP-SAST-SEMGREP",
            ("semgrep", "scan", "--config", "/cfg/scanner.yml", "--metrics", "off", "--disable-version-check", "--no-git-ignore", "--json", "--no-error", "/src"),
            {"SEMGREP_SEND_METRICS": "off"},
            semgrep_config,
        ),
        adapter(
            "CAP-SCA-OSV",
            (
                osv_command,
                *(() if not hosted else ("scan",)),
                "source",
                "--offline",
                "--offline-vulnerabilities",
                "--format",
                "json",
                "--recursive",
                "--allow-no-lockfiles",
                "/src",
            ),
            {"XDG_CACHE_HOME": "/root/.cache"},
            extra_mounts=osv_cache,
        ),
        adapter(
            "CAP-SECRETS-GITLEAKS",
            (gitleaks_command, *(() if not hosted else ("detect",)), "--source", "/src", "--no-git", "--no-banner", "--redact", "--report-format", "json", "--report-path", "-"),
        ),
        adapter(
            "CAP-REPO-TRIVY",
            (
                trivy_command,
                *(() if not hosted else ("fs",)),
                "--offline-scan",
                "--skip-db-update",
                "--skip-java-db-update",
                "--skip-check-update",
                "--scanners",
                trivy_scanners,
                "--format",
                "json",
                "--quiet",
                "/src",
            ),
            {"TRIVY_CACHE_DIR": "/root/.cache/trivy"},
            extra_mounts=trivy_cache,
        ),
    ]
