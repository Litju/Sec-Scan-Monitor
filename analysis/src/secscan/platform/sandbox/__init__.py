"""Sandbox execution plane (ADR-0009).

`SandboxBackend` port + constrained local Docker backend. Default profile
for untrusted operations: network none, read-only input mount, isolated
scratch output, no host secrets, no Docker socket inside, bounded
CPU/RAM/PIDs, execution timeout, explicit command allowlist, captured
stdout/stderr.

LAW: a sandbox-required capability REFUSES when no backend is available —
never a silent fallback to unrestricted host execution. Stronger
Firecracker-class microVM backends are future architecture behind the
same port.
"""

from __future__ import annotations

import os
import threading
import time
from contextlib import nullcontext
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from secscan.platform.domain.capability import SandboxRequirement
from secscan.platform.domain.ports import SandboxBackend


class SandboxUnavailableError(RuntimeError):
    """Raised when a sandbox-required execution has no available backend."""


class SandboxTimeoutError(SandboxUnavailableError):
    """Raised only when the backend cannot return a bounded timeout result."""


class SandboxRefusalError(RuntimeError):
    """Raised when an execution is refused by profile constraints."""


class ProfileViolationError(RuntimeError):
    """Raised when a requested execution violates its sandbox profile."""


@dataclass(frozen=True)
class SandboxProfile:
    """The qualification-level isolation profile for untrusted operations."""

    name: str = "default"
    network: str = "none"  # none | loopback-only | allowlisted
    input_read_only: bool = True
    output_scratch: bool = True
    host_secrets: bool = False
    docker_socket: bool = False
    cpu_limit: float = 1.0
    memory_limit: str = "256m"
    pids_limit: int = 64
    timeout_seconds: int = 60
    command_allowlist: tuple[str, ...] = ("python", "cat", "sh", "dir")
    env: dict[str, str] = field(default_factory=dict)

    def allows_command(self, command: list[str]) -> bool:
        if not command:
            return False
        return command[0].split("/")[-1] in self.command_allowlist


DEFAULT_PROFILE = SandboxProfile()


@dataclass
class SandboxExecutionResult:
    sandbox_id: str
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False
    profile_name: str = "default"
    backend_name: str = "docker"


class DockerSandboxBackend:
    """Constrained Docker backend (qualification-level isolation)."""

    def __init__(self, image: str, profile: SandboxProfile = DEFAULT_PROFILE, client: Any | None = None) -> None:
        self._image = image
        self._profile = profile
        self._client = client
        self._lock = threading.Lock()

    def _docker(self) -> Any:
        if self._client is None:
            import docker  # type: ignore[import-untyped]  # stubs: types-docker (optional)

            self._client = docker.from_env()
        return self._client

    def is_available(self) -> bool:
        try:
            return bool(self._docker().ping())
        except Exception:
            return False

    def run(
        self,
        *,
        command: list[str],
        profile: dict[str, Any] | None = None,
        timeout_seconds: int | None = None,
        input_bytes: bytes | None = None,
        mounts: list[tuple[str, str, bool]] | None = None,
        environment: dict[str, str] | None = None,
        working_dir: str | None = None,
    ) -> dict[str, Any]:
        resolved = self._resolve_profile(profile)
        timeout = timeout_seconds if timeout_seconds is not None else resolved.timeout_seconds

        if not resolved.allows_command(command):
            raise ProfileViolationError(
                f"command {command[0] if command else '<empty>'} is not in the profile allowlist"
            )
        if resolved.docker_socket:
            raise ProfileViolationError("docker socket mounts are forbidden by the sandbox profile")
        for host_path, container_path, read_only in mounts or []:
            if not read_only:
                raise ProfileViolationError(
                    f"writable host mount refused: {host_path} -> {container_path}"
                )
        if not self.is_available():
            raise SandboxUnavailableError("Docker daemon unavailable; sandbox-required execution refused")

        container_environment = {
            "SECSCAN_SANDBOX": "1",
            "HOME": "/tmp/home",
            **resolved.env,
            **(environment or {}),
        }
        if not resolved.host_secrets:
            container_environment["SECSCAN_NO_HOST_SECRETS"] = "1"
        kwargs: dict[str, Any] = {
            "image": self._image,
            "command": command,
            "detach": True,
            "network_disabled": resolved.network == "none",
            "read_only": True,
            "pids_limit": resolved.pids_limit,
            "mem_limit": resolved.memory_limit,
            "nano_cpus": int(resolved.cpu_limit * 1_000_000_000),
            "environment": container_environment,
            "tmpfs": {"/tmp": "rw,noexec,nosuid,size=128m"},
        }
        if working_dir:
            kwargs["working_dir"] = working_dir
        if mounts:
            kwargs["volumes"] = {
                host: {"bind": target, "mode": "ro"}
                for host, target, _read_only in mounts
            }
        container = None
        started_monotonic = time.monotonic()
        try:
            with self._lock:
                container = self._docker().containers.run(**kwargs)
            exit_info = container.wait(timeout=timeout)
            exit_code = int(exit_info.get("StatusCode", -1))
            timed_out = False
            stdout = container.logs(stdout=True, stderr=False).decode("utf-8", errors="replace")
            stderr = container.logs(stdout=False, stderr=True).decode("utf-8", errors="replace")
            return {
                "sandbox_id": container.short_id,
                "exit_code": exit_code,
                "stdout": stdout,
                "stderr": stderr,
                "timed_out": timed_out,
                "profile_name": resolved.name,
            }
        except Exception as exc:
            if container is not None and time.monotonic() - started_monotonic >= timeout:
                try:
                    container.kill()
                except Exception:
                    pass
                stdout = container.logs(stdout=True, stderr=False).decode("utf-8", errors="replace")
                stderr = container.logs(stdout=False, stderr=True).decode("utf-8", errors="replace")
                return {
                    "sandbox_id": container.short_id,
                    "exit_code": 124,
                    "stdout": stdout,
                    "stderr": stderr,
                    "timed_out": True,
                    "profile_name": resolved.name,
                }
            raise SandboxUnavailableError(f"sandbox execution failed: {exc}") from exc
        finally:
            if container is not None:
                try:
                    container.remove(force=True)
                except Exception:
                    pass

    def _resolve_profile(self, profile: dict[str, Any] | None) -> SandboxProfile:
        if profile is None:
            return self._profile
        base = self._profile
        allowlist = tuple(profile.get("command_allowlist", base.command_allowlist))
        return SandboxProfile(
            name=str(profile.get("name", base.name)),
            network=str(profile.get("network", base.network)),
            input_read_only=bool(profile.get("input_read_only", base.input_read_only)),
            output_scratch=bool(profile.get("output_scratch", base.output_scratch)),
            host_secrets=bool(profile.get("host_secrets", base.host_secrets)),
            docker_socket=bool(profile.get("docker_socket", base.docker_socket)),
            cpu_limit=float(profile.get("cpu_limit", base.cpu_limit)),
            memory_limit=str(profile.get("memory_limit", base.memory_limit)),
            pids_limit=int(profile.get("pids_limit", base.pids_limit)),
            timeout_seconds=int(profile.get("timeout_seconds", base.timeout_seconds)),
            command_allowlist=allowlist,
            env=dict(profile.get("env", base.env)),
        )


class VercelSandboxBackend:
    """Vercel Sandbox adapter for pinned scanner images."""

    _MAX_TRANSFER_BYTES = 64 * 1024 * 1024
    _MAX_TRANSFER_FILES = 10_000

    def __init__(self, image: str, *, project_id: str, profile: SandboxProfile = DEFAULT_PROFILE) -> None:
        self._image = image.strip()
        self._project_id = project_id.strip()
        self._profile = profile

    def is_available(self) -> bool:
        token = os.environ.get("VERCEL_OIDC_TOKEN") or os.environ.get("VERCEL_TOKEN")
        return bool(
            self._image
            and self._project_id
            and token
            and token != "[SENSITIVE]"
        )

    def _resolve_profile(self, profile: dict[str, Any] | None) -> SandboxProfile:
        if profile is None:
            return self._profile
        base = self._profile
        return SandboxProfile(
            name=str(profile.get("name", base.name)),
            network=str(profile.get("network", base.network)),
            input_read_only=bool(profile.get("input_read_only", base.input_read_only)),
            output_scratch=bool(profile.get("output_scratch", base.output_scratch)),
            host_secrets=bool(profile.get("host_secrets", base.host_secrets)),
            docker_socket=bool(profile.get("docker_socket", base.docker_socket)),
            cpu_limit=float(profile.get("cpu_limit", base.cpu_limit)),
            memory_limit=str(profile.get("memory_limit", base.memory_limit)),
            pids_limit=int(profile.get("pids_limit", base.pids_limit)),
            timeout_seconds=int(profile.get("timeout_seconds", base.timeout_seconds)),
            command_allowlist=tuple(profile.get("command_allowlist", base.command_allowlist)),
            env=dict(profile.get("env", base.env)),
        )

    def run(
        self,
        *,
        command: list[str],
        profile: dict[str, Any] | None = None,
        timeout_seconds: int | None = None,
        input_bytes: bytes | None = None,
        mounts: list[tuple[str, str, bool]] | None = None,
        environment: dict[str, str] | None = None,
        working_dir: str | None = None,
    ) -> dict[str, Any]:
        resolved = self._resolve_profile(profile)
        timeout = timeout_seconds if timeout_seconds is not None else resolved.timeout_seconds
        if not self.is_available():
            raise SandboxUnavailableError("Vercel Sandbox credentials or image are unavailable")
        if resolved.network != "none" or resolved.host_secrets or resolved.docker_socket:
            raise ProfileViolationError("hosted scanner sandbox requires network-none and no host secrets")
        if not command or not resolved.allows_command(command):
            raise ProfileViolationError("hosted scanner command is outside the declared allowlist")
        for host_path, _container_path, read_only in mounts or []:
            if not read_only:
                raise ProfileViolationError("hosted scanner requested a writable input mount")
            if not Path(host_path).exists():
                raise FileNotFoundError("hosted scanner input mount is missing")
        safe_environment = {key: value for key, value in (environment or {}).items() if key and value is not None}
        if any(
            any(marker in key.upper() for marker in ("TOKEN", "SECRET", "PASSWORD", "DATABASE", "AUTH"))
            for key in safe_environment
        ):
            raise ProfileViolationError("hosted scanner environment contains a forbidden secret-like key")

        try:
            from vercel import api
            from vercel.sandbox import NetworkPolicy, SandboxCredentials
            from vercel.sandbox.sync import SandboxServiceOptions, create_sandbox
        except ImportError as exc:  # pragma: no cover - exercised in hosted build
            raise SandboxUnavailableError("Vercel Sandbox SDK is required for hosted execution") from exc

        try:
            oidc_token = os.environ.get("VERCEL_OIDC_TOKEN")
            credentials_context: Any
            if oidc_token:
                credentials_context = nullcontext()
            else:
                token = os.environ.get("VERCEL_TOKEN", "")

                def credentials() -> SandboxCredentials:
                    return SandboxCredentials(
                        token=token,
                        team_id=os.environ.get("VERCEL_TEAM_ID", ""),
                        project_id=self._project_id,
                    )

                credentials_context = api.session(
                    service_options=[SandboxServiceOptions(credentials_factory=credentials)]
                )
            with credentials_context:
                with create_sandbox(
                    project_id=self._project_id,
                    image=self._image,
                    execution_time_limit=timeout,
                    network_policy=NetworkPolicy.deny_all(),
                    persistent=False,
                    destroy=True,
                ) as sandbox:
                    transferred = self._copy_mounts(sandbox, mounts or [])
                    if input_bytes is not None:
                        if len(input_bytes) > self._MAX_TRANSFER_BYTES:
                            raise ProfileViolationError("hosted sandbox input exceeds transfer bound")
                        sandbox.fs.write_bytes("/input", input_bytes)
                        transferred += len(input_bytes)
                    result = sandbox.run_process(
                        command[0],
                        command[1:],
                        cwd=working_dir,
                        env={"SECSCAN_SANDBOX": "1", "SECSCAN_NO_HOST_SECRETS": "1", **safe_environment},
                        kill_after=timeout,
                        capture_output=True,
                        check=False,
                    )
                    return {
                        "sandbox_id": str(sandbox.name),
                        "exit_code": int(result.returncode),
                        "stdout": result.stdout or "",
                        "stderr": result.stderr or "",
                        "timed_out": int(result.returncode) == 124,
                        "profile_name": resolved.name,
                        "backend_name": "vercel-sandbox",
                        "transferred_bytes": transferred,
                    }
        except ProfileViolationError:
            raise
        except Exception as exc:
            if type(exc).__name__ in {"SandboxTimeoutError", "TimeoutError"}:
                return {
                    "sandbox_id": "vercel-sandbox-timeout",
                    "exit_code": 124,
                    "stdout": "",
                    "stderr": "",
                    "timed_out": True,
                    "profile_name": resolved.name,
                    "backend_name": "vercel-sandbox",
                }
            raise SandboxUnavailableError(
                f"Vercel Sandbox execution failed closed ({type(exc).__name__})"
            ) from exc

    def _copy_mounts(self, sandbox: Any, mounts: list[tuple[str, str, bool]]) -> int:
        total_bytes = 0
        total_files = 0
        for host_path_text, container_path_text, _read_only in mounts:
            host_path = Path(host_path_text).resolve()
            container_path = PurePosixPath(container_path_text)
            if not container_path.is_absolute() or ".." in container_path.parts:
                raise ProfileViolationError("hosted sandbox mount path is invalid")
            paths = [host_path] if host_path.is_file() else sorted(path for path in host_path.rglob("*") if path.is_file())
            for source in paths:
                if source.is_symlink():
                    raise ProfileViolationError("hosted sandbox refuses symlink mounts")
                relative = source.name if host_path.is_file() else source.relative_to(host_path).as_posix()
                destination = container_path / relative
                data = source.read_bytes()
                total_files += 1
                total_bytes += len(data)
                if total_files > self._MAX_TRANSFER_FILES or total_bytes > self._MAX_TRANSFER_BYTES:
                    raise ProfileViolationError("hosted sandbox input exceeds transfer bound")
                sandbox.fs.mkdir(str(destination.parent))
                sandbox.fs.write_bytes(str(destination), data)
        return total_bytes


class NullSandboxBackend:
    """Always-unavailable backend: forces sandbox-required refusals."""

    def is_available(self) -> bool:
        return False

    def run(
        self,
        *,
        command: list[str],
        profile: dict[str, Any] | None = None,
        timeout_seconds: int | None = None,
        input_bytes: bytes | None = None,
        mounts: list[tuple[str, str, bool]] | None = None,
        environment: dict[str, str] | None = None,
        working_dir: str | None = None,
    ) -> dict[str, Any]:
        raise SandboxUnavailableError("no sandbox backend configured; sandbox-required execution refused")


class SandboxExecutionService:
    """Application-layer gate between capabilities and sandbox backends."""

    def __init__(self, backend: SandboxBackend) -> None:
        self._backend = backend

    def execute(
        self,
        *,
        capability: Any,  # CapabilityManifest
        command: list[str],
        timeout_seconds: int | None = None,
        mounts: list[tuple[str, str, bool]] | None = None,
        environment: dict[str, str] | None = None,
        working_dir: str | None = None,
    ) -> SandboxExecutionResult:
        if capability.sandbox_requirement == SandboxRequirement.REQUIRED and not self._backend.is_available():
            # LAW: never fall back to host execution for sandbox-required work.
            raise SandboxRefusalError(
                f"capability {capability.capability_id} is sandbox-required but no backend is available: REFUSE"
            )
        # Command allowlist from the capability manifest is enforced HERE,
        # at the application boundary, for every backend.
        allowlist = tuple(capability.command_allowlist or ())
        if allowlist and (not command or command[0].split("/")[-1] not in allowlist):
            raise ProfileViolationError(
                f"command {command[0] if command else '<empty>'} is not in the capability "
                f"{capability.capability_id} command allowlist"
            )
        for host_path, container_path, read_only in mounts or []:
            if not read_only:
                raise ProfileViolationError(
                    f"capability {capability.capability_id} requested writable host mount {host_path} -> {container_path}"
                )
        if str(capability.network_policy) not in {"none", "NetworkPolicy.NONE"}:
            raise ProfileViolationError(
                f"capability {capability.capability_id} requests unsupported network policy "
                f"{capability.network_policy}; fail closed"
            )
        profile_overrides: dict[str, Any] = {
            "timeout_seconds": capability.timeout_seconds,
            "network": "none",
            "command_allowlist": list(allowlist),
        }
        resource_limits = dict(getattr(capability, "resource_limits", {}) or {})
        if "cpu" in resource_limits:
            profile_overrides["cpu_limit"] = float(str(resource_limits["cpu"]).rstrip("c"))
        if "memory" in resource_limits:
            profile_overrides["memory_limit"] = str(resource_limits["memory"])
        if "pids" in resource_limits:
            profile_overrides["pids_limit"] = int(resource_limits["pids"])
        result = self._backend.run(
            command=command,
            profile=profile_overrides,
            timeout_seconds=timeout_seconds or capability.timeout_seconds,
            mounts=mounts,
            environment=environment,
            working_dir=working_dir,
        )
        return SandboxExecutionResult(
            sandbox_id=str(result["sandbox_id"]),
            exit_code=int(result["exit_code"]),
            stdout=str(result["stdout"]),
            stderr=str(result.get("stderr", "")),
            timed_out=bool(result.get("timed_out", False)),
            profile_name=str(result.get("profile_name", "default")),
            backend_name=str(result.get("backend_name", "docker")),
        )
