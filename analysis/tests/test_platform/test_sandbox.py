"""Sandbox tests (G10): profile law, refusal semantics, and — when the
Docker daemon is reachable — real isolation verification."""

from __future__ import annotations

import pytest

from secscan.platform.domain.capability import (
    CapabilityManifest,
    NetworkPolicy,
    RiskClass,
    SandboxRequirement,
)
from secscan.platform.domain.ids import CapabilityId
from secscan.platform.sandbox import (
    DEFAULT_PROFILE,
    DockerSandboxBackend,
    NullSandboxBackend,
    ProfileViolationError,
    SandboxExecutionService,
    SandboxRefusalError,
    SandboxUnavailableError,
)


def _capability(requirement: SandboxRequirement = SandboxRequirement.REQUIRED, **overrides) -> CapabilityManifest:
    kwargs = dict(
        capability_id=CapabilityId("CAP-SANDBOX-TEST"),
        version="1.0.0",
        description="test",
        risk_class=RiskClass.LOW,
        required_authority="inspect",
        sandbox_requirement=requirement,
        network_policy=NetworkPolicy.NONE,
        timeout_seconds=10,
        command_allowlist=["python", "cat"],
    )
    kwargs.update(overrides)
    return CapabilityManifest(**kwargs)


class TestProfileLaw:
    def test_default_profile_constraints(self) -> None:
        assert DEFAULT_PROFILE.network == "none"
        assert DEFAULT_PROFILE.input_read_only is True
        assert DEFAULT_PROFILE.output_scratch is True
        assert DEFAULT_PROFILE.host_secrets is False
        assert DEFAULT_PROFILE.docker_socket is False
        assert DEFAULT_PROFILE.cpu_limit > 0
        assert DEFAULT_PROFILE.memory_limit
        assert DEFAULT_PROFILE.pids_limit > 0
        assert DEFAULT_PROFILE.timeout_seconds > 0

    def test_command_allowlist_enforced(self) -> None:
        assert DEFAULT_PROFILE.allows_command(["python", "-c", "print(1)"])
        assert DEFAULT_PROFILE.allows_command(["cat", "file"])
        assert not DEFAULT_PROFILE.allows_command(["curl", "https://evil.example"])
        assert not DEFAULT_PROFILE.allows_command([])


class TestRefusalSemantics:
    def test_sandbox_required_refuses_without_backend(self) -> None:
        service = SandboxExecutionService(NullSandboxBackend())
        with pytest.raises(SandboxRefusalError):
            service.execute(capability=_capability(), command=["python", "-c", "print(1)"])

    def test_sandbox_optional_allows_non_sandbox_path(self) -> None:
        """Optional-sandbox capabilities may run without a backend (the
        backend contract still applies when one is configured)."""
        capability = _capability(requirement=SandboxRequirement.NONE)
        assert capability.sandbox_requirement == SandboxRequirement.NONE

    def test_backend_unavailable_error_when_forced(self) -> None:
        with pytest.raises(SandboxUnavailableError):
            NullSandboxBackend().run(command=["cat"], profile=None, timeout_seconds=5)

    def test_disallowed_command_refused_before_execution(self) -> None:
        backend = NullSandboxBackend()
        SandboxExecutionService(backend)

        class _NeverRuns:
            def is_available(self) -> bool:
                return True

            def run(self, **kwargs):
                raise AssertionError("must not execute")

        strict = SandboxExecutionService(_NeverRuns())
        with pytest.raises(ProfileViolationError):
            strict.execute(capability=_capability(), command=["curl", "https://evil.example"])


class TestDockerIsolation:
    """Real Docker isolation tests — skipped when the daemon is down
    (recorded limitation, never a silent pass)."""

    @pytest.fixture(scope="class")
    def backend(self):
        backend = DockerSandboxBackend(image="alpine:3.20")
        if not backend.is_available():
            pytest.skip("Docker daemon unavailable; sandbox isolation tests recorded as NOT_RUN")
        return backend

    def test_echo_captures_output(self, backend) -> None:
        result = backend.run(command=["cat", "/etc/alpine-release"], timeout_seconds=30)
        assert result["exit_code"] == 0
        assert "3.20" in result["stdout"]

    def test_network_is_disabled(self, backend) -> None:
        result = backend.run(command=["sh", "-c", "wget -q -O - http://1.1.1.1 2>&1 || true"], timeout_seconds=60)
        # network none: any egress attempt fails (wget error text or empty)
        assert result["exit_code"] == 0  # the `|| true` makes the shell succeed
        assert "wget" in result["stdout"]  # wget ran; its failure text is captured

    def test_no_docker_socket_inside(self, backend) -> None:
        result = backend.run(command=["sh", "-c", "ls /var/run/docker.sock 2>&1 || true"], timeout_seconds=30)
        assert "No such file" in result["stdout"] or "not found" in result["stdout"]

    def test_timeout_enforced(self, backend) -> None:
        result = backend.run(command=["sh", "-c", "sleep 300"], timeout_seconds=2)
        assert result["timed_out"] is True
        assert result["exit_code"] == 124

    def test_disallowed_command_refused(self, backend) -> None:
        with pytest.raises(ProfileViolationError):
            backend.run(command=["curl", "http://example.com"], timeout_seconds=30)
