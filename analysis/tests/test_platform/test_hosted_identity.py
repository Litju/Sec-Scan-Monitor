from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from secscan.platform.hosted import identity as identity_module
from secscan.platform.hosted.identity import (
    ClientMembership,
    HumanAccessDenied,
    HumanAccessService,
    HumanRole,
    InMemoryHumanMembershipStore,
    NeonAuthJwtVerifier,
    VerifiedHumanIdentity,
    extract_bearer_token,
)


def test_bearer_parser_rejects_ambiguous_tokens() -> None:
    assert extract_bearer_token("Bearer token-without-spaces") == "token-without-spaces"
    for value in (None, "Basic token", "Bearer ", "Bearer token with spaces"):
        with pytest.raises(ValueError):
            extract_bearer_token(value)


def test_membership_is_client_scoped_and_role_checked() -> None:
    identity = VerifiedHumanIdentity("human-1", "https://issuer.example", "subject-1")
    store = InMemoryHumanMembershipStore(
        [ClientMembership("human-1", "client-a", HumanRole.CLIENT_VIEWER)]
    )
    access = HumanAccessService(store)

    assert access.require_client_access(identity, "client-a").client_id == "client-a"
    with pytest.raises(HumanAccessDenied):
        access.require_client_access(identity, "client-b")
    with pytest.raises(HumanAccessDenied):
        access.require_client_access(identity, "client-a", roles=frozenset({HumanRole.APPROVER}))


def test_platform_admin_membership_allows_client_scoped_application_guard() -> None:
    identity = VerifiedHumanIdentity("admin-1", "https://issuer.example", "subject-1")
    store = InMemoryHumanMembershipStore(
        [ClientMembership("admin-1", "client-a", HumanRole.PLATFORM_ADMIN)]
    )

    assert HumanAccessService(store).require_client_access(identity, "client-b").role == HumanRole.PLATFORM_ADMIN


def test_neon_auth_jwt_verifier_checks_signature_claims_and_product_principal() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = jwt.encode(
        {
            "iss": "https://issuer.example",
            "aud": "secscanmonitor",
            "sub": "neon-user-1",
            "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
            "roles": ["CLIENT_VIEWER", "provider-admin"],
        },
        private_key,
        algorithm="RS256",
    )

    class _Jwks:
        def get_signing_key_from_jwt(self, value: str) -> SimpleNamespace:
            assert value == token
            return SimpleNamespace(key=private_key.public_key())

    class _Revocations:
        revoked: set[str] = set()

        def is_revoked(self, value: str) -> bool:
            return value in self.revoked

        def revoke(self, value: str, _principal_id: str) -> None:
            self.revoked.add(value)

    revocations = _Revocations()
    verifier = NeonAuthJwtVerifier(
        issuer="https://issuer.example",
        audience="secscanmonitor",
        jwks_url="https://issuer.example/.well-known/jwks.json",
        principal_id_resolver=lambda issuer, subject: f"human-{subject}",
        jwks_client=_Jwks(),
        revocation_store=revocations,
    )

    identity = verifier.verify_bearer_token(token)
    assert identity.human_principal_id == "human-neon-user-1"
    assert identity.subject == "neon-user-1"
    assert identity.roles == frozenset({HumanRole.CLIENT_VIEWER})
    revocations.revoke(token, identity.human_principal_id)
    with pytest.raises(PermissionError, match="human session is revoked"):
        verifier.verify_bearer_token(token)


def test_neon_auth_jwt_verifier_accepts_ed25519_tokens() -> None:
    private_key = ed25519.Ed25519PrivateKey.generate()
    token = jwt.encode(
        {
            "iss": "https://auth.example",
            "aud": "https://auth.example",
            "sub": "neon-user-1",
            "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
        },
        private_key,
        algorithm="EdDSA",
    )

    class _Jwks:
        def get_signing_key_from_jwt(self, value: str) -> SimpleNamespace:
            assert value == token
            return SimpleNamespace(key=private_key.public_key())

    verifier = NeonAuthJwtVerifier(
        issuer="https://auth.example",
        audience="https://auth.example",
        jwks_url="https://auth.example/.well-known/jwks.json",
        jwks_client=_Jwks(),
    )

    assert verifier.verify_bearer_token(token).subject == "neon-user-1"


def test_neon_auth_jwt_verifier_fails_closed_for_expiry_and_tampering() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    expired = jwt.encode(
        {
            "iss": "https://issuer.example",
            "aud": "secscanmonitor",
            "sub": "neon-user-1",
            "exp": datetime.now(timezone.utc) - timedelta(minutes=1),
        },
        private_key,
        algorithm="RS256",
    )

    class _Jwks:
        def get_signing_key_from_jwt(self, value: str) -> SimpleNamespace:
            return SimpleNamespace(key=private_key.public_key())

    verifier = NeonAuthJwtVerifier(
        issuer="https://issuer.example",
        audience="secscanmonitor",
        jwks_url="https://issuer.example/.well-known/jwks.json",
        jwks_client=_Jwks(),
    )
    for value in (expired, expired + "tampered"):
        with pytest.raises(PermissionError, match="identity verification failed"):
            verifier.verify_bearer_token(value)


def test_neon_auth_session_cookie_requires_active_matching_provider_user(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Response:
        status = 200

        def __enter__(self) -> "_Response":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, _limit: int) -> bytes:
            return b'{"session": {}, "user": {"id": "neon-user-1"}}'

    captured: dict[str, str] = {}

    def _urlopen(request: object, *, timeout: float) -> _Response:
        captured["cookie"] = request.get_header("Cookie")  # type: ignore[union-attr]
        captured["timeout"] = str(timeout)
        return _Response()

    monkeypatch.setattr(identity_module, "urlopen", _urlopen)
    verifier = NeonAuthJwtVerifier(
        issuer="https://auth.example",
        audience="https://auth.example",
        jwks_url="https://auth.example/jwks",
        session_url="https://auth.example/session",
    )

    assert verifier.verify_session_cookie("session=active") == "neon-user-1"
    assert captured == {"cookie": "session=active", "timeout": "3.0"}
    with pytest.raises(PermissionError):
        verifier.verify_session_cookie("session=revoked\r\nX-Injected: yes")
