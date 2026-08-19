"""Human identity and client membership boundary.

Human authentication is verified from the provider's signed JWT. Tenant
membership remains a separate PostgreSQL concern; JWT roles never replace
client membership or the agent/OPA authority path.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from json import JSONDecodeError, loads
from typing import Any, Callable, Protocol
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import jwt
from jwt import PyJWKClient
from jwt.exceptions import PyJWTError


class HumanRole(StrEnum):
    PLATFORM_ADMIN = "PLATFORM_ADMIN"
    FIRM_OPERATOR = "FIRM_OPERATOR"
    SECURITY_REVIEWER = "SECURITY_REVIEWER"
    APPROVER = "APPROVER"
    CLIENT_VIEWER = "CLIENT_VIEWER"


@dataclass(frozen=True)
class VerifiedHumanIdentity:
    """Claims already verified by a standards-based identity adapter."""

    human_principal_id: str
    issuer: str
    subject: str
    roles: frozenset[HumanRole] = frozenset()


@dataclass(frozen=True)
class ClientMembership:
    human_principal_id: str
    client_id: str
    role: HumanRole
    active: bool = True


class HumanIdentityVerifier(Protocol):
    """Provider adapter contract; implementations verify signatures and claims."""

    def verify_bearer_token(self, token: str) -> VerifiedHumanIdentity: ...


class HumanTokenRevocationStore(Protocol):
    """Durable product-session revocations; provider JWTs remain stateless."""

    def is_revoked(self, token: str) -> bool: ...

    def revoke(self, token: str, human_principal_id: str) -> None: ...


class NeonAuthJwtVerifier:
    """Verify Neon Auth JWTs without trusting browser-supplied identity data.

    ``principal_id_resolver`` is the product identity bridge. When omitted,
    the verified Neon Auth subject is used as the product human principal ID;
    hosted provisioning must create the matching product principal before the
    user can see any tenant rows.
    """

    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        jwks_url: str,
        principal_id_resolver: Callable[[str, str], str | None] | None = None,
        jwks_client: Any | None = None,
        session_url: str | None = None,
        session_origin: str | None = None,
        session_timeout_seconds: float = 3.0,
        revocation_store: HumanTokenRevocationStore | None = None,
        algorithms: tuple[str, ...] = ("EdDSA", "RS256", "ES256"),
        clock_skew_seconds: int = 30,
    ) -> None:
        if not issuer.strip() or not audience.strip() or not jwks_url.strip():
            raise ValueError("hosted identity verification requires issuer, audience, and JWKS URL")
        if not algorithms or any(algorithm not in {"EdDSA", "RS256", "ES256"} for algorithm in algorithms):
            raise ValueError("hosted identity verification permits only asymmetric JWT algorithms")
        self._issuer = issuer
        self._audience = audience
        self._principal_id_resolver = principal_id_resolver
        self._jwks_client = jwks_client or PyJWKClient(jwks_url, cache_jwk_set=True, lifespan=300)
        self._session_url = session_url.strip() if session_url else None
        self._session_origin = session_origin.strip() if session_origin else None
        self._session_timeout_seconds = session_timeout_seconds
        self._revocation_store = revocation_store
        self._algorithms = algorithms
        self._clock_skew_seconds = clock_skew_seconds

    def verify_bearer_token(self, token: str) -> VerifiedHumanIdentity:
        if not token or any(character.isspace() for character in token):
            raise ValueError("bearer token required")
        try:
            signing_key = self._jwks_client.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=list(self._algorithms),
                audience=self._audience,
                issuer=self._issuer,
                options={"require": ["exp", "iss", "sub"]},
                leeway=self._clock_skew_seconds,
            )
            subject = _claim_text(claims, "sub")
            issuer = _claim_text(claims, "iss")
            principal_id = (
                self._principal_id_resolver(issuer, subject)
                if self._principal_id_resolver is not None
                else subject
            )
            if not principal_id or len(principal_id) > 96:
                raise PermissionError("human principal is not provisioned")
            if self._revocation_store is not None and self._revocation_store.is_revoked(token):
                raise PermissionError("human session is revoked")
            return VerifiedHumanIdentity(
                human_principal_id=principal_id,
                issuer=issuer,
                subject=subject,
                roles=_roles_from_claims(claims),
            )
        except PermissionError:
            raise
        except (PyJWTError, KeyError, TypeError, ValueError) as exc:
            # Do not serialize token, claim, key, or provider response content.
            raise PermissionError("human identity verification failed") from exc

    def verify_session_cookie(self, cookie: str) -> str:
        """Resolve the browser session with Neon Auth before accepting a JWT.

        Neon Auth access JWTs are stateless and can remain cryptographically
        valid after sign-out.  The provider session is therefore the revocation
        boundary; its user ID must be checked against the already verified JWT.
        """

        if not self._session_url or not cookie or any(character in cookie for character in "\r\n"):
            raise PermissionError("active human session is required")
        request = Request(
            self._session_url,
            headers={
                "Accept": "application/json",
                "Cookie": cookie,
                **({"Origin": self._session_origin} if self._session_origin else {}),
            },
            method="GET",
        )
        try:
            with urlopen(request, timeout=self._session_timeout_seconds) as response:
                if response.status != 200:
                    raise PermissionError("active human session is required")
                payload = loads(response.read(1_048_576).decode("utf-8"))
            user = payload.get("user") if isinstance(payload, dict) else None
            subject = user.get("id") if isinstance(user, dict) else None
            if not isinstance(subject, str) or not subject.strip():
                raise PermissionError("active human session is required")
            return subject.strip()
        except PermissionError:
            raise
        except (HTTPError, URLError, OSError, TimeoutError, JSONDecodeError, UnicodeError, TypeError) as exc:
            raise PermissionError("active human session verification failed") from exc


class HumanMembershipStore(Protocol):
    def memberships_for(self, human_principal_id: str, client_id: str) -> tuple[ClientMembership, ...]: ...

    def is_platform_admin(self, human_principal_id: str) -> bool: ...


class HumanAccessDenied(PermissionError):
    """Raised without revealing whether an inaccessible client exists."""


@dataclass
class InMemoryHumanMembershipStore:
    """Test-only membership store; hosted composition must inject PostgreSQL."""

    memberships: list[ClientMembership] = field(default_factory=list)

    def memberships_for(self, human_principal_id: str, client_id: str) -> tuple[ClientMembership, ...]:
        return tuple(
            membership
            for membership in self.memberships
            if membership.human_principal_id == human_principal_id
            and membership.client_id == client_id
            and membership.active
        )

    def is_platform_admin(self, human_principal_id: str) -> bool:
        return any(
            membership.human_principal_id == human_principal_id
            and membership.role == HumanRole.PLATFORM_ADMIN
            and membership.active
            for membership in self.memberships
        )


class HumanAccessService:
    """Checks server-side client membership independently of OPA authority."""

    def __init__(self, memberships: HumanMembershipStore) -> None:
        self._memberships = memberships

    def require_client_access(
        self,
        identity: VerifiedHumanIdentity,
        client_id: str,
        *,
        roles: frozenset[HumanRole] = frozenset(),
    ) -> ClientMembership:
        if self._memberships.is_platform_admin(identity.human_principal_id):
            return ClientMembership(
                human_principal_id=identity.human_principal_id,
                client_id=client_id,
                role=HumanRole.PLATFORM_ADMIN,
            )
        matches = self._memberships.memberships_for(identity.human_principal_id, client_id)
        if not matches or (roles and not any(match.role in roles for match in matches)):
            raise HumanAccessDenied("client access denied")
        return matches[0]


def extract_bearer_token(authorization: str | None) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise ValueError("bearer token required")
    token = authorization[7:].strip()
    if not token or any(character.isspace() for character in token):
        raise ValueError("bearer token required")
    return token


def _claim_text(claims: dict[str, Any], name: str) -> str:
    value = claims.get(name)
    if not isinstance(value, str) or not value.strip():
        raise PermissionError("required identity claim is missing")
    return value.strip()


def _roles_from_claims(claims: dict[str, Any]) -> frozenset[HumanRole]:
    raw_roles = claims.get("roles", ())
    if isinstance(raw_roles, str):
        raw_roles = (raw_roles,)
    if not isinstance(raw_roles, (list, tuple, set, frozenset)):
        raise PermissionError("identity roles claim is invalid")
    roles: set[HumanRole] = set()
    for raw_role in raw_roles:
        try:
            roles.add(HumanRole(str(raw_role)))
        except ValueError:
            # Unknown provider roles cannot grant product authority.
            continue
    return frozenset(roles)
