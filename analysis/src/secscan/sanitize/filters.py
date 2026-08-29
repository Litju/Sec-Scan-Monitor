"""Deterministic Gate 4 sanitization filters for FL-005."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any

from secscan.contracts.canonical import Asset, Delta, Finding

_EVIDENCE_PATH_PATTERN = re.compile(r"(?i)(?:[A-Z]:[\\/][^\"'\s]+|(?:^|[\s\"'])(?:evidence|exports)[\\/][^\"'\s]+)")
_IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_FORBIDDEN_VALUE_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----"),
    re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    re.compile(r"(?i)github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"(?i)\bsk-[A-Za-z0-9]{20,}"),
    re.compile(r"(?i)bitlocker.*recovery"),
    re.compile(
        r"(?i)\b[a-z0-9_]*(?:password|passwd|pwd|api[_-]?key|apikey|secret|token|authorization)"
        r"(?:\\?['\"])?\s*[:=]\s*(?:\\?['\"])?[^,\\\s}\"']+(?:\\?['\"])?"
    ),
)


def _hostname_alias(asset_id: str) -> str:
    return f"asset-{asset_id[-6:]}"


def scrub_text(value: str, *, host_aliases: Mapping[str, str] | None = None) -> tuple[str, list[str]]:
    """Public deterministic scrubber for advisory-facing text.

    Redacts secret-like content, local evidence/export paths, IP addresses,
    and optional hostname aliases. Returns the scrubbed string and the list
    of sanitization notes. Used by typed filters and by the firm report
    builder so redaction is by construction, not by request.
    """

    aliases = host_aliases if host_aliases is not None else {}
    notes: list[str] = []
    sanitized = value
    for forbidden_pattern in _FORBIDDEN_VALUE_PATTERNS:
        if forbidden_pattern.search(sanitized):
            sanitized = forbidden_pattern.sub("[redacted-sensitive-content]", sanitized)
            notes.append("secret-like string content redacted")
    if _EVIDENCE_PATH_PATTERN.search(sanitized):
        sanitized = _EVIDENCE_PATH_PATTERN.sub("[redacted-local-path]", sanitized)
        notes.append("local evidence/export path redacted")
    if _IP_PATTERN.search(sanitized):
        sanitized = _IP_PATTERN.sub("[redacted-ip]", sanitized)
        notes.append("ip address redacted")
    for original, alias in aliases.items():
        if original and original in sanitized:
            sanitized = sanitized.replace(original, alias)
            notes.append("hostname replaced with deterministic alias")
    return sanitized, notes


def _scrub_string(value: str, *, host_aliases: Mapping[str, str]) -> tuple[str, list[str]]:
    return scrub_text(value, host_aliases=host_aliases)


def sanitize_asset(asset: Asset) -> tuple[Asset, list[str]]:
    """Return a sanitized advisory-facing asset record."""

    alias = _hostname_alias(asset.asset_id)
    return asset.model_copy(update={"hostname": alias}), ["hostname replaced with deterministic alias"]


def sanitize_finding(finding: Finding, *, host_aliases: Mapping[str, str]) -> tuple[Finding, list[str]]:
    """Sanitize advisory-facing finding strings without changing typed structure."""

    title, notes = _scrub_string(finding.title, host_aliases=host_aliases)
    policy_basis, policy_notes = _scrub_string(finding.policy_basis, host_aliases=host_aliases)
    return finding.model_copy(update={"title": title, "policy_basis": policy_basis}), notes + policy_notes


def sanitize_delta(delta: Delta, *, host_aliases: Mapping[str, str]) -> tuple[Delta, list[str]]:
    """Sanitize advisory-facing delta strings without changing typed structure."""

    prior_value, prior_notes = _scrub_string(delta.prior_value, host_aliases=host_aliases)
    current_value, current_notes = _scrub_string(delta.current_value, host_aliases=host_aliases)
    return delta.model_copy(update={"prior_value": prior_value, "current_value": current_value}), prior_notes + current_notes


def payload_contains_secret_like_content(payload: Any) -> bool:
    """Return whether a Python payload still contains obvious secret-like content."""

    if isinstance(payload, dict):
        return any(payload_contains_secret_like_content(value) for value in payload.values())
    if isinstance(payload, list):
        return any(payload_contains_secret_like_content(value) for value in payload)
    if isinstance(payload, str):
        return any(pattern.search(payload) for pattern in _FORBIDDEN_VALUE_PATTERNS)
    return False


def stable_json(payload: object) -> str:
    """Return deterministic JSON used by FL-005 sanitization tests."""

    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
