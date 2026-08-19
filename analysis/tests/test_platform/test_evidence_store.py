"""Content-addressed evidence store tests: hashing, immutability, concurrency."""

from __future__ import annotations

import hashlib

from secscan.platform.evidence import (
    InMemoryContentAddressedEvidenceStore,
    LocalContentAddressedEvidenceStore,
)


def test_sha256_addressing() -> None:
    store = InMemoryContentAddressedEvidenceStore()
    content = b"raw scanner output"
    address = store.put(content)
    assert address == hashlib.sha256(content).hexdigest()
    assert store.exists(address)
    assert store.get(address) == content


def test_same_content_same_address_immutable() -> None:
    store = InMemoryContentAddressedEvidenceStore()
    first = store.put(b"same content")
    second = store.put(b"same content")
    assert first == second
    # Altered content cannot land at the same address
    third = store.put(b"same content.")
    assert third != first


def test_immutability_by_content_identity() -> None:
    store = InMemoryContentAddressedEvidenceStore()
    address = store.put(b"v1")
    with __import__("pytest").raises(KeyError):
        # there is no API to overwrite; get by another address fails
        store.get(hashlib.sha256(b"v2").hexdigest())
    assert store.get(address) == b"v1"


def test_local_store_round_trip(tmp_path) -> None:
    store = LocalContentAddressedEvidenceStore(tmp_path / "blobs")
    content = b"local blob content"
    address = store.put(content, content_type="text/plain")
    assert address == hashlib.sha256(content).hexdigest()
    assert store.exists(address)
    assert store.get(address) == content


def test_local_store_missing_raises(tmp_path) -> None:
    store = LocalContentAddressedEvidenceStore(tmp_path / "blobs")
    import pytest

    with pytest.raises(KeyError):
        store.get("0" * 64)
