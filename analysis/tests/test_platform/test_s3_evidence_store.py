"""S3-compatible evidence store contract tests (moto, dev-only).

Proves the adapter contract (put/get/exists, digest integrity) against a
real S3-compatible endpoint emulated by moto — no cloud required. Live
remote S3 remains a recorded limitation.
"""

from __future__ import annotations

import hashlib

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from secscan.platform.evidence.s3 import S3CompatibleEvidenceStore


@pytest.fixture()
def s3_store():
    with mock_aws():
        client = boto3.client("s3", region_name="us-east-1")
        client.create_bucket(Bucket="secscan-evidence")
        store = S3CompatibleEvidenceStore(
            bucket="secscan-evidence",
            endpoint_url="http://localhost:4566",
            region="us-east-1",
            prefix="test/",
        )
        store._client = client  # reuse the moto client deterministically
        yield store


def test_put_returns_sha256_and_get_roundtrips(s3_store) -> None:
    content = b"evidence payload"
    digest = s3_store.put(content)
    assert digest == hashlib.sha256(content).hexdigest()
    assert s3_store.exists(digest)
    assert s3_store.get(digest) == content


def test_content_addressing_integrity(s3_store) -> None:
    """A stored blob must equal its digest — corruption is detectable."""
    content = b"integrity check payload"
    digest = s3_store.put(content)
    assert hashlib.sha256(s3_store.get(digest)).hexdigest() == digest


def test_missing_key_raises(s3_store) -> None:
    with pytest.raises(ClientError):
        s3_store.get("f" * 64)
