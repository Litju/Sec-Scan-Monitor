"""S3-compatible evidence store adapter contract.

Vendor-neutral by construction: the S3 API itself is the contract (MinIO,
Ceph RGW, AWS S3, GCS S3-interop, etc.). The domain depends only on the
EvidenceStore port; this adapter is interchangeable.

The implementation uses boto3 (lazy import) which speaks the S3 API to any
S3-compatible endpoint. boto3 is an optional extra of the package
(`secscan-platform[s3]`), never a canonical-suite requirement.
"""

from __future__ import annotations

import hashlib
from typing import Any, cast


class S3CompatibleEvidenceStore:
    """Content-addressed blobs stored under an S3-compatible object key
    prefix. Keys are `<prefix>/<aa>/<bb>/<sha256>` so addressing matches the
    local backend semantics."""

    def __init__(
        self,
        *,
        endpoint_url: str,
        bucket: str,
        prefix: str = "evidence",
        region: str = "auto",
        aws_access_key_id: str | None = None,
        aws_secret_access_key: str | None = None,
        session_kwargs: dict[str, Any] | None = None,
    ) -> None:
        self._endpoint_url = endpoint_url
        self._bucket = bucket
        self._prefix = prefix.rstrip("/")
        self._region = region
        self._aws_access_key_id = aws_access_key_id
        self._aws_secret_access_key = aws_secret_access_key
        self._session_kwargs = session_kwargs or {}
        self._client: Any | None = None

    def _get_client(self) -> Any:
        if self._client is None:
            try:
                import boto3  # type: ignore
            except ImportError as exc:  # pragma: no cover - optional extra
                raise RuntimeError(
                    "S3CompatibleEvidenceStore requires the 's3' extra "
                    "(boto3). Install with: uv pip install 'boto3>=1.34'"
                ) from exc
            self._client = boto3.client(
                "s3",
                endpoint_url=self._endpoint_url,
                region_name=self._region,
                aws_access_key_id=self._aws_access_key_id,
                aws_secret_access_key=self._aws_secret_access_key,
                **self._session_kwargs,
            )
        return self._client

    @staticmethod
    def address(content: bytes) -> str:
        return hashlib.sha256(content).hexdigest()

    def _key(self, sha256: str) -> str:
        return f"{self._prefix}/{sha256[:2]}/{sha256[2:4]}/{sha256}"

    def put(self, content: bytes, *, content_type: str = "") -> str:
        sha256 = self.address(content)
        client = self._get_client()
        client.put_object(
            Bucket=self._bucket,
            Key=self._key(sha256),
            Body=content,
            ContentType=content_type or "application/octet-stream",
        )
        return sha256

    def get(self, sha256: str) -> bytes:
        client = self._get_client()
        response = client.get_object(Bucket=self._bucket, Key=self._key(sha256))
        return cast(bytes, response["Body"].read())

    def exists(self, sha256: str) -> bool:
        client = self._get_client()
        try:
            client.head_object(Bucket=self._bucket, Key=self._key(sha256))
            return True
        except Exception:  # botocore ClientError family; keep adapter-agnostic
            return False
