"""Content-addressed evidence store.

Implements the EvidenceStore port with SHA-256 addressing and immutable
writes by content identity. Local filesystem backend for deterministic
dev/test; an S3-compatible adapter contract is provided separately.
"""

from __future__ import annotations

import hashlib
import pathlib
import re
import tempfile
import threading


class LocalContentAddressedEvidenceStore:
    """Filesystem backend: blobs at <root>/<aa>/<bb>/<sha256>.

    Content addressing gives immutable-by-content writes for free: writing
    the same content twice yields the same address; different content can
    never overwrite an existing blob (addresses differ).
    """

    def __init__(self, root: pathlib.Path | str) -> None:
        self._root = pathlib.Path(root)
        self._root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    @staticmethod
    def address(content: bytes) -> str:
        return hashlib.sha256(content).hexdigest()

    def _path(self, sha256: str) -> pathlib.Path:
        return self._root / sha256[:2] / sha256[2:4] / sha256

    def put(self, content: bytes, *, content_type: str = "") -> str:
        sha256 = self.address(content)
        target = self._path(sha256)
        with self._lock:
            if not target.exists():
                target.parent.mkdir(parents=True, exist_ok=True)
                tmp = target.with_suffix(".tmp")
                tmp.write_bytes(content)
                # atomic-ish rename on same filesystem; Windows may need
                # replace if a concurrent writer created the file meanwhile
                try:
                    tmp.replace(target)
                except FileExistsError:
                    tmp.unlink()
        return sha256

    def get(self, sha256: str) -> bytes:
        target = self._path(sha256)
        if not target.is_file():
            raise KeyError(f"no blob at content address {sha256}")
        return target.read_bytes()

    def exists(self, sha256: str) -> bool:
        return self._path(sha256).is_file()


class InMemoryContentAddressedEvidenceStore:
    """Deterministic in-memory backend for unit tests (not canonical state)."""

    def __init__(self) -> None:
        self._blobs: dict[str, bytes] = {}

    def put(self, content: bytes, *, content_type: str = "") -> str:
        sha256 = hashlib.sha256(content).hexdigest()
        self._blobs.setdefault(sha256, content)
        return sha256

    def get(self, sha256: str) -> bytes:
        if sha256 not in self._blobs:
            raise KeyError(f"no blob at content address {sha256}")
        return self._blobs[sha256]

    def exists(self, sha256: str) -> bool:
        return sha256 in self._blobs


class VercelBlobEvidenceStore:
    """Private Vercel Blob adapter with content-addressed, immutable writes."""

    _DIGEST = re.compile(r"^[0-9a-f]{64}$")

    def __init__(self, token: str | None = None) -> None:
        try:
            from vercel.blob import BlobClient
        except ImportError as exc:  # pragma: no cover - exercised in hosted build
            raise RuntimeError("Vercel Blob SDK is required for hosted evidence") from exc
        self._client = BlobClient(token=token)

    @classmethod
    def _path(cls, sha256: str) -> str:
        if not cls._DIGEST.fullmatch(sha256):
            raise ValueError("evidence address must be a lowercase SHA-256 digest")
        return f"evidence/{sha256}"

    def put(self, content: bytes, *, content_type: str = "") -> str:
        sha256 = hashlib.sha256(content).hexdigest()
        path = self._path(sha256)
        try:
            self._client.put(
                path,
                content,
                access="private",
                content_type=content_type or "application/octet-stream",
                overwrite=False,
            )
        except Exception as exc:
            # A replay may race an already completed immutable write. Confirm
            # the canonical content before treating the conflict as success.
            try:
                existing = self._client.get(path, access="private", use_cache=False)
                if hashlib.sha256(existing.content).hexdigest() != sha256:
                    raise RuntimeError("private evidence content-address collision") from exc
            except Exception:
                raise RuntimeError("private evidence write failed") from exc
        return sha256

    def get(self, sha256: str) -> bytes:
        path = self._path(sha256)
        try:
            result = self._client.get(path, access="private", use_cache=False)
        except Exception as exc:
            raise KeyError("private evidence object unavailable") from exc
        content = bytes(result.content)
        if hashlib.sha256(content).hexdigest() != sha256:
            raise RuntimeError("private evidence digest verification failed")
        return content


def make_local_store(root: pathlib.Path | str | None = None) -> LocalContentAddressedEvidenceStore:
    """Create a local store (default: platform temp dir, deterministic per run)."""
    if root is None:
        root = pathlib.Path(tempfile.gettempdir()) / "secscan-evidence"
    return LocalContentAddressedEvidenceStore(root)
