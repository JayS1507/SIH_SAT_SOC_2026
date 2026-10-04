from __future__ import annotations

import hashlib
import os
from pathlib import Path
from dataclasses import dataclass


@dataclass
class Artifact:
    key: str
    sha256: str
    size: int


class ArtifactStore:
    def __init__(self) -> None:
        self.backend = os.getenv("ARTIFACT_STORAGE", "local").lower()
        self.root = Path(os.getenv("ARTIFACT_LOCAL_DIR", "/tmp/artifacts" if os.getenv("VERCEL") else "./artifacts"))
        self.bucket = os.getenv("S3_BUCKET", "")
        self._s3 = None
        if self.backend in {"s3", "minio"}:
            try:
                import boto3
                self._s3 = boto3.client("s3", endpoint_url=os.getenv("S3_ENDPOINT_URL") or None)
            except ImportError:
                self.backend = "local"

    def put(self, category: str, object_id: str, content: bytes, suffix: str = "bin") -> Artifact:
        digest = hashlib.sha256(content).hexdigest()
        key = f"{category}/{object_id}/{digest}.{suffix.lstrip('.')}"
        if self.backend in {"s3", "minio"} and self._s3 and self.bucket:
            try:
                self._s3.head_object(Bucket=self.bucket, Key=key)
            except Exception:
                self._s3.put_object(Bucket=self.bucket, Key=key, Body=content)
        else:
            path = self.root / key
            path.parent.mkdir(parents=True, exist_ok=True)
            if not path.exists():
                path.write_bytes(content)
        return Artifact(key=key, sha256=digest, size=len(content))


artifact_store = ArtifactStore()
