import hashlib
import os
from pathlib import Path

import jwt
from fastapi.testclient import TestClient

try:
    from backend.app.artifacts import ArtifactStore
    from backend.app.main import app
except ModuleNotFoundError:
    from app.artifacts import ArtifactStore
    from app.main import app


def test_auth_disabled_and_request_id(monkeypatch):
    monkeypatch.setenv("DEMO_AUTH_DISABLED", "true")
    response = TestClient(app).get("/api/v1/readiness", headers={"X-Request-ID": "test-correlation"})
    assert response.status_code == 200
    assert response.headers["X-Request-ID"] == "test-correlation"
    assert response.json()["status"] == "ready"


def test_jwt_role_guard(monkeypatch):
    monkeypatch.setenv("DEMO_AUTH_DISABLED", "false")
    monkeypatch.setenv("JWT_SECRET", "x" * 32)
    client = TestClient(app)
    token = jwt.encode({"sub": "reviewer", "roles": ["reviewer"]}, "x" * 32, algorithm="HS256")
    assert client.post("/api/v1/submissions", headers={"Authorization": f"Bearer {token}"},
                       json={"name": "forbidden", "records": []}).status_code == 403
    provider = jwt.encode({"sub": "provider", "role": "data_provider"}, "x" * 32, algorithm="HS256")
    assert client.post("/api/v1/submissions", headers={"Authorization": f"Bearer {provider}"},
                       json={"name": "allowed", "records": []}).status_code == 201


def test_immutable_artifact_hashing(tmp_path: Path):
    store = ArtifactStore()
    store.root = tmp_path
    content = b"evidence"
    artifact = store.put("submissions", "id-1", content, "bin")
    assert artifact.sha256 == hashlib.sha256(content).hexdigest()
    assert (tmp_path / artifact.key).read_bytes() == content
    store.put("submissions", "id-1", b"changed", "bin")
    assert (tmp_path / artifact.key).read_bytes() == content
