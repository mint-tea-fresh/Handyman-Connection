from __future__ import annotations

from cryptography.fernet import Fernet
from starlette.testclient import TestClient


def test_runtime_factory_builds_a_healthy_asgi_app(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("JOBBER_CLIENT_ID", "client-id")
    monkeypatch.setenv("JOBBER_CLIENT_SECRET", "client-secret")
    monkeypatch.setenv("APP_BASE_URL", "http://localhost:8000")
    monkeypatch.setenv("APP_ENCRYPTION_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("MCP_API_KEY", "m" * 32)
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'runtime.db'}")
    monkeypatch.setenv("EXPORT_DIR", str(tmp_path / "exports"))

    from jobber_mcp.runtime import create_application

    app = create_application()

    with TestClient(app) as client:
        response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "database": "ready"}
