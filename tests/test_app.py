from __future__ import annotations

import asyncio
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx
from cryptography.fernet import Fernet
from starlette.testclient import TestClient

from jobber_mcp.app import create_app
from jobber_mcp.config import Settings


def make_settings(tmp_path: Path) -> Settings:
    return Settings.from_mapping(
        {
            "JOBBER_CLIENT_ID": "client-id",
            "JOBBER_CLIENT_SECRET": "client-secret",
            "APP_BASE_URL": "https://jobber.example.com",
            "APP_ENCRYPTION_KEY": Fernet.generate_key().decode(),
            "MCP_API_KEY": "private-mcp-key-" + "x" * 32,
            "DATABASE_URL": f"sqlite:///{tmp_path / 'app.db'}",
            "EXPORT_DIR": str(tmp_path / "exports"),
        }
    )


def test_health_endpoint_is_public_and_reports_database_readiness(tmp_path: Path) -> None:
    app = create_app(make_settings(tmp_path))

    with TestClient(app) as client:
        response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "database": "ready"}
    assert "cache-control" in response.headers


def test_private_routes_reject_missing_or_invalid_bearer_token(tmp_path: Path) -> None:
    app = create_app(make_settings(tmp_path))

    with TestClient(app) as client:
        missing = client.get("/oauth/status")
        invalid = client.get("/oauth/status", headers={"Authorization": "Bearer wrong"})
        mcp_missing = client.post("/mcp", json={})

    assert missing.status_code == 401
    assert invalid.status_code == 401
    assert mcp_missing.status_code == 401
    assert missing.headers["WWW-Authenticate"] == "Bearer"
    assert missing.json() == {"error": "unauthorized"}


def test_oauth_start_and_status_are_available_to_authenticated_admin(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    app = create_app(settings)
    headers = {"Authorization": f"Bearer {settings.mcp_api_key}"}

    with TestClient(app) as client:
        status = client.get("/oauth/status", headers=headers)
        start = client.get("/oauth/start", headers=headers, follow_redirects=False)

    assert status.status_code == 200
    assert status.json() == {"connected": False}
    assert status.headers["Cache-Control"] == "no-store"
    assert start.status_code == 307
    assert start.headers["location"].startswith(settings.jobber_authorize_url)
    assert "code_challenge_method=S256" in start.headers["location"]


def test_oauth_callback_is_public_validates_state_and_connects_account(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url == httpx.URL(settings.jobber_token_url):
            return httpx.Response(
                200,
                json={
                    "access_token": "new-access",
                    "refresh_token": "new-refresh",
                    "expires_in": 3600,
                },
            )
        return httpx.Response(
            200,
            json={"data": {"account": {"id": "account-1", "name": "Sow Home Services"}}},
        )

    http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    app = create_app(settings, http_client=http_client)
    headers = {"Authorization": f"Bearer {settings.mcp_api_key}"}
    try:
        with TestClient(app) as client:
            start = client.get("/oauth/start", headers=headers, follow_redirects=False)
            state = parse_qs(urlparse(start.headers["location"]).query)["state"][0]
            callback = client.get(
                "/oauth/callback",
                params={"code": "one-time-code", "state": state},
            )
            status = client.get("/oauth/status", headers=headers)
    finally:
        asyncio.run(http_client.aclose())

    assert callback.status_code == 200
    assert callback.json() == {"connected": True, "account_name": "Sow Home Services"}
    assert "new-access" not in callback.text
    assert status.json()["connected"] is True
    assert status.json()["account_id"] == "account-1"


def test_authenticated_csv_download_serves_only_files_inside_export_directory(
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
    settings.export_dir.mkdir(parents=True)
    exported = settings.export_dir / "clients-0123456789abcdef.csv"
    exported.write_text("id,name\n1,Jane\n", encoding="utf-8")
    outside = tmp_path / "secret.csv"
    outside.write_text("private", encoding="utf-8")
    app = create_app(settings)
    headers = {"Authorization": f"Bearer {settings.mcp_api_key}"}

    with TestClient(app) as client:
        downloaded = client.get("/exports/clients-0123456789abcdef.csv", headers=headers)
        missing = client.get("/exports/secret.csv", headers=headers)

    assert downloaded.status_code == 200
    assert downloaded.headers["content-type"].startswith("text/csv")
    assert downloaded.text == "id,name\n1,Jane\n"
    assert missing.status_code == 404
    assert "private" not in missing.text
