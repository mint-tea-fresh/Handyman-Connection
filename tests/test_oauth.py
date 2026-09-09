from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from cryptography.fernet import Fernet

from jobber_mcp.config import Settings
from jobber_mcp.oauth import InvalidOAuthState, OAuthService
from jobber_mcp.storage import TokenStore


def make_settings(tmp_path) -> Settings:
    return Settings.from_mapping(
        {
            "JOBBER_CLIENT_ID": "client-id",
            "JOBBER_CLIENT_SECRET": "client-secret",
            "APP_BASE_URL": "https://jobber.example.com",
            "APP_ENCRYPTION_KEY": Fernet.generate_key().decode(),
            "MCP_API_KEY": "m" * 32,
            "DATABASE_URL": f"sqlite:///{tmp_path / 'oauth.db'}",
        }
    )


def test_start_authorization_creates_pkce_url_and_persists_flow(tmp_path) -> None:
    now = datetime(2026, 9, 8, 12, 0, tzinfo=UTC)
    settings = make_settings(tmp_path)
    store = TokenStore(settings.database_url, settings.app_encryption_key)
    service = OAuthService(settings, store, clock=lambda: now)

    authorization_url = service.start_authorization()

    parsed = urlparse(authorization_url)
    params = parse_qs(parsed.query)
    assert f"{parsed.scheme}://{parsed.netloc}{parsed.path}" == settings.jobber_authorize_url
    assert params["response_type"] == ["code"]
    assert params["client_id"] == ["client-id"]
    assert params["redirect_uri"] == [settings.oauth_callback_url]
    assert params["code_challenge_method"] == ["S256"]
    state = params["state"][0]
    verifier = store.consume_oauth_flow(state, now)
    assert verifier is not None
    assert 43 <= len(verifier) <= 128
    expected_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    assert params["code_challenge"] == [expected_challenge]


@pytest.mark.asyncio
async def test_complete_authorization_exchanges_code_and_saves_account_tokens(tmp_path) -> None:
    now = datetime(2026, 9, 8, 12, 0, tzinfo=UTC)
    settings = make_settings(tmp_path)
    store = TokenStore(settings.database_url, settings.app_encryption_key)
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url == httpx.URL(settings.jobber_token_url):
            form = parse_qs(request.content.decode())
            assert form["grant_type"] == ["authorization_code"]
            assert form["code"] == ["one-time-code"]
            assert form["client_secret"] == ["client-secret"]
            assert form["redirect_uri"] == [settings.oauth_callback_url]
            assert len(form["code_verifier"][0]) >= 43
            return httpx.Response(
                200,
                json={
                    "access_token": "new-access",
                    "refresh_token": "new-refresh",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                },
            )
        assert request.url == httpx.URL(settings.jobber_graphql_url)
        assert request.headers["Authorization"] == "Bearer new-access"
        assert request.headers["X-JOBBER-GRAPHQL-VERSION"] == "2025-04-16"
        return httpx.Response(
            200,
            json={"data": {"account": {"id": "account-1", "name": "Sow Home Services"}}},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        service = OAuthService(settings, store, http_client=client, clock=lambda: now)
        authorization_url = service.start_authorization()
        state = parse_qs(urlparse(authorization_url).query)["state"][0]

        bundle = await service.complete_authorization("one-time-code", state)

    assert bundle == store.get_tokens()
    assert bundle.account_id == "account-1"
    assert bundle.account_name == "Sow Home Services"
    assert bundle.expires_at == datetime(2026, 9, 8, 13, 0, tzinfo=UTC)
    assert len(requests) == 2


@pytest.mark.asyncio
async def test_complete_authorization_rejects_unknown_or_replayed_state(tmp_path) -> None:
    settings = make_settings(tmp_path)
    store = TokenStore(settings.database_url, settings.app_encryption_key)
    service = OAuthService(settings, store)

    with pytest.raises(InvalidOAuthState, match="invalid, expired, or already used"):
        await service.complete_authorization("code", "unknown-state")
