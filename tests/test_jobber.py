from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs

import httpx
import pytest
from cryptography.fernet import Fernet

from jobber_mcp.config import Settings
from jobber_mcp.jobber import ACCOUNT_QUERY, JobberAPIError, JobberClient
from jobber_mcp.storage import TokenBundle, TokenStore


def make_settings(tmp_path) -> Settings:
    return Settings.from_mapping(
        {
            "JOBBER_CLIENT_ID": "client-id",
            "JOBBER_CLIENT_SECRET": "client-secret",
            "APP_BASE_URL": "https://jobber.example.com",
            "APP_ENCRYPTION_KEY": Fernet.generate_key().decode(),
            "MCP_API_KEY": "m" * 32,
            "DATABASE_URL": f"sqlite:///{tmp_path / 'jobber.db'}",
        }
    )


@pytest.mark.asyncio
async def test_expired_access_token_refreshes_and_persists_rotated_pair(tmp_path) -> None:
    now = datetime(2026, 9, 8, 12, 0, tzinfo=UTC)
    settings = make_settings(tmp_path)
    store = TokenStore(settings.database_url, settings.app_encryption_key)
    store.save_tokens(
        TokenBundle(
            access_token="old-access",
            refresh_token="old-refresh",
            expires_at=now - timedelta(seconds=1),
            account_id="account-1",
            account_name="Sow Home Services",
        )
    )
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url == httpx.URL(settings.jobber_token_url):
            form = parse_qs(request.content.decode())
            assert form == {
                "client_id": ["client-id"],
                "client_secret": ["client-secret"],
                "grant_type": ["refresh_token"],
                "refresh_token": ["old-refresh"],
            }
            return httpx.Response(
                200,
                json={
                    "access_token": "rotated-access",
                    "refresh_token": "rotated-refresh",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                },
            )
        assert request.headers["Authorization"] == "Bearer rotated-access"
        assert request.headers["X-JOBBER-GRAPHQL-VERSION"] == "2025-04-16"
        return httpx.Response(200, json={"data": {"account": {"id": "account-1"}}})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        client = JobberClient(settings, store, http_client=http_client, clock=lambda: now)
        result = await client.execute(ACCOUNT_QUERY)

    assert result == {"account": {"id": "account-1"}}
    saved = store.get_tokens()
    assert saved is not None
    assert saved.access_token == "rotated-access"
    assert saved.refresh_token == "rotated-refresh"
    assert saved.expires_at == now + timedelta(hours=1)
    assert len(requests) == 2


@pytest.mark.asyncio
async def test_unauthorized_graphql_response_refreshes_and_retries_once(tmp_path) -> None:
    now = datetime(2026, 9, 8, 12, 0, tzinfo=UTC)
    settings = make_settings(tmp_path)
    store = TokenStore(settings.database_url, settings.app_encryption_key)
    store.save_tokens(
        TokenBundle(
            access_token="apparently-valid",
            refresh_token="refresh-before-401",
            expires_at=now + timedelta(minutes=30),
            account_id="account-1",
            account_name="Sow Home Services",
        )
    )
    graphql_attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal graphql_attempts
        if request.url == httpx.URL(settings.jobber_token_url):
            return httpx.Response(
                200,
                json={
                    "access_token": "access-after-401",
                    "refresh_token": "refresh-after-401",
                    "expires_in": 3600,
                },
            )
        graphql_attempts += 1
        if graphql_attempts == 1:
            assert request.headers["Authorization"] == "Bearer apparently-valid"
            return httpx.Response(401, json={"error": "invalid_token"})
        assert request.headers["Authorization"] == "Bearer access-after-401"
        return httpx.Response(200, json={"data": {"account": {"id": "account-1"}}})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        client = JobberClient(settings, store, http_client=http_client, clock=lambda: now)
        result = await client.execute(ACCOUNT_QUERY)

    assert result["account"]["id"] == "account-1"
    assert graphql_attempts == 2
    saved = store.get_tokens()
    assert saved is not None
    assert saved.refresh_token == "refresh-after-401"


@pytest.mark.asyncio
async def test_paginate_follows_cursors_and_honors_max_records(tmp_path) -> None:
    now = datetime(2026, 9, 8, 12, 0, tzinfo=UTC)
    settings = make_settings(tmp_path)
    store = TokenStore(settings.database_url, settings.app_encryption_key)
    store.save_tokens(
        TokenBundle(
            access_token="access",
            refresh_token="refresh",
            expires_at=now + timedelta(minutes=30),
            account_id="account-1",
            account_name="Sow Home Services",
        )
    )
    cursors: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        variables = json.loads(request.content)["variables"]
        cursors.append(variables["cursor"])
        if variables["cursor"] is None:
            nodes = [{"id": "1"}, {"id": "2"}]
            page_info = {"hasNextPage": True, "endCursor": "next-page"}
        else:
            nodes = [{"id": "3"}, {"id": "4"}]
            page_info = {"hasNextPage": False, "endCursor": None}
        return httpx.Response(
            200,
            json={"data": {"clients": {"nodes": nodes, "pageInfo": page_info}}},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        client = JobberClient(settings, store, http_client=http_client, clock=lambda: now)
        result = await client.paginate(
            "query ($limit: Int!, $cursor: String) { clients(first: $limit, after: $cursor) "
            "{ nodes { id } pageInfo { hasNextPage endCursor } } }",
            "clients",
            page_size=2,
            max_records=3,
        )

    assert result == [{"id": "1"}, {"id": "2"}, {"id": "3"}]
    assert cursors == [None, "next-page"]


@pytest.mark.asyncio
async def test_graphql_errors_are_raised_without_leaking_remote_details(tmp_path) -> None:
    now = datetime(2026, 9, 8, 12, 0, tzinfo=UTC)
    settings = make_settings(tmp_path)
    store = TokenStore(settings.database_url, settings.app_encryption_key)
    store.save_tokens(
        TokenBundle(
            access_token="access",
            refresh_token="refresh",
            expires_at=now + timedelta(minutes=30),
            account_id="account-1",
            account_name="Sow Home Services",
        )
    )

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"errors": [{"message": "Client Jane Doe token=private-value"}]},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        client = JobberClient(settings, store, http_client=http_client, clock=lambda: now)
        with pytest.raises(JobberAPIError) as raised:
            await client.execute(ACCOUNT_QUERY)

    assert str(raised.value) == "Jobber GraphQL request failed"


@pytest.mark.asyncio
async def test_execute_rejects_graphql_mutations_before_network_access(tmp_path) -> None:
    now = datetime(2026, 9, 8, 12, 0, tzinfo=UTC)
    settings = make_settings(tmp_path)
    store = TokenStore(settings.database_url, settings.app_encryption_key)
    store.save_tokens(
        TokenBundle(
            access_token="access",
            refresh_token="refresh",
            expires_at=now + timedelta(minutes=30),
            account_id="account-1",
            account_name="Sow Home Services",
        )
    )

    def handler(_request: httpx.Request) -> httpx.Response:
        pytest.fail("mutation must be rejected before network access")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        client = JobberClient(settings, store, http_client=http_client, clock=lambda: now)
        with pytest.raises(JobberAPIError, match="read-only"):
            await client.execute("mutation Dangerous { clientCreate(input: {}) { client { id } } }")
