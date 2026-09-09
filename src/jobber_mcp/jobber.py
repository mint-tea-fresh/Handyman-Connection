from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from jobber_mcp.config import Settings
from jobber_mcp.storage import TokenBundle, TokenStore

ACCOUNT_QUERY = "query GetAccount { account { id name } }"


class NotConnectedError(RuntimeError):
    """Raised when no Jobber account has completed OAuth."""


class JobberAPIError(RuntimeError):
    """Raised for a sanitized Jobber API failure."""


class JobberClient:
    def __init__(
        self,
        settings: Settings,
        store: TokenStore,
        *,
        http_client: httpx.AsyncClient | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.settings = settings
        self.store = store
        self._http_client = http_client
        self._clock = clock or (lambda: datetime.now(UTC))
        self._refresh_lock = asyncio.Lock()

    async def _post(self, url: str, **kwargs: Any) -> httpx.Response:
        if self._http_client is not None:
            return await self._http_client.post(url, **kwargs)
        async with httpx.AsyncClient(timeout=30.0) as client:
            return await client.post(url, **kwargs)

    async def _refresh_token(self, stale_access_token: str) -> str:
        async with self._refresh_lock:
            bundle = self.store.get_tokens()
            if bundle is None:
                raise NotConnectedError("Jobber is not connected; complete OAuth first")
            if bundle.access_token != stale_access_token:
                return bundle.access_token
            response = await self._post(
                self.settings.jobber_token_url,
                data={
                    "client_id": self.settings.jobber_client_id,
                    "client_secret": self.settings.jobber_client_secret,
                    "grant_type": "refresh_token",
                    "refresh_token": bundle.refresh_token,
                },
            )
            response.raise_for_status()
            payload = response.json()
            rotated = TokenBundle(
                access_token=payload["access_token"],
                refresh_token=payload["refresh_token"],
                expires_at=self._clock() + timedelta(seconds=int(payload["expires_in"])),
                account_id=bundle.account_id,
                account_name=bundle.account_name,
            )
            self.store.save_tokens(rotated)
            return rotated.access_token

    async def _access_token(self) -> str:
        bundle = self.store.get_tokens()
        if bundle is None:
            raise NotConnectedError("Jobber is not connected; complete OAuth first")
        if bundle.expires_at > self._clock() + timedelta(seconds=120):
            return bundle.access_token
        return await self._refresh_token(bundle.access_token)

    async def _graphql_request(
        self, query: str, variables: dict[str, Any], access_token: str
    ) -> httpx.Response:
        return await self._post(
            self.settings.jobber_graphql_url,
            headers={
                "Authorization": f"Bearer {access_token}",
                "X-JOBBER-GRAPHQL-VERSION": self.settings.jobber_api_version,
                "Content-Type": "application/json",
            },
            json={"query": query, "variables": variables},
        )

    async def execute(
        self, query: str, variables: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        operation_header = query.split("{", 1)[0].lower()
        if "mutation" in operation_header:
            raise JobberAPIError("Jobber connector is read-only; mutations are forbidden")
        request_variables = variables or {}
        access_token = await self._access_token()
        response = await self._graphql_request(query, request_variables, access_token)
        if response.status_code == 401:
            access_token = await self._refresh_token(access_token)
            response = await self._graphql_request(query, request_variables, access_token)
        response.raise_for_status()
        payload = response.json()
        if payload.get("errors") or not isinstance(payload.get("data"), dict):
            raise JobberAPIError("Jobber GraphQL request failed")
        return payload["data"]

    async def paginate(
        self,
        query: str,
        connection_name: str,
        *,
        variables: dict[str, Any] | None = None,
        page_size: int = 50,
        max_records: int = 500,
    ) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        cursor: str | None = None
        while len(records) < max_records:
            page_variables = dict(variables or {})
            page_variables.update(
                {
                    "limit": min(page_size, max_records - len(records)),
                    "cursor": cursor,
                }
            )
            data = await self.execute(query, page_variables)
            connection = data[connection_name]
            records.extend(connection["nodes"])
            records = records[:max_records]
            page_info = connection["pageInfo"]
            if not page_info["hasNextPage"] or len(records) >= max_records:
                break
            cursor = page_info.get("endCursor")
            if not cursor:
                raise JobberAPIError("Jobber pagination response was invalid")
        return records
