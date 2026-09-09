from __future__ import annotations

import base64
import hashlib
import secrets
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from urllib.parse import urlencode

import httpx

from jobber_mcp.config import Settings
from jobber_mcp.storage import TokenBundle, TokenStore


class InvalidOAuthState(ValueError):
    """Raised when an OAuth state is missing, expired, or already used."""


class OAuthService:
    def __init__(
        self,
        settings: Settings,
        store: TokenStore,
        *,
        clock: Callable[[], datetime] | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self.settings = settings
        self.store = store
        self._clock = clock or (lambda: datetime.now(UTC))
        self._http_client = http_client

    def start_authorization(self) -> str:
        state = secrets.token_urlsafe(32)
        verifier = secrets.token_urlsafe(64)
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode()).digest()
        ).rstrip(b"=").decode()
        self.store.save_oauth_flow(state, verifier, self._clock() + timedelta(minutes=10))
        params = {
            "response_type": "code",
            "client_id": self.settings.jobber_client_id,
            "redirect_uri": self.settings.oauth_callback_url,
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        return f"{self.settings.jobber_authorize_url}?{urlencode(params)}"

    async def _post(self, url: str, **kwargs: object) -> httpx.Response:
        if self._http_client is not None:
            return await self._http_client.post(url, **kwargs)
        async with httpx.AsyncClient(timeout=30.0) as client:
            return await client.post(url, **kwargs)

    async def complete_authorization(self, code: str, state: str) -> TokenBundle:
        verifier = self.store.consume_oauth_flow(state, self._clock())
        if verifier is None:
            raise InvalidOAuthState("OAuth state is invalid, expired, or already used")
        token_response = await self._post(
            self.settings.jobber_token_url,
            data={
                "client_id": self.settings.jobber_client_id,
                "client_secret": self.settings.jobber_client_secret,
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self.settings.oauth_callback_url,
                "code_verifier": verifier,
            },
        )
        token_response.raise_for_status()
        token_data = token_response.json()
        account_response = await self._post(
            self.settings.jobber_graphql_url,
            headers={
                "Authorization": f"Bearer {token_data['access_token']}",
                "X-JOBBER-GRAPHQL-VERSION": self.settings.jobber_api_version,
                "Content-Type": "application/json",
            },
            json={"query": "query GetAccount { account { id name } }"},
        )
        account_response.raise_for_status()
        account_data = account_response.json()["data"]["account"]
        bundle = TokenBundle(
            access_token=token_data["access_token"],
            refresh_token=token_data["refresh_token"],
            expires_at=self._clock() + timedelta(seconds=int(token_data["expires_in"])),
            account_id=account_data["id"],
            account_name=account_data["name"],
        )
        self.store.save_tokens(bundle)
        return bundle
