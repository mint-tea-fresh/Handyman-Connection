from __future__ import annotations

import hmac
import re
from collections.abc import Callable
from datetime import datetime
from urllib.parse import urlparse

import httpx
from mcp.server.transport_security import TransportSecuritySettings
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route
from starlette.types import ASGIApp

from jobber_mcp.config import Settings
from jobber_mcp.jobber import JobberClient
from jobber_mcp.mcp_server import create_mcp_server
from jobber_mcp.oauth import InvalidOAuthState, OAuthService
from jobber_mcp.reporting import ReportingService
from jobber_mcp.storage import TokenStore


class BearerAuthMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, api_key: str) -> None:
        super().__init__(app)
        self.api_key = api_key

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        path = request.url.path
        protected = (
            path == "/mcp"
            or path.startswith("/mcp/")
            or path in {"/oauth/start", "/oauth/status"}
            or path.startswith("/exports/")
        )
        if protected:
            supplied = request.headers.get("Authorization", "")
            expected = f"Bearer {self.api_key}"
            if not hmac.compare_digest(supplied, expected):
                return JSONResponse(
                    {"error": "unauthorized"},
                    status_code=401,
                    headers={"WWW-Authenticate": "Bearer", "Cache-Control": "no-store"},
                )
        return await call_next(request)


def create_app(
    settings: Settings,
    *,
    http_client: httpx.AsyncClient | None = None,
    clock: Callable[[], datetime] | None = None,
) -> ASGIApp:
    store = TokenStore(settings.database_url, settings.app_encryption_key)
    oauth = OAuthService(settings, store, http_client=http_client, clock=clock)
    jobber = JobberClient(settings, store, http_client=http_client, clock=clock)
    reporting = ReportingService(jobber, settings.export_dir, settings.app_base_url)
    server = create_mcp_server(store, reporting)
    hostname = urlparse(settings.app_base_url).hostname or "localhost"
    app = server.streamable_http_app(
        streamable_http_path="/mcp",
        json_response=True,
        stateless_http=True,
        host=hostname,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=[hostname, f"{hostname}:*", "localhost:*", "127.0.0.1:*", "testserver"],
            allowed_origins=[settings.app_base_url],
        ),
    )

    async def health(_request: Request) -> JSONResponse:
        store.get_tokens()
        return JSONResponse(
            {"status": "ok", "database": "ready"},
            headers={"Cache-Control": "no-store"},
        )

    async def oauth_start(_request: Request) -> RedirectResponse:
        return RedirectResponse(
            oauth.start_authorization(),
            status_code=307,
            headers={"Cache-Control": "no-store"},
        )

    async def oauth_status(_request: Request) -> JSONResponse:
        tokens = store.get_tokens()
        content: dict[str, object] = {"connected": False}
        if tokens is not None:
            content = {
                "connected": True,
                "account_id": tokens.account_id,
                "account_name": tokens.account_name,
                "access_token_expires_at": tokens.expires_at.isoformat(),
            }
        return JSONResponse(content, headers={"Cache-Control": "no-store"})

    async def oauth_callback(request: Request) -> JSONResponse:
        code = request.query_params.get("code")
        state = request.query_params.get("state")
        if not code or not state:
            return JSONResponse(
                {"error": "invalid_oauth_callback"},
                status_code=400,
                headers={"Cache-Control": "no-store"},
            )
        try:
            tokens = await oauth.complete_authorization(code, state)
        except InvalidOAuthState:
            return JSONResponse(
                {"error": "invalid_oauth_state"},
                status_code=400,
                headers={"Cache-Control": "no-store"},
            )
        except (httpx.HTTPError, KeyError, TypeError, ValueError):
            return JSONResponse(
                {"error": "jobber_oauth_failed"},
                status_code=502,
                headers={"Cache-Control": "no-store"},
            )
        return JSONResponse(
            {"connected": True, "account_name": tokens.account_name},
            headers={"Cache-Control": "no-store"},
        )

    async def download_export(request: Request) -> Response:
        filename = request.path_params["filename"]
        allowed = r"(?:clients|requests|quotes|jobs|invoices)-[0-9a-f]{16}\.csv"
        if re.fullmatch(allowed, filename) is None:
            return JSONResponse({"error": "not_found"}, status_code=404)
        path = settings.export_dir / filename
        if not path.is_file():
            return JSONResponse({"error": "not_found"}, status_code=404)
        return FileResponse(
            path,
            media_type="text/csv; charset=utf-8",
            filename=filename,
            headers={"Cache-Control": "no-store"},
        )

    app.routes.insert(0, Route("/health", health, methods=["GET"]))
    app.routes.insert(1, Route("/oauth/start", oauth_start, methods=["GET"]))
    app.routes.insert(2, Route("/oauth/status", oauth_status, methods=["GET"]))
    app.routes.insert(3, Route("/oauth/callback", oauth_callback, methods=["GET"]))
    app.routes.insert(4, Route("/exports/{filename:str}", download_export, methods=["GET"]))
    app.add_middleware(BearerAuthMiddleware, api_key=settings.mcp_api_key)
    app.state.settings = settings
    app.state.store = store
    app.state.oauth = oauth
    app.state.reporting = reporting
    return app
