from __future__ import annotations

import base64
import hashlib
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.fernet import Fernet


class ConfigError(ValueError):
    """Raised when startup configuration is missing or unsafe."""


@dataclass(frozen=True, slots=True)
class Settings:
    jobber_client_id: str
    jobber_client_secret: str = field(repr=False)
    app_base_url: str
    app_encryption_key: str = field(repr=False)
    mcp_api_key: str = field(repr=False)
    database_url: str = "sqlite:///./jobber_mcp.db"
    jobber_api_version: str = "2025-04-16"
    jobber_authorize_url: str = "https://api.getjobber.com/api/oauth/authorize"
    jobber_token_url: str = "https://api.getjobber.com/api/oauth/token"  # noqa: S105
    jobber_graphql_url: str = "https://api.getjobber.com/api/graphql"
    export_dir: Path = Path("exports")

    @property
    def oauth_callback_url(self) -> str:
        return f"{self.app_base_url}/oauth/callback"

    @classmethod
    def from_mapping(cls, values: Mapping[str, str]) -> Settings:
        database_url = values.get("DATABASE_URL", "sqlite:///./jobber_mcp.db")
        if database_url.startswith("postgres://"):
            database_url = "postgresql+psycopg://" + database_url.removeprefix("postgres://")
        elif database_url.startswith("postgresql://"):
            database_url = "postgresql+psycopg://" + database_url.removeprefix("postgresql://")
        app_base_url = values.get("APP_BASE_URL") or values.get("RENDER_EXTERNAL_URL")
        if not app_base_url:
            raise ConfigError("Missing required setting: APP_BASE_URL")
        raw_encryption_key = values.get("APP_ENCRYPTION_KEY")
        if not raw_encryption_key:
            raise ConfigError("Missing required setting: APP_ENCRYPTION_KEY")
        try:
            Fernet(raw_encryption_key.encode())
            encryption_key = raw_encryption_key
        except (ValueError, TypeError):
            if len(raw_encryption_key) < 32:
                raise ConfigError(
                    "APP_ENCRYPTION_KEY must be a Fernet key or at least 32 characters"
                ) from None
            encryption_key = base64.urlsafe_b64encode(
                hashlib.sha256(raw_encryption_key.encode()).digest()
            ).decode()
        try:
            settings = cls(
                jobber_client_id=values["JOBBER_CLIENT_ID"],
                jobber_client_secret=values["JOBBER_CLIENT_SECRET"],
                app_base_url=app_base_url.rstrip("/"),
                app_encryption_key=encryption_key,
                mcp_api_key=values["MCP_API_KEY"],
                database_url=database_url,
                jobber_api_version=values.get("JOBBER_API_VERSION", "2025-04-16"),
                export_dir=Path(values.get("EXPORT_DIR", "exports")),
            )
        except KeyError as exc:
            raise ConfigError(f"Missing required setting: {exc.args[0]}") from None

        if not (
            settings.app_base_url.startswith("https://")
            or settings.app_base_url.startswith("http://localhost")
            or settings.app_base_url.startswith("http://127.0.0.1")
        ):
            raise ConfigError("APP_BASE_URL must use HTTPS outside local development")
        if len(settings.mcp_api_key) < 32:
            raise ConfigError("MCP_API_KEY must contain at least 32 characters")
        return settings

    @classmethod
    def from_env(cls) -> Settings:
        return cls.from_mapping(os.environ)
