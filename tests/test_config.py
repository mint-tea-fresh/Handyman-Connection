import pytest
from cryptography.fernet import Fernet

from jobber_mcp.config import ConfigError, Settings


def test_settings_load_required_values_and_safe_defaults() -> None:
    settings = Settings.from_mapping(
        {
            "JOBBER_CLIENT_ID": "client-id",
            "JOBBER_CLIENT_SECRET": "client-secret",
            "APP_BASE_URL": "https://jobber.example.com/",
            "APP_ENCRYPTION_KEY": Fernet.generate_key().decode(),
            "MCP_API_KEY": "a" * 32,
        }
    )

    assert settings.app_base_url == "https://jobber.example.com"
    assert settings.oauth_callback_url == "https://jobber.example.com/oauth/callback"
    assert settings.database_url == "sqlite:///./jobber_mcp.db"
    assert settings.jobber_api_version == "2025-04-16"
    assert settings.export_dir.name == "exports"


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"APP_BASE_URL": "http://public.example.com"}, "APP_BASE_URL"),
        ({"APP_ENCRYPTION_KEY": "not-a-fernet-key"}, "APP_ENCRYPTION_KEY"),
        ({"MCP_API_KEY": "short"}, "MCP_API_KEY"),
    ],
)
def test_settings_reject_insecure_configuration(override: dict[str, str], message: str) -> None:
    values = {
        "JOBBER_CLIENT_ID": "client-id",
        "JOBBER_CLIENT_SECRET": "client-secret",
        "APP_BASE_URL": "https://jobber.example.com",
        "APP_ENCRYPTION_KEY": Fernet.generate_key().decode(),
        "MCP_API_KEY": "a" * 32,
    }
    values.update(override)

    with pytest.raises(ConfigError, match=message):
        Settings.from_mapping(values)


def test_settings_repr_does_not_expose_secrets() -> None:
    settings = Settings.from_mapping(
        {
            "JOBBER_CLIENT_ID": "client-id",
            "JOBBER_CLIENT_SECRET": "super-secret",
            "APP_BASE_URL": "https://jobber.example.com",
            "APP_ENCRYPTION_KEY": Fernet.generate_key().decode(),
            "MCP_API_KEY": "private-" + "a" * 32,
        }
    )

    rendered = repr(settings)
    assert "super-secret" not in rendered
    assert "private-" not in rendered
    assert settings.app_encryption_key not in rendered


def test_render_postgres_url_uses_installed_psycopg_driver() -> None:
    settings = Settings.from_mapping(
        {
            "JOBBER_CLIENT_ID": "client-id",
            "JOBBER_CLIENT_SECRET": "client-secret",
            "APP_BASE_URL": "https://jobber.example.com",
            "APP_ENCRYPTION_KEY": Fernet.generate_key().decode(),
            "MCP_API_KEY": "m" * 32,
            "DATABASE_URL": "postgres://user@host/database",
        }
    )

    assert settings.database_url == "postgresql+psycopg://user@host/database"


def test_settings_accept_render_generated_encryption_secret() -> None:
    raw_secret = "render-generated-secret-that-is-at-least-32-characters"

    settings = Settings.from_mapping(
        {
            "JOBBER_CLIENT_ID": "client-id",
            "JOBBER_CLIENT_SECRET": "client-secret",
            "APP_BASE_URL": "https://jobber.example.com",
            "APP_ENCRYPTION_KEY": raw_secret,
            "MCP_API_KEY": "m" * 32,
        }
    )

    assert settings.app_encryption_key != raw_secret
    Fernet(settings.app_encryption_key.encode())


def test_settings_use_render_external_url_when_app_base_url_is_omitted() -> None:
    settings = Settings.from_mapping(
        {
            "JOBBER_CLIENT_ID": "client-id",
            "JOBBER_CLIENT_SECRET": "client-secret",
            "RENDER_EXTERNAL_URL": "https://sow-jobber-mcp.onrender.com/",
            "APP_ENCRYPTION_KEY": Fernet.generate_key().decode(),
            "MCP_API_KEY": "m" * 32,
        }
    )

    assert settings.app_base_url == "https://sow-jobber-mcp.onrender.com"
