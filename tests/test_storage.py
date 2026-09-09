from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cryptography.fernet import Fernet

from jobber_mcp.storage import TokenBundle, TokenStore


def test_token_store_encrypts_secrets_at_rest_and_round_trips(tmp_path) -> None:
    database_path = tmp_path / "tokens.db"
    store = TokenStore(f"sqlite:///{database_path}", Fernet.generate_key().decode())
    expires_at = datetime.now(UTC) + timedelta(hours=1)
    expected = TokenBundle(
        access_token="access-token-value",
        refresh_token="refresh-token-value",
        expires_at=expires_at,
        account_id="account-1",
        account_name="Sow Home Services",
    )

    store.save_tokens(expected)

    assert store.get_tokens() == expected
    raw_database = database_path.read_bytes()
    assert b"access-token-value" not in raw_database
    assert b"refresh-token-value" not in raw_database
    assert b"Sow Home Services" not in raw_database


def test_oauth_flow_verifier_is_encrypted_and_state_is_single_use(tmp_path) -> None:
    database_path = tmp_path / "flows.db"
    store = TokenStore(f"sqlite:///{database_path}", Fernet.generate_key().decode())
    now = datetime.now(UTC)

    store.save_oauth_flow("opaque-state", "pkce-verifier-secret", now + timedelta(minutes=10))

    assert b"pkce-verifier-secret" not in database_path.read_bytes()
    assert store.consume_oauth_flow("opaque-state", now) == "pkce-verifier-secret"
    assert store.consume_oauth_flow("opaque-state", now) is None
