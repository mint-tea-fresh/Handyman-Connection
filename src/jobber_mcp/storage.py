from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import Column, Float, Integer, LargeBinary, MetaData, String, Table, create_engine
from sqlalchemy.engine import Engine


class StorageError(RuntimeError):
    """Raised when encrypted persisted data cannot be read safely."""


@dataclass(frozen=True, slots=True)
class TokenBundle:
    access_token: str = field(repr=False)
    refresh_token: str = field(repr=False)
    expires_at: datetime
    account_id: str
    account_name: str


metadata = MetaData()
tokens_table = Table(
    "oauth_tokens",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("access_token", LargeBinary, nullable=False),
    Column("refresh_token", LargeBinary, nullable=False),
    Column("expires_at", Float, nullable=False),
    Column("account_id", String(512), nullable=False),
    Column("account_name", LargeBinary, nullable=False),
)
oauth_flows_table = Table(
    "oauth_flows",
    metadata,
    Column("state_hash", String(64), primary_key=True),
    Column("verifier", LargeBinary, nullable=False),
    Column("expires_at", Float, nullable=False),
)


class TokenStore:
    def __init__(self, database_url: str, encryption_key: str) -> None:
        self._cipher = Fernet(encryption_key.encode())
        engine_options = {"pool_pre_ping": True}
        if database_url.startswith("sqlite:"):
            engine_options["connect_args"] = {"check_same_thread": False}
        self.engine: Engine = create_engine(database_url, **engine_options)
        metadata.create_all(self.engine)

    def _encrypt(self, value: str) -> bytes:
        return self._cipher.encrypt(value.encode())

    def _decrypt(self, value: bytes) -> str:
        try:
            return self._cipher.decrypt(value).decode()
        except InvalidToken as exc:
            raise StorageError("Stored OAuth data could not be decrypted") from exc

    def save_tokens(self, bundle: TokenBundle) -> None:
        values = {
            "id": 1,
            "access_token": self._encrypt(bundle.access_token),
            "refresh_token": self._encrypt(bundle.refresh_token),
            "expires_at": bundle.expires_at.timestamp(),
            "account_id": bundle.account_id,
            "account_name": self._encrypt(bundle.account_name),
        }
        with self.engine.begin() as connection:
            existing = connection.execute(
                tokens_table.select().where(tokens_table.c.id == 1)
            ).first()
            if existing is None:
                connection.execute(tokens_table.insert().values(**values))
            else:
                connection.execute(
                    tokens_table.update().where(tokens_table.c.id == 1).values(**values)
                )

    def get_tokens(self) -> TokenBundle | None:
        with self.engine.connect() as connection:
            row = connection.execute(
                tokens_table.select().where(tokens_table.c.id == 1)
            ).mappings().first()
        if row is None:
            return None
        return TokenBundle(
            access_token=self._decrypt(row["access_token"]),
            refresh_token=self._decrypt(row["refresh_token"]),
            expires_at=datetime.fromtimestamp(row["expires_at"], tz=UTC),
            account_id=row["account_id"],
            account_name=self._decrypt(row["account_name"]),
        )

    @staticmethod
    def _state_hash(state: str) -> str:
        return hashlib.sha256(state.encode()).hexdigest()

    def save_oauth_flow(self, state: str, verifier: str, expires_at: datetime) -> None:
        state_hash = self._state_hash(state)
        with self.engine.begin() as connection:
            connection.execute(
                oauth_flows_table.delete().where(oauth_flows_table.c.state_hash == state_hash)
            )
            connection.execute(
                oauth_flows_table.insert().values(
                    state_hash=state_hash,
                    verifier=self._encrypt(verifier),
                    expires_at=expires_at.timestamp(),
                )
            )

    def consume_oauth_flow(self, state: str, now: datetime) -> str | None:
        state_hash = self._state_hash(state)
        with self.engine.begin() as connection:
            row = connection.execute(
                oauth_flows_table.select().where(oauth_flows_table.c.state_hash == state_hash)
            ).mappings().first()
            result = connection.execute(
                oauth_flows_table.delete().where(oauth_flows_table.c.state_hash == state_hash)
            )
        if row is None or result.rowcount != 1 or row["expires_at"] < now.timestamp():
            return None
        return self._decrypt(row["verifier"])
