from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography.fernet import Fernet
from mcp import Client

from jobber_mcp.mcp_server import create_mcp_server
from jobber_mcp.reporting import ExportArtifact
from jobber_mcp.storage import TokenBundle, TokenStore


class StubReportingService:
    async def export_records(self, dataset: str, *, max_records: int = 500) -> list[dict[str, Any]]:
        return [{"dataset": dataset, "limit": max_records}]

    async def quote_summary(self, *, max_records: int = 1000) -> dict[str, Any]:
        return {"quote_count": max_records}

    async def quote_report(self, *, max_records: int = 500) -> dict[str, Any]:
        return {"summary": {"quote_count": 1}, "quotes": [{"id": "q1"}]}

    async def create_csv(self, dataset: str, *, max_records: int = 1000) -> ExportArtifact:
        return ExportArtifact(
            dataset=dataset,
            row_count=max_records,
            path=Path(f"/private/{dataset}.csv"),
            download_url=f"https://jobber.example.com/exports/{dataset}.csv",
        )


@pytest.mark.asyncio
async def test_mcp_exposes_only_named_read_only_reporting_tools(tmp_path: Path) -> None:
    store = TokenStore(
        f"sqlite:///{tmp_path / 'mcp.db'}",
        Fernet.generate_key().decode(),
    )
    store.save_tokens(
        TokenBundle(
            access_token="access",
            refresh_token="refresh",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            account_id="account-1",
            account_name="Sow Home Services",
        )
    )
    server = create_mcp_server(store, StubReportingService())

    async with Client(server) as client:
        listed = await client.list_tools()
        names = {tool.name for tool in listed.tools}
        clients_result = await client.call_tool("jobber_list_clients", {"max_records": 12})
        status_result = await client.call_tool("jobber_account_status", {})
        csv_result = await client.call_tool(
            "jobber_export_csv", {"dataset": "quotes", "max_records": 20}
        )

    assert names == {
        "jobber_account_status",
        "jobber_list_clients",
        "jobber_list_requests",
        "jobber_list_quotes",
        "jobber_list_jobs",
        "jobber_list_invoices",
        "jobber_quote_summary",
        "jobber_quote_report",
        "jobber_export_csv",
    }
    assert all(tool.annotations and tool.annotations.read_only_hint for tool in listed.tools)
    assert clients_result.structured_content == {
        "dataset": "clients",
        "count": 1,
        "records": [{"dataset": "clients", "limit": 12}],
    }
    assert status_result.structured_content["connected"] is True
    assert "Bearer" not in str(status_result.structured_content)
    assert "refresh" not in str(status_result.structured_content)
    assert csv_result.structured_content == {
        "dataset": "quotes",
        "row_count": 20,
        "download_url": "https://jobber.example.com/exports/quotes.csv",
    }
