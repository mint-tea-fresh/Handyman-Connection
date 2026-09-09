from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

import pytest

from jobber_mcp.reporting import DATASETS, ReportingService, UnknownDatasetError


class StubJobberClient:
    def __init__(self, records: list[dict[str, Any]]) -> None:
        self.records = records
        self.calls: list[tuple[str, str, int]] = []

    async def paginate(
        self,
        query: str,
        connection_name: str,
        *,
        variables: dict[str, Any] | None = None,
        page_size: int = 50,
        max_records: int = 500,
    ) -> list[dict[str, Any]]:
        del variables, page_size
        self.calls.append((query, connection_name, max_records))
        return self.records[:max_records]


@pytest.mark.asyncio
@pytest.mark.parametrize("dataset", ["clients", "requests", "quotes", "jobs", "invoices"])
async def test_named_exports_use_only_fixed_read_only_queries(tmp_path: Path, dataset: str) -> None:
    client = StubJobberClient([{"id": "1"}])
    service = ReportingService(client, tmp_path, "https://jobber.example.com")

    records = await service.export_records(dataset, max_records=25)

    assert records == [{"id": "1"}]
    query, connection, limit = client.calls[0]
    assert connection == dataset
    assert limit == 25
    assert query == DATASETS[dataset].query
    assert "mutation" not in query.lower()
    assert "$limit" in query and "$cursor" in query


@pytest.mark.asyncio
async def test_named_exports_reject_unregistered_dataset(tmp_path: Path) -> None:
    service = ReportingService(StubJobberClient([]), tmp_path, "https://jobber.example.com")

    with pytest.raises(UnknownDatasetError, match="clients, requests, quotes, jobs, invoices"):
        await service.export_records("../../secrets", max_records=25)


@pytest.mark.asyncio
async def test_quote_summary_aggregates_status_counts_and_amounts(tmp_path: Path) -> None:
    client = StubJobberClient(
        [
            {"id": "1", "quoteStatus": "DRAFT", "amounts": {"total": 100.25}},
            {"id": "2", "quoteStatus": "SENT", "amounts": {"total": 200}},
            {"id": "3", "quoteStatus": "SENT", "amounts": {"total": None}},
            {"id": "4", "quoteStatus": "APPROVED", "amounts": {"total": "50.75"}},
        ]
    )
    service = ReportingService(client, tmp_path, "https://jobber.example.com")

    summary = await service.quote_summary(max_records=100)

    assert summary == {
        "quote_count": 4,
        "priced_quote_count": 3,
        "total_amount": 351.0,
        "average_amount": 117.0,
        "by_status": {
            "APPROVED": {"count": 1, "total_amount": 50.75},
            "DRAFT": {"count": 1, "total_amount": 100.25},
            "SENT": {"count": 2, "total_amount": 200.0},
        },
    }


@pytest.mark.asyncio
async def test_csv_export_flattens_records_and_prevents_spreadsheet_formulas(
    tmp_path: Path,
) -> None:
    client = StubJobberClient(
        [
            {
                "id": "1",
                "name": '=HYPERLINK("https://bad.example")',
                "client": {"id": "c1", "name": "Jane Doe"},
                "tags": ["priority", "repeat"],
            }
        ]
    )
    service = ReportingService(client, tmp_path, "https://jobber.example.com")

    artifact = await service.create_csv("clients", max_records=10)

    assert artifact.row_count == 1
    assert artifact.path.parent == tmp_path
    assert artifact.path.name.startswith("clients-")
    assert artifact.download_url == f"https://jobber.example.com/exports/{artifact.path.name}"
    with artifact.path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert rows == [
        {
            "client.id": "c1",
            "client.name": "Jane Doe",
            "id": "1",
            "name": '\'=HYPERLINK("https://bad.example")',
            "tags": '["priority", "repeat"]',
        }
    ]


@pytest.mark.asyncio
async def test_quote_report_returns_rows_and_summary_from_one_export(tmp_path: Path) -> None:
    quotes = [
        {"id": "q1", "quoteStatus": "SENT", "amounts": {"total": 125}},
        {"id": "q2", "quoteStatus": "APPROVED", "amounts": {"total": 75}},
    ]
    client = StubJobberClient(quotes)
    service = ReportingService(client, tmp_path, "https://jobber.example.com")

    report = await service.quote_report(max_records=50)

    assert report["quotes"] == quotes
    assert report["summary"]["quote_count"] == 2
    assert report["summary"]["total_amount"] == 200.0
    assert len(client.calls) == 1
