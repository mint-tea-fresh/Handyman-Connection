from __future__ import annotations

import csv
import json
import secrets
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any, Protocol


class UnknownDatasetError(ValueError):
    """Raised when a caller asks for a non-allowlisted export."""


class PaginatingClient(Protocol):
    async def paginate(
        self,
        query: str,
        connection_name: str,
        *,
        variables: dict[str, Any] | None = None,
        page_size: int = 50,
        max_records: int = 500,
    ) -> list[dict[str, Any]]: ...


@dataclass(frozen=True, slots=True)
class Dataset:
    name: str
    query: str


@dataclass(frozen=True, slots=True)
class ExportArtifact:
    dataset: str
    row_count: int
    path: Path
    download_url: str


def _connection_query(name: str, fields: str) -> str:
    return f"""query Export{name.title()}($limit: Int!, $cursor: String) {{
  {name}(first: $limit, after: $cursor) {{
    nodes {{ {fields} }}
    pageInfo {{ hasNextPage endCursor }}
  }}
}}"""


DATASETS: dict[str, Dataset] = {
    "clients": Dataset(
        "clients",
        _connection_query(
            "clients",
            "id name firstName lastName companyName email phone balance isArchived "
            "createdAt updatedAt",
        ),
    ),
    "requests": Dataset(
        "requests",
        _connection_query(
            "requests",
            "id title requestStatus createdAt updatedAt client { id name }",
        ),
    ),
    "quotes": Dataset(
        "quotes",
        _connection_query(
            "quotes",
            "id quoteNumber title quoteStatus createdAt updatedAt sentAt transitionedAt "
            "amounts { total } client { id name }",
        ),
    ),
    "jobs": Dataset(
        "jobs",
        _connection_query(
            "jobs",
            "id jobNumber title jobStatus jobType startAt endAt createdAt updatedAt total "
            "client { id name }",
        ),
    ),
    "invoices": Dataset(
        "invoices",
        _connection_query(
            "invoices",
            "id invoiceNumber subject invoiceStatus issuedDate dueDate createdAt updatedAt "
            "amounts { total } client { id name }",
        ),
    ),
}


class ReportingService:
    def __init__(self, client: PaginatingClient, export_dir: Path, base_url: str) -> None:
        self.client = client
        self.export_dir = export_dir
        self.base_url = base_url.rstrip("/")

    async def export_records(self, dataset: str, *, max_records: int = 500) -> list[dict[str, Any]]:
        definition = DATASETS.get(dataset)
        if definition is None:
            raise UnknownDatasetError(
                "Unknown dataset; allowed values: clients, requests, quotes, jobs, invoices"
            )
        return await self.client.paginate(
            definition.query,
            definition.name,
            max_records=max_records,
        )

    @staticmethod
    def _quote_summary(quotes: list[dict[str, Any]]) -> dict[str, Any]:
        totals: dict[str, dict[str, Decimal | int]] = {}
        total_amount = Decimal("0")
        priced_count = 0
        for quote in quotes:
            status = str(quote.get("quoteStatus") or "UNKNOWN")
            status_totals = totals.setdefault(status, {"count": 0, "total_amount": Decimal("0")})
            status_totals["count"] = int(status_totals["count"]) + 1
            raw_amount = (quote.get("amounts") or {}).get("total")
            if raw_amount is not None:
                amount = Decimal(str(raw_amount))
                total_amount += amount
                priced_count += 1
                status_totals["total_amount"] = Decimal(str(status_totals["total_amount"])) + amount
        by_status = {
            status: {
                "count": values["count"],
                "total_amount": float(Decimal(str(values["total_amount"]))),
            }
            for status, values in sorted(totals.items())
        }
        return {
            "quote_count": len(quotes),
            "priced_quote_count": priced_count,
            "total_amount": float(total_amount),
            "average_amount": float(total_amount / priced_count) if priced_count else 0.0,
            "by_status": by_status,
        }

    async def quote_summary(self, *, max_records: int = 1000) -> dict[str, Any]:
        quotes = await self.export_records("quotes", max_records=max_records)
        return self._quote_summary(quotes)

    async def quote_report(self, *, max_records: int = 500) -> dict[str, Any]:
        quotes = await self.export_records("quotes", max_records=max_records)
        return {"summary": self._quote_summary(quotes), "quotes": quotes}

    @staticmethod
    def _flatten(record: dict[str, Any], prefix: str = "") -> dict[str, str]:
        flattened: dict[str, str] = {}
        for key, value in record.items():
            column = f"{prefix}.{key}" if prefix else key
            if isinstance(value, dict):
                flattened.update(ReportingService._flatten(value, column))
            elif isinstance(value, list):
                flattened[column] = json.dumps(value, ensure_ascii=False)
            elif value is None:
                flattened[column] = ""
            else:
                rendered = str(value)
                if rendered.startswith(("=", "+", "-", "@", "\t", "\r")):
                    rendered = "'" + rendered
                flattened[column] = rendered
        return flattened

    async def create_csv(self, dataset: str, *, max_records: int = 1000) -> ExportArtifact:
        records = await self.export_records(dataset, max_records=max_records)
        rows = [self._flatten(record) for record in records]
        fieldnames = sorted({key for row in rows for key in row})
        self.export_dir.mkdir(parents=True, exist_ok=True)
        filename = f"{dataset}-{secrets.token_hex(8)}.csv"
        path = self.export_dir / filename
        with path.open("w", newline="", encoding="utf-8") as handle:
            if fieldnames:
                writer = csv.DictWriter(handle, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows)
        path.chmod(0o600)
        return ExportArtifact(
            dataset=dataset,
            row_count=len(rows),
            path=path,
            download_url=f"{self.base_url}/exports/{filename}",
        )
