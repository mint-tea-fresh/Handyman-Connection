from __future__ import annotations

from typing import Any, Protocol

from mcp.server import MCPServer
from mcp.types import ToolAnnotations

from jobber_mcp.reporting import ExportArtifact
from jobber_mcp.storage import TokenStore


class ReportingTools(Protocol):
    async def export_records(
        self, dataset: str, *, max_records: int = 500
    ) -> list[dict[str, Any]]: ...

    async def quote_summary(self, *, max_records: int = 1000) -> dict[str, Any]: ...

    async def quote_report(self, *, max_records: int = 500) -> dict[str, Any]: ...

    async def create_csv(
        self, dataset: str, *, max_records: int = 1000
    ) -> ExportArtifact: ...


READ_ONLY = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=True,
)


def _limit(value: int) -> int:
    if not 1 <= value <= 5000:
        raise ValueError("max_records must be between 1 and 5000")
    return value


def create_mcp_server(store: TokenStore, reporting: ReportingTools) -> MCPServer:
    server = MCPServer(
        "Sow Home Services Jobber Reporting",
        instructions=(
            "Read-only reporting tools for the connected Jobber account. "
            "No arbitrary GraphQL or mutations are available."
        ),
    )

    @server.tool(name="jobber_account_status", annotations=READ_ONLY)
    async def account_status() -> dict[str, Any]:
        """Show whether Jobber is connected without returning OAuth credentials."""
        tokens = store.get_tokens()
        if tokens is None:
            return {"connected": False}
        return {
            "connected": True,
            "account_id": tokens.account_id,
            "account_name": tokens.account_name,
            "access_token_expires_at": tokens.expires_at.isoformat(),
        }

    async def records(dataset: str, max_records: int) -> dict[str, Any]:
        values = await reporting.export_records(dataset, max_records=_limit(max_records))
        return {"dataset": dataset, "count": len(values), "records": values}

    @server.tool(name="jobber_list_clients", annotations=READ_ONLY)
    async def list_clients(max_records: int = 100) -> dict[str, Any]:
        """List clients using the connector's fixed, read-only client query."""
        return await records("clients", max_records)

    @server.tool(name="jobber_list_requests", annotations=READ_ONLY)
    async def list_requests(max_records: int = 100) -> dict[str, Any]:
        """List requests using the connector's fixed, read-only request query."""
        return await records("requests", max_records)

    @server.tool(name="jobber_list_quotes", annotations=READ_ONLY)
    async def list_quotes(max_records: int = 100) -> dict[str, Any]:
        """List quotes using the connector's fixed, read-only quote query."""
        return await records("quotes", max_records)

    @server.tool(name="jobber_list_jobs", annotations=READ_ONLY)
    async def list_jobs(max_records: int = 100) -> dict[str, Any]:
        """List jobs using the connector's fixed, read-only job query."""
        return await records("jobs", max_records)

    @server.tool(name="jobber_list_invoices", annotations=READ_ONLY)
    async def list_invoices(max_records: int = 100) -> dict[str, Any]:
        """List invoices using the connector's fixed, read-only invoice query."""
        return await records("invoices", max_records)

    @server.tool(name="jobber_quote_summary", annotations=READ_ONLY)
    async def quote_summary(max_records: int = 1000) -> dict[str, Any]:
        """Summarize quote counts and values by status."""
        return await reporting.quote_summary(max_records=_limit(max_records))

    @server.tool(name="jobber_quote_report", annotations=READ_ONLY)
    async def quote_report(max_records: int = 500) -> dict[str, Any]:
        """Return quote rows together with an aggregate summary."""
        return await reporting.quote_report(max_records=_limit(max_records))

    @server.tool(name="jobber_export_csv", annotations=READ_ONLY)
    async def export_csv(dataset: str, max_records: int = 1000) -> dict[str, Any]:
        """Create a private CSV for an allowlisted Jobber reporting dataset."""
        artifact = await reporting.create_csv(dataset, max_records=_limit(max_records))
        return {
            "dataset": artifact.dataset,
            "row_count": artifact.row_count,
            "download_url": artifact.download_url,
        }

    return server
