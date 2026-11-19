"""Helpers shared by the offline tests. Nothing here touches the network."""

import httpx

from scam_cemetery.models import SourceResult, SourceStatus


def source(
    name: str,
    status: SourceStatus,
    *,
    summary: str | None = None,
    display_name: str | None = None,
) -> SourceResult:
    return SourceResult(
        source=name,
        display_name=display_name or name,
        status=status,
        summary=summary or f"{display_name or name}: {status}",
    )


def vt_body(
    *,
    malicious: int = 0,
    suspicious: int = 0,
    harmless: int = 60,
    undetected: int = 5,
) -> dict:
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": undetected,
                }
            }
        }
    }


def mock_client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


class FakeDns:
    """In-memory DNS. A missing name has no records. Nothing here touches the network."""

    def __init__(self, records: dict[tuple[str, str], list[str] | Exception] | None = None) -> None:
        self.records = records or {}
        self.calls: list[tuple[str, str]] = []

    async def lookup(self, name: str, record_type: str) -> list[str]:
        key = (name.lower(), record_type.upper())
        self.calls.append(key)
        value = self.records.get(key, [])
        if isinstance(value, Exception):
            raise value
        return list(value)
