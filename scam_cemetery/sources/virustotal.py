"""VirusTotal v3 URL lookup, plus a submit-and-poll when the URL is new.

The public API allows 4 requests per minute. Lookup, submit, and poll all
share one budget on this object. A URL with no report is "unknown" and marked
``needs_scan`` so the bot can send a follow-up after the scan, instead of
holding the first reply open.
"""

import asyncio
import base64
import re
import time
from collections.abc import Awaitable, Callable
from typing import Any

import httpx

from scam_cemetery.models import SourceResult
from scam_cemetery.sources.base import SourceFailure

_ENDPOINT = "https://www.virustotal.com/api/v3/urls"
_ANALYSES = "https://www.virustotal.com/api/v3/analyses"
_ANALYSIS_ID = re.compile(r"^[A-Za-z0-9_-]{1,128}$")


class RequestBudget:
    """Allow at most ``limit`` acquisitions in any ``period`` seconds."""

    def __init__(self, limit: int = 4, period: float = 60.0) -> None:
        self.limit = limit
        self.period = period
        self._stamps: list[float] = []
        self._lock = asyncio.Lock()

    async def acquire(
        self,
        *,
        now: Callable[[], float] | None = None,
        sleep: Callable[[float], Awaitable[None]] | None = None,
    ) -> None:
        clock = now or time.monotonic
        pause = sleep or asyncio.sleep
        while True:
            async with self._lock:
                current = clock()
                self._stamps = [stamp for stamp in self._stamps if current - stamp < self.period]
                if len(self._stamps) < self.limit:
                    self._stamps.append(current)
                    return
                wait_for = self.period - (current - self._stamps[0])
            await pause(max(wait_for, 0))


class VirusTotalSource:
    name = "virustotal"
    display_name = "VirusTotal"

    def __init__(self, api_key: str | None, *, budget: RequestBudget | None = None) -> None:
        self._api_key = api_key
        self.budget = budget or RequestBudget()

    def is_configured(self) -> bool:
        return bool(self._api_key)

    async def lookup(self, url: str, client: httpx.AsyncClient) -> SourceResult:
        await self.budget.acquire()
        response = await client.get(
            f"{_ENDPOINT}/{url_identifier(url)}",
            headers=self._headers(),
        )
        if response.status_code == 404:
            return SourceResult(
                source=self.name,
                display_name=self.display_name,
                status="unknown",
                summary="VirusTotal: not scanned yet",
                detail={"needs_scan": True},
            )
        if response.status_code >= 400:
            raise SourceFailure(f"HTTP {response.status_code}")
        return parse_virustotal(response.json())

    async def submit(self, url: str, client: httpx.AsyncClient) -> str:
        """Ask VirusTotal to scan ``url``. Returns the analysis id."""
        await self.budget.acquire()
        response = await client.post(
            _ENDPOINT,
            data={"url": url},
            headers=self._headers(),
        )
        if response.status_code >= 400:
            raise SourceFailure(f"HTTP {response.status_code}")
        analysis_id = _analysis_id(response.json())
        if analysis_id is None:
            raise SourceFailure("submit response had no analysis id")
        return analysis_id

    async def poll(self, analysis_id: str, client: httpx.AsyncClient) -> SourceResult | None:
        """Return the scan result, or None if VirusTotal is not finished."""
        if not _ANALYSIS_ID.fullmatch(analysis_id):
            raise SourceFailure("analysis id was not usable")
        await self.budget.acquire()
        response = await client.get(
            f"{_ANALYSES}/{analysis_id}",
            headers=self._headers(),
        )
        if response.status_code >= 400:
            raise SourceFailure(f"HTTP {response.status_code}")
        attributes = _attributes(response.json())
        if attributes.get("status") != "completed":
            return None
        stats = attributes.get("stats")
        if not isinstance(stats, dict):
            raise SourceFailure("completed scan had no stats")
        return result_from_stats(stats)

    def _headers(self) -> dict[str, str]:
        return {"x-apikey": self._api_key or "", "Accept": "application/json"}


def url_identifier(url: str) -> str:
    """Unpadded URL-safe base64, which is how VirusTotal v3 addresses a URL."""
    encoded = base64.urlsafe_b64encode(url.encode()).decode()
    return encoded.rstrip("=")


def parse_virustotal(payload: dict[str, Any]) -> SourceResult:
    return result_from_stats(_stats(payload))


def result_from_stats(stats: dict[str, Any]) -> SourceResult:
    malicious = _count(stats, "malicious")
    suspicious = _count(stats, "suspicious")
    harmless = _count(stats, "harmless")
    undetected = _count(stats, "undetected")
    detail = {
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
    }
    if malicious > 0:
        return SourceResult(
            source=VirusTotalSource.name,
            display_name=VirusTotalSource.display_name,
            status="malicious",
            summary=f"VirusTotal: {malicious} engines flagged this URL",
            detail=detail,
        )
    if suspicious > 0:
        return SourceResult(
            source=VirusTotalSource.name,
            display_name=VirusTotalSource.display_name,
            status="suspicious",
            summary=f"VirusTotal: {suspicious} engines marked it suspicious",
            detail=detail,
        )
    return SourceResult(
        source=VirusTotalSource.name,
        display_name=VirusTotalSource.display_name,
        status="clean",
        summary=(
            f"VirusTotal: no engines flagged it ({harmless} harmless, {undetected} undetected)"
        ),
        detail=detail,
    )


def _analysis_id(payload: object) -> str | None:
    if not isinstance(payload, dict):
        return None
    data = payload.get("data")
    if not isinstance(data, dict) or not isinstance(data.get("id"), str):
        return None
    analysis_id = data["id"]
    if not _ANALYSIS_ID.fullmatch(analysis_id):
        return None
    return analysis_id


def _attributes(payload: object) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    data = payload.get("data")
    if not isinstance(data, dict):
        return {}
    attributes = data.get("attributes")
    return attributes if isinstance(attributes, dict) else {}


def _stats(payload: dict[str, Any]) -> dict[str, Any]:
    data = payload.get("data")
    if not isinstance(data, dict):
        raise ValueError("VirusTotal response has no data object")
    attributes = data.get("attributes")
    if not isinstance(attributes, dict):
        raise ValueError("VirusTotal response has no attributes")
    stats = attributes.get("last_analysis_stats")
    if not isinstance(stats, dict):
        raise ValueError("VirusTotal response has no last_analysis_stats")
    return stats


def _count(stats: dict[str, Any], key: str) -> int:
    value = stats.get(key) or 0
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"VirusTotal stat {key} is not an integer") from exc
