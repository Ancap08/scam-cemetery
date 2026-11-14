"""VirusTotal v3 URL report lookup.

This does not submit the URL for a new scan. A URL VirusTotal has never seen
comes back as "unknown", which the rules judge treats as CAUTION.
"""

import base64
from typing import Any

import httpx

from scam_cemetery.models import SourceResult

_ENDPOINT = "https://www.virustotal.com/api/v3/urls"


class VirusTotalSource:
    name = "virustotal"
    display_name = "VirusTotal"

    def __init__(self, api_key: str | None) -> None:
        self._api_key = api_key

    def is_configured(self) -> bool:
        return bool(self._api_key)

    async def lookup(self, url: str, client: httpx.AsyncClient) -> SourceResult:
        url_id = url_identifier(url)
        response = await client.get(
            f"{_ENDPOINT}/{url_id}",
            headers={"x-apikey": self._api_key or "", "Accept": "application/json"},
        )
        if response.status_code == 404:
            return SourceResult(
                source=self.name,
                display_name=self.display_name,
                status="unknown",
                summary="VirusTotal: URL has not been scanned",
            )
        if response.status_code >= 400:
            raise RuntimeError(f"HTTP {response.status_code}")
        return parse_virustotal(response.json())


def url_identifier(url: str) -> str:
    """Unpadded URL-safe base64, which is how VirusTotal v3 addresses a URL."""
    encoded = base64.urlsafe_b64encode(url.encode()).decode()
    return encoded.rstrip("=")


def parse_virustotal(payload: dict[str, Any]) -> SourceResult:
    stats = _stats(payload)
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
