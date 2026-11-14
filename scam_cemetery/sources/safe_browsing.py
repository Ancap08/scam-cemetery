"""Google Safe Browsing v4 Lookup API (threatMatches.find)."""

from typing import Any

import httpx

from scam_cemetery import __version__
from scam_cemetery.models import SourceResult

_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
_THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]


class SafeBrowsingSource:
    name = "google_safe_browsing"
    display_name = "Google Safe Browsing"

    def __init__(self, api_key: str | None) -> None:
        self._api_key = api_key

    def is_configured(self) -> bool:
        return bool(self._api_key)

    async def lookup(self, url: str, client: httpx.AsyncClient) -> SourceResult:
        # The key rides in the query string. Callers must not log this URL.
        response = await client.post(
            _ENDPOINT,
            params={"key": self._api_key},
            json={
                "client": {"clientId": "scam-cemetery", "clientVersion": __version__},
                "threatInfo": {
                    "threatTypes": _THREAT_TYPES,
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}],
                },
            },
        )
        if response.status_code >= 400:
            raise RuntimeError(f"HTTP {response.status_code}")
        return parse_safe_browsing(response.json())


def parse_safe_browsing(payload: dict[str, Any]) -> SourceResult:
    """Turn a threatMatches.find body into a source result.

    An empty object means the URL is not on the lists we asked about.
    """
    matches = payload.get("matches") or []
    if not isinstance(matches, list) or not matches:
        return SourceResult(
            source=SafeBrowsingSource.name,
            display_name=SafeBrowsingSource.display_name,
            status="clean",
            summary="Google Safe Browsing: no matches",
        )
    threat_types = sorted(
        {str(match.get("threatType") or "UNKNOWN") for match in matches if isinstance(match, dict)}
    )
    listed = ", ".join(threat_types) or "UNKNOWN"
    return SourceResult(
        source=SafeBrowsingSource.name,
        display_name=SafeBrowsingSource.display_name,
        status="malicious",
        summary=f"Google Safe Browsing: flagged {listed}",
        detail={"threat_types": threat_types},
    )
