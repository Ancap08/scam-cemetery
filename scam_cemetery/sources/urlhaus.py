"""URLhaus (abuse.ch) single-URL lookup.

Auth is the ``Auth-Key`` header from https://auth.abuse.ch/. A URL that is
not in the database is treated as clean: URLhaus only lists malware URLs.
"""

from typing import Any

import httpx

from scam_cemetery.models import SourceResult

_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"


class URLhausSource:
    name = "urlhaus"
    display_name = "URLhaus"

    def __init__(self, auth_key: str | None) -> None:
        self._auth_key = auth_key

    def is_configured(self) -> bool:
        return bool(self._auth_key)

    async def lookup(self, url: str, client: httpx.AsyncClient) -> SourceResult:
        response = await client.post(
            _ENDPOINT,
            data={"url": url},
            headers={"Auth-Key": self._auth_key or ""},
        )
        if response.status_code >= 400:
            raise RuntimeError(f"HTTP {response.status_code}")
        return parse_urlhaus(response.json())


def parse_urlhaus(payload: dict[str, Any]) -> SourceResult:
    query_status = str(payload.get("query_status") or "")
    if query_status == "no_results":
        return SourceResult(
            source=URLhausSource.name,
            display_name=URLhausSource.display_name,
            status="clean",
            summary="URLhaus: not listed",
        )
    if query_status != "ok":
        detail = query_status or "unexpected response"
        return SourceResult(
            source=URLhausSource.name,
            display_name=URLhausSource.display_name,
            status="error",
            summary=f"URLhaus: {detail}",
            detail={"query_status": query_status},
        )
    threat = str(payload.get("threat") or "malware")
    url_status = str(payload.get("url_status") or "unknown")
    return SourceResult(
        source=URLhausSource.name,
        display_name=URLhausSource.display_name,
        status="malicious",
        summary=f"URLhaus: listed as {threat} ({url_status})",
        detail={"threat": threat, "url_status": url_status},
    )
