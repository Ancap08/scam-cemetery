"""URLhaus (abuse.ch) single-URL lookup.

Auth is the ``Auth-Key`` header from https://auth.abuse.ch/. The body is form
data, field ``url``. ``query_status: no_results`` means the URL is not listed,
including when that JSON arrives on a non-200 status. Other failures keep the
HTTP status and query_status so the log is useful, and never include the key.
"""

import re
from typing import Any

import httpx

from scam_cemetery.models import SourceResult
from scam_cemetery.sources.base import SourceFailure

_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"
# Tokens we are willing to copy into a log line. Anything else is dropped so a
# surprising body cannot smuggle the Auth-Key into the logs.
_SAFE_TOKEN = re.compile(r"^[A-Za-z0-9_ .:/-]{1,80}$")


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
        payload = _json_object(response)
        query_status = str(payload.get("query_status") or "")
        # Read the body before trusting the HTTP status. A listed or not-listed
        # answer is the result, even if a proxy or a future API puts it on a 4xx.
        if query_status == "no_results":
            return parse_urlhaus(payload)
        if response.status_code < 400 and query_status:
            return parse_urlhaus(payload)
        raise SourceFailure(
            _failure_reason(response.status_code, query_status, payload.get("error"))
        )


def _json_object(response: httpx.Response) -> dict[str, Any]:
    try:
        payload = response.json()
    except ValueError:
        return {}
    return payload if isinstance(payload, dict) else {}


def _failure_reason(status_code: int, query_status: str, error: object) -> str:
    parts = [f"HTTP {status_code}"]
    if _SAFE_TOKEN.fullmatch(query_status):
        parts.append(f"query_status={query_status}")
    elif isinstance(error, str) and _SAFE_TOKEN.fullmatch(error):
        parts.append(f"error={error}")
    return ", ".join(parts)


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
