"""Optional Numverify carrier and line type.

Blank NUMVERIFY_API_KEY skips this source, the same way the other keys work.
The number has to be sent to Numverify for the lookup. It is not copied into
the result. Offline prefix data stays in the Phone source; this is the only
live carrier line, and only when the key is set.
"""

from typing import Any

import httpx

from scam_cemetery.models import SourceResult
from scam_cemetery.sources.base import SourceFailure

_ENDPOINT = "https://apilayer.net/api/validate"


class NumverifySource:
    name = "numverify"
    display_name = "Numverify"

    def __init__(self, api_key: str | None) -> None:
        self._api_key = api_key

    def is_configured(self) -> bool:
        return bool(self._api_key)

    async def lookup(self, target: str, client: httpx.AsyncClient) -> SourceResult:
        # The key and the number ride in the query string. Do not log this URL.
        digits = target[1:] if target.startswith("+") else target
        response = await client.get(
            _ENDPOINT,
            params={"access_key": self._api_key, "number": digits, "format": "1"},
        )
        if response.status_code >= 400:
            raise SourceFailure(f"HTTP {response.status_code}")
        payload = _json_object(response)
        if payload.get("success") is False:
            code = _error_code(payload)
            reason = f"HTTP {response.status_code}, error={code}" if code else "request failed"
            raise SourceFailure(reason)
        return _parse(payload, digits)


def _parse(payload: dict[str, Any], digits: str) -> SourceResult:
    if payload.get("valid") is False:
        return SourceResult(
            source=NumverifySource.name,
            display_name=NumverifySource.display_name,
            status="suspicious",
            summary="Numverify: reports this number as invalid",
        )
    if payload.get("valid") is not True:
        raise SourceFailure("response had no valid field")
    carrier = _clean(payload.get("carrier"), digits) or "unknown carrier"
    line = _clean(payload.get("line_type"), digits) or "unknown line type"
    country = _clean(payload.get("country_code"), digits)
    where = f" ({country})" if country else ""
    return SourceResult(
        source=NumverifySource.name,
        display_name=NumverifySource.display_name,
        status="clean",
        summary=f"Numverify: {carrier}, {line}{where}",
        detail={"carrier": carrier, "line_type": line, "country_code": country},
    )


def _clean(value: object, digits: str) -> str:
    if not isinstance(value, str):
        return ""
    text = value.replace(f"+{digits}", "").replace(digits, "").strip()
    return " ".join(text.split())


def _error_code(payload: dict[str, Any]) -> str:
    error = payload.get("error")
    if not isinstance(error, dict):
        return ""
    code = error.get("code")
    return str(code) if isinstance(code, int) else ""


def _json_object(response: httpx.Response) -> dict[str, Any]:
    try:
        payload = response.json()
    except ValueError:
        return {}
    return payload if isinstance(payload, dict) else {}
