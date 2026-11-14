"""The small interface every source implements.

A new source is a class with ``name``, ``display_name``, ``is_configured``,
and ``lookup``. The pipeline skips a source whose key is missing and turns
timeouts into a result, so one source cannot sink the reply.
"""

from typing import Protocol

import httpx

from scam_cemetery.models import SourceResult


class SourceFailure(Exception):
    """A vendor call failed in a way that is safe to put in the log and the reply.

    ``reason`` is a short status such as ``HTTP 403, query_status=unknown_auth_key``.
    It must never include an API key or a request URL.
    """

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class ThreatSource(Protocol):
    name: str
    display_name: str

    def is_configured(self) -> bool:
        """False when the API key was not provided. The pipeline will not call lookup."""

    async def lookup(self, url: str, client: httpx.AsyncClient) -> SourceResult:
        """Ask the vendor about ``url``. Raise SourceFailure on HTTP failure."""


def skipped_result(name: str, display_name: str) -> SourceResult:
    return SourceResult(
        source=name,
        display_name=display_name,
        status="skipped",
        summary=f"{display_name}: skipped (no API key)",
    )


def timeout_result(name: str, display_name: str) -> SourceResult:
    return SourceResult(
        source=name,
        display_name=display_name,
        status="timeout",
        summary=f"{display_name}: timed out",
    )


def error_result(name: str, display_name: str, reason: str | None = None) -> SourceResult:
    detail = reason or "request failed"
    return SourceResult(
        source=name,
        display_name=display_name,
        status="error",
        summary=f"{display_name}: {detail}",
        detail={"reason": detail} if reason else {},
    )
