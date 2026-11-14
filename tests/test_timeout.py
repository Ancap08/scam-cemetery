"""One slow or failed source must not hold up the other two."""

import asyncio
import time

import httpx

from scam_cemetery.judges.rules import RulesJudge
from scam_cemetery.pipeline import Pipeline
from scam_cemetery.sources.safe_browsing import SafeBrowsingSource
from scam_cemetery.sources.urlhaus import URLhausSource
from scam_cemetery.sources.virustotal import VirusTotalSource
from tests.helpers import mock_client, vt_body


def _pipeline(timeout: float) -> Pipeline:
    return Pipeline(
        sources=[
            SafeBrowsingSource("gsb-key"),
            VirusTotalSource("vt-key"),
            URLhausSource("uh-key"),
        ],
        judges=[RulesJudge()],
        timeout=timeout,
    )


async def test_a_slow_source_times_out_and_the_others_still_answer():
    async def handler(request: httpx.Request) -> httpx.Response:
        host = request.url.host
        if host == "safebrowsing.googleapis.com":
            await asyncio.sleep(2)
            return httpx.Response(200, json={})
        if host == "www.virustotal.com":
            return httpx.Response(200, json=vt_body())
        if host == "urlhaus-api.abuse.ch":
            return httpx.Response(200, json={"query_status": "no_results"})
        raise AssertionError(host)

    started = time.monotonic()
    async with mock_client(handler) as client:
        result = await _pipeline(0.05).check("https://example.com/", client)
    elapsed = time.monotonic() - started

    by_name = {item.source: item.status for item in result.sources}
    assert by_name == {
        "google_safe_browsing": "timeout",
        "virustotal": "clean",
        "urlhaus": "clean",
    }
    assert result.judgment.verdict == "CAUTION"
    assert elapsed < 1.0


async def test_a_failed_source_does_not_block_the_others():
    def handler(request: httpx.Request) -> httpx.Response:
        host = request.url.host
        if host == "safebrowsing.googleapis.com":
            return httpx.Response(503, json={"error": "down"})
        if host == "www.virustotal.com":
            return httpx.Response(404, json={"error": "not found"})
        if host == "urlhaus-api.abuse.ch":
            return httpx.Response(200, json={"query_status": "no_results"})
        raise AssertionError(host)

    async with mock_client(handler) as client:
        result = await _pipeline(5).check("https://new.example/", client)

    by_name = {item.source: item.status for item in result.sources}
    assert by_name["google_safe_browsing"] == "error"
    assert by_name["virustotal"] == "unknown"
    assert by_name["urlhaus"] == "clean"
    assert result.judgment.verdict == "CAUTION"
    summaries = "\n".join(item.summary for item in result.sources)
    assert "Google Safe Browsing: HTTP 503" in summaries
    assert "VirusTotal: URL has not been scanned" in summaries
