"""A missing source key is skipped and named in the reply. It does not crash."""

import httpx

from scam_cemetery.formatting import format_report
from scam_cemetery.judges.rules import RulesJudge
from scam_cemetery.pipeline import Pipeline
from scam_cemetery.sources.safe_browsing import SafeBrowsingSource
from scam_cemetery.sources.urlhaus import URLhausSource
from scam_cemetery.sources.virustotal import VirusTotalSource
from tests.helpers import mock_client, vt_body


async def test_missing_keys_skip_the_source_and_make_no_request():
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"called {request.url.host} with no key configured")

    pipeline = Pipeline(
        sources=[
            SafeBrowsingSource(None),
            VirusTotalSource(None),
            URLhausSource(None),
        ],
        judges=[RulesJudge()],
        timeout=5,
    )
    async with mock_client(handler) as client:
        result = await pipeline.check("https://example.com/", client)

    assert [item.status for item in result.sources] == ["skipped", "skipped", "skipped"]
    report = format_report(result)
    assert "Google Safe Browsing: skipped (no API key)" in report
    assert "VirusTotal: skipped (no API key)" in report
    assert "URLhaus: skipped (no API key)" in report
    assert result.judgment.verdict == "CAUTION"


async def test_a_configured_source_still_runs_when_the_others_are_missing():
    called: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        called.append(request.url.host)
        assert request.url.host == "www.virustotal.com"
        assert request.headers["x-apikey"] == "vt-key"
        return httpx.Response(200, json=vt_body())

    pipeline = Pipeline(
        sources=[
            SafeBrowsingSource(None),
            VirusTotalSource("vt-key"),
            URLhausSource(""),
        ],
        judges=[RulesJudge()],
        timeout=5,
    )
    async with mock_client(handler) as client:
        result = await pipeline.check("https://example.com/path", client)

    assert called == ["www.virustotal.com"]
    by_name = {item.source: item for item in result.sources}
    assert by_name["google_safe_browsing"].status == "skipped"
    assert by_name["urlhaus"].status == "skipped"
    assert by_name["virustotal"].status == "clean"
    assert result.judgment.verdict == "GO"
    report = format_report(result)
    assert "skipped (no API key)" in report
    assert "VirusTotal: no engines flagged it" in report
