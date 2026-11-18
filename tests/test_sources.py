"""The three clients speak the real request shapes. Responses are mocked."""

import base64
import json
import logging

import httpx

from scam_cemetery.judges.rules import RulesJudge
from scam_cemetery.pipeline import Pipeline
from scam_cemetery.sources.safe_browsing import SafeBrowsingSource, parse_safe_browsing
from scam_cemetery.sources.urlhaus import URLhausSource, parse_urlhaus
from scam_cemetery.sources.virustotal import VirusTotalSource, parse_virustotal, url_identifier
from tests.helpers import mock_client, vt_body


def test_virustotal_url_id_is_unpadded_urlsafe_base64():
    url = "http://www.somedomain.com/this/is/my/url"
    identifier = url_identifier(url)
    assert "=" not in identifier
    padded = identifier + "=" * (-len(identifier) % 4)
    assert base64.urlsafe_b64decode(padded).decode() == url


async def test_safe_browsing_posts_a_lookup_and_reads_matches():
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["body"] = json.loads(request.content)
        assert "key" not in request.headers
        return httpx.Response(
            200,
            json={"matches": [{"threatType": "SOCIAL_ENGINEERING"}]},
        )

    async with mock_client(handler) as client:
        result = await SafeBrowsingSource("secret-key").lookup("https://phish.example/", client)

    assert "key=secret-key" in seen["url"]
    threat = seen["body"]["threatInfo"]
    assert threat["threatEntries"] == [{"url": "https://phish.example/"}]
    assert "MALWARE" in threat["threatTypes"]
    assert "SOCIAL_ENGINEERING" in threat["threatTypes"]
    assert result.status == "malicious"
    assert "SOCIAL_ENGINEERING" in result.summary
    assert parse_safe_browsing({}).status == "clean"


async def test_virustotal_lookup_and_not_scanned():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.headers["x-apikey"] == "vt-key"
        assert request.url.path.startswith("/api/v3/urls/")
        return httpx.Response(404, json={"error": {"code": "NotFoundError"}})

    async with mock_client(handler) as client:
        missing = await VirusTotalSource("vt-key").lookup("https://new.example/a", client)
    assert missing.status == "unknown"

    hit = parse_virustotal(vt_body(malicious=3, suspicious=1))
    assert hit.status == "malicious"
    assert "3 engines" in hit.summary
    suspicious = parse_virustotal(vt_body(suspicious=2))
    assert suspicious.status == "suspicious"


async def test_urlhaus_posts_the_url_with_an_auth_key_header():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url == "https://urlhaus-api.abuse.ch/v1/url/"
        assert request.headers["auth-key"] == "uh-key"
        assert request.content == b"url=http%3A%2F%2Fevil.example%2Fa.exe"
        return httpx.Response(
            200,
            json={"query_status": "ok", "threat": "malware_download", "url_status": "online"},
        )

    async with mock_client(handler) as client:
        result = await URLhausSource("uh-key").lookup("http://evil.example/a.exe", client)

    assert result.status == "malicious"
    assert "malware_download" in result.summary
    assert parse_urlhaus({"query_status": "no_results"}).status == "clean"
    assert parse_urlhaus({"query_status": "invalid_url"}).status == "error"


async def test_urlhaus_no_results_is_clean_on_http_200_and_on_an_error_status():
    async def check(status: int) -> str:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(status, json={"query_status": "no_results"})

        async with mock_client(handler) as client:
            result = await URLhausSource("uh-key").lookup("http://example.com/", client)
        return result.status

    assert await check(200) == "clean"
    assert await check(404) == "clean"


async def test_urlhaus_http_error_names_the_status_and_not_the_key(caplog):
    caplog.set_level(logging.WARNING)

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["auth-key"] == "super-secret-key"
        return httpx.Response(403, json={"query_status": "unknown_auth_key"})

    pipeline = Pipeline(
        sources=[URLhausSource("super-secret-key")],
        judges=[RulesJudge()],
        timeout=5,
    )
    async with mock_client(handler) as client:
        result = await pipeline.check("http://example.com/", client)

    assert result.sources[0].status == "error"
    assert "HTTP 403" in result.sources[0].summary
    assert "query_status=unknown_auth_key" in result.sources[0].summary
    assert "urlhaus lookup failed (HTTP 403, query_status=unknown_auth_key)" in caplog.text
    assert "super-secret-key" not in caplog.text
