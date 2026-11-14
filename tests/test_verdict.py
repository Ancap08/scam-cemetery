"""Verdict rules, the Grok parser, and the fallback when xAI fails."""

import json

import httpx
import pytest

from scam_cemetery.formatting import format_report
from scam_cemetery.judges.grok import GrokJudge, _parse_judgment
from scam_cemetery.judges.rules import RulesJudge
from scam_cemetery.models import CheckResult, Judgment
from scam_cemetery.pipeline import Pipeline
from tests.helpers import mock_client, source


def _pipeline(judges, timeout=8.0, sources=None) -> Pipeline:
    return Pipeline(sources or [], judges=judges, timeout=timeout)


async def test_rules_malicious_is_nogo():
    judgment = await RulesJudge().judge(
        "https://evil.example/",
        [source("Google Safe Browsing", "malicious"), source("VirusTotal", "clean")],
    )
    assert judgment.verdict == "NO-GO"
    assert judgment.judge == "rules"
    assert "Google Safe Browsing" in judgment.reason


async def test_rules_unknown_error_timeout_and_suspicious_are_caution():
    judge = RulesJudge()
    for status in ("unknown", "error", "timeout", "suspicious"):
        judgment = await judge.judge("https://example.com/", [source("VirusTotal", status)])
        assert judgment.verdict == "CAUTION", status


async def test_rules_all_clean_is_go_and_skipped_sources_do_not_count():
    judgment = await RulesJudge().judge(
        "https://example.com/",
        [
            source("Google Safe Browsing", "clean"),
            source("VirusTotal", "skipped"),
            source("URLhaus", "clean"),
        ],
    )
    assert judgment.verdict == "GO"


async def test_rules_all_skipped_is_caution():
    judgment = await RulesJudge().judge(
        "https://example.com/",
        [source("Google Safe Browsing", "skipped"), source("VirusTotal", "skipped")],
    )
    assert judgment.verdict == "CAUTION"
    assert "not checked" in judgment.reason


async def test_rules_malicious_wins_over_a_timeout():
    judgment = await RulesJudge().judge(
        "https://evil.example/",
        [source("URLhaus", "malicious"), source("VirusTotal", "timeout")],
    )
    assert judgment.verdict == "NO-GO"


async def test_grok_parser_accepts_fenced_json_and_verdict_aliases():
    fenced = 'Sure\n```json\n{"verdict": "NO GO", "reason": "It is listed."}\n```'
    assert _parse_judgment(fenced) == Judgment(
        verdict="NO-GO", reason="It is listed.", judge="grok"
    )
    assert _parse_judgment('{"verdict": "no_go", "reason": "Listed."}').verdict == "NO-GO"


async def test_grok_parser_rejects_junk():
    from scam_cemetery.judges.base import JudgeUnavailable

    with pytest.raises(JudgeUnavailable):
        _parse_judgment("I think this is fine.")
    with pytest.raises(JudgeUnavailable):
        _parse_judgment('{"verdict": "MAYBE", "reason": "no"}')


async def test_pipeline_uses_grok_when_it_answers():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "api.x.ai"
        assert request.headers["authorization"].startswith("Bearer ")
        body = json.loads(request.content)
        assert body["model"] == "grok-4.7"
        answer = {"verdict": "CAUTION", "reason": "VirusTotal has not scanned it."}
        return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(answer)}}]})

    async with mock_client(handler) as client:
        judge = GrokJudge(
            "test-key",
            model="grok-4.7",
            base_url="https://api.x.ai/v1",
            client=client,
        )
        result = await _pipeline([judge, RulesJudge()]).check("https://example.com/", client)

    assert result.judgment.verdict == "CAUTION"
    assert result.judgment.judge == "grok"
    assert result.judgment.reason == "VirusTotal has not scanned it."


async def test_pipeline_falls_back_when_xai_fails():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": "nope"})

    async with mock_client(handler) as client:
        judge = GrokJudge(
            "test-key", model="grok-4.7", base_url="https://api.x.ai/v1", client=client
        )
        result = await _pipeline(
            [judge, RulesJudge()],
            sources=[_static("google_safe_browsing", "Google Safe Browsing", "clean")],
        ).check("https://example.com/", client)

    assert result.judgment.judge == "rules"
    assert result.judgment.verdict == "GO"


async def test_pipeline_rejects_a_go_that_ignores_a_malicious_hit():
    def handler(request: httpx.Request) -> httpx.Response:
        answer = {"verdict": "GO", "reason": "Looks fine to me."}
        return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(answer)}}]})

    async with mock_client(handler) as client:
        judge = GrokJudge(
            "test-key", model="grok-4.7", base_url="https://api.x.ai/v1", client=client
        )
        result = await _pipeline(
            [judge, RulesJudge()],
            sources=[_static("urlhaus", "URLhaus", "malicious")],
        ).check("https://evil.example/", client)

    assert result.judgment.judge == "rules"
    assert result.judgment.verdict == "NO-GO"


async def test_missing_xai_key_uses_rules_without_calling_xai():
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("xAI was called without a key")

    async with mock_client(handler) as client:
        judge = GrokJudge(None, model="grok-4.7", base_url="https://api.x.ai/v1", client=client)
        result = await _pipeline([judge, RulesJudge()]).check("https://example.com/", client)

    assert result.judgment.judge == "rules"
    assert result.judgment.verdict == "CAUTION"


def test_report_has_the_verdict_and_one_line_per_source():
    result = CheckResult(
        url="https://evil.example/phish",
        sources=[
            source("sb", "malicious", summary="Google Safe Browsing: flagged MALWARE"),
            source("vt", "clean", summary="VirusTotal: no engines flagged it"),
            source("uh", "skipped", summary="URLhaus: skipped (no API key)"),
        ],
        judgment=Judgment(verdict="NO-GO", reason="Safe Browsing listed it.", judge="grok"),
    )
    text = format_report(result)
    lines = text.splitlines()
    assert lines[0] == "NO-GO"
    assert "https://evil.example/phish" in lines
    assert "Google Safe Browsing: flagged MALWARE" in lines
    assert "VirusTotal: no engines flagged it" in lines
    assert "URLhaus: skipped (no API key)" in lines
    assert "Grok: Safe Browsing listed it." in lines


class _StaticSource:
    """A source that does not use the network. Used to feed the pipeline."""

    def __init__(self, name: str, display_name: str, status: str) -> None:
        self.name = name
        self.display_name = display_name
        self._status = status

    def is_configured(self) -> bool:
        return True

    async def lookup(self, url: str, client: httpx.AsyncClient):
        del url, client
        return source(self.name, self._status, display_name=self.display_name)


def _static(name: str, display_name: str, status: str) -> _StaticSource:
    return _StaticSource(name, display_name, status)
