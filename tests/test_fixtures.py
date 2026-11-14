"""Replay the known-good and known-bad fixtures through the real parsers."""

import json
from pathlib import Path

import pytest

from scam_cemetery.judges.rules import RulesJudge
from scam_cemetery.sources.safe_browsing import parse_safe_browsing
from scam_cemetery.sources.urlhaus import parse_urlhaus
from scam_cemetery.sources.virustotal import parse_virustotal
from scam_cemetery.url_extract import extract_urls

_FIXTURES = json.loads((Path(__file__).parent / "fixtures" / "urls.json").read_text())


def _cases():
    rows = []
    for kind in ("known_good", "known_bad"):
        for item in _FIXTURES[kind]:
            rows.append(pytest.param(item, id=f"{kind}-{item['url']}"))
    return rows


@pytest.mark.parametrize("item", _cases())
async def test_fixture_url_gets_the_expected_rules_verdict(item: dict):
    results = [
        parse_safe_browsing(item["safe_browsing"]),
        parse_virustotal(item["virustotal"]),
        parse_urlhaus(item["urlhaus"]),
    ]
    judgment = await RulesJudge().judge(item["url"], results)
    assert judgment.verdict == item["expected_verdict"]
    # The URL still has to survive a messy paste, which is how it arrives.
    pasted = f"can you look at {item['url']} please"
    assert extract_urls(pasted) == [item["url"]]


def test_fixture_file_has_both_kinds():
    assert _FIXTURES["known_good"]
    assert _FIXTURES["known_bad"]
    assert "malware.testing.google.test" in _FIXTURES["known_bad"][0]["url"]
