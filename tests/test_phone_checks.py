"""Phone fixtures and the optional Numverify source."""

import json
from pathlib import Path

import httpx
import pytest

from scam_cemetery.judges.grok import GrokJudge
from scam_cemetery.judges.rules import RulesJudge
from scam_cemetery.pipeline import Pipeline
from scam_cemetery.sources.numverify import NumverifySource
from scam_cemetery.sources.phone_info import PhoneNumberSource, inspect_phone
from scam_cemetery.subjects import extract_subjects
from tests.helpers import mock_client, source

_FIXTURES = json.loads((Path(__file__).parent / "fixtures" / "phones.json").read_text())


@pytest.mark.parametrize("case", _FIXTURES["cases"], ids=lambda case: case["name"])
async def test_phone_fixture(case: dict):
    subjects = extract_subjects(case["raw"], default_region=case["region"])
    phones = [item for item in subjects if item.kind == "phone"]
    if case["extract"]:
        assert [item.canonical for item in phones] == [case["e164"]]
        assert phones[0].display == case["display"]
        assert case["e164"] not in case["display"]
        checked = case["e164"]
    else:
        assert phones == []
        checked = case["raw"]

    result = inspect_phone(checked, region=case["region"])
    assert result.status == case["status"]
    assert "offline" in result.summary
    assert "not a live carrier lookup" in result.summary
    if "line_type" in case:
        assert case["line_type"] in result.summary
    if "region_code" in case:
        assert case["region_code"] in result.summary
    blob = result.summary + json.dumps(result.detail)
    assert case["raw"] not in blob
    if "e164" in case:
        assert case["e164"] not in blob
        national = case["e164"][1:]
        assert national not in blob

    judgment = await RulesJudge().judge(
        case.get("display", "redacted"),
        [result, source("numverify", "skipped", display_name="Numverify")],
        subject_type="phone",
    )
    assert judgment.verdict == case["verdict"]
    assert "this phone number" in judgment.reason


async def test_voip_and_premium_are_not_go_when_grok_says_go():
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assert body["subject_type"] == "phone"
        assert body["url"] == "+1******1212"
        assert "9005551212" not in request.content.decode()
        answer = {"verdict": "GO", "reason": "This phone number looks fine."}
        return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(answer)}}]})

    async with mock_client(handler) as client:
        judge = GrokJudge(
            "test-key", model="grok-4.7", base_url="https://api.x.ai/v1", client=client
        )
        result = await Pipeline(
            sources=[PhoneNumberSource()],
            judges=[judge, RulesJudge()],
            timeout=5,
        ).check(
            "+19005551212",
            client,
            subject_type="phone",
            display="+1******1212",
        )

    assert result.judgment.verdict == "CAUTION"
    assert result.judgment.judge == "rules"
    assert "this phone number" in result.judgment.reason
    assert "+19005551212" not in result.judgment.reason
    assert "900555" not in result.sources[0].summary


async def test_numverify_is_skipped_without_a_key_and_reports_carrier_with_one():
    def refuse(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"called {request.url.host} with no key")

    async with mock_client(refuse) as client:
        skipped = await Pipeline(
            sources=[PhoneNumberSource(), NumverifySource(None)],
            judges=[RulesJudge()],
            timeout=5,
        ).check("+14155552671", client, subject_type="phone", display="+1******2671")
    assert skipped.sources[1].status == "skipped"
    assert "no API key" in skipped.sources[1].summary
    assert skipped.judgment.verdict == "GO"

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["access_key"] == "nv-test-key"
        assert request.url.params["number"] == "14155552671"
        return httpx.Response(
            200,
            json={
                "valid": True,
                "number": "14155552671",
                "local_format": "4155552671",
                "international_format": "+14155552671",
                "country_code": "US",
                "carrier": "Example Wireless",
                "line_type": "mobile",
            },
        )

    async with mock_client(handler) as client:
        checked = await NumverifySource("nv-test-key").lookup("+14155552671", client)
    assert checked.status == "clean"
    assert "Example Wireless" in checked.summary
    assert "mobile" in checked.summary
    blob = checked.summary + json.dumps(checked.detail)
    assert "14155552671" not in blob
    assert "4155552671" not in blob
    assert "nv-test-key" not in blob
    assert checked.detail == {
        "carrier": "Example Wireless",
        "line_type": "mobile",
        "country_code": "US",
    }
