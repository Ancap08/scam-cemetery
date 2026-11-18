"""Email sources, fixtures, and the rule that a lookalike or disposable domain is not GO."""

import json
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from scam_cemetery.judges.grok import GrokJudge
from scam_cemetery.judges.rules import RulesJudge
from scam_cemetery.pipeline import Pipeline
from scam_cemetery.sources.disposable import DisposableDomainSource, disposable_domains
from scam_cemetery.sources.domain_age import DomainAgeSource
from scam_cemetery.sources.domain_target import DomainThreatAdapter
from scam_cemetery.sources.email_syntax import EmailSyntaxSource
from scam_cemetery.sources.lookalike import BrandLookalikeSource, assess_domain
from scam_cemetery.sources.mail_dns import MailDnsSource
from scam_cemetery.sources.safe_browsing import SafeBrowsingSource
from scam_cemetery.sources.urlhaus import URLhausSource
from scam_cemetery.sources.virustotal import RequestBudget, VirusTotalSource
from tests.helpers import FakeDns, mock_client

_FIXTURES = json.loads((Path(__file__).parent / "fixtures" / "emails.json").read_text())
_NOW = datetime.fromisoformat(_FIXTURES["now"]).astimezone(UTC)


def test_the_vendored_list_is_the_normal_disposable_list():
    domains = disposable_domains()
    assert len(domains) > 10000
    assert "mailinator.com" in domains
    assert "gmail.com" not in domains
    assert "example.com" not in domains
    assert "paypal.com" not in domains


async def test_a_subdomain_of_a_listed_domain_matches_the_parent():
    source = DisposableDomainSource(frozenset({"mailinator.com"}))
    async with httpx.AsyncClient() as client:
        hit = await source.lookup("ada@a.mailinator.com", client)
        miss = await source.lookup("ada@example.com", client)
    assert hit.status == "suspicious"
    assert hit.detail["matched"] == "mailinator.com"
    assert miss.status == "clean"


def test_lookalike_cases():
    assert assess_domain("paypal.com").status == "clean"
    assert assess_domain("login.paypal.com").status == "clean"
    assert assess_domain("example.com").status == "clean"
    assert assess_domain("apply.com").status == "clean"
    assert assess_domain("phase.com").status == "clean"
    assert assess_domain("gmail.com").status == "clean"

    homoglyph = assess_domain("paypa1.com")
    assert homoglyph.status == "malicious"
    assert "PayPal" in homoglyph.summary

    typo = assess_domain("paypall.com")
    assert typo.status == "malicious"

    bait = assess_domain("paypal-secure.com")
    assert bait.status == "malicious"
    assert "added words" in bait.summary

    embedded = assess_domain("paypal.com.evil.example")
    assert embedded.status == "malicious"
    assert "embedded" in embedded.summary

    other_tld = assess_domain("paypal.org")
    assert other_tld.status == "malicious"

    # apple-pie is a word, not a bait token, and apple is too short to fuzzy-match.
    assert assess_domain("apple-pie.com").status == "clean"


@pytest.mark.parametrize("case", _FIXTURES["cases"], ids=lambda case: case["name"])
async def test_email_fixtures_get_the_expected_statuses(case: dict):
    email = case["email"]
    domain = email.split("@", 1)[1]
    local = email.split("@", 1)[0]
    resolver = FakeDns(
        {
            (domain, "MX"): case["mx"],
            (domain, "TXT"): case["spf"],
            (f"_dmarc.{domain}", "TXT"): case["dmarc"],
        }
    )

    def handler(request: httpx.Request) -> httpx.Response:
        assert local not in str(request.url)
        if request.url.host == "data.iana.org":
            tld = domain.rsplit(".", 1)[-1]
            return httpx.Response(
                200,
                json={"services": [[[tld], ["https://rdap.test/rdap/"]]]},
            )
        assert request.url.host == "rdap.test"
        assert request.url.path == f"/rdap/domain/{domain}"
        return httpx.Response(
            200,
            json={
                "events": [
                    {"eventAction": "registration", "eventDate": case["registered"]},
                ]
            },
        )

    async with mock_client(handler) as client:
        results = [
            await EmailSyntaxSource().lookup(email, client),
            await MailDnsSource(resolver).lookup(email, client),
            await DomainAgeSource(now=lambda: _NOW).lookup(email, client),
            await DisposableDomainSource().lookup(email, client),
            await BrandLookalikeSource().lookup(email, client),
        ]
    by_name = {item.source: item.status for item in results}
    expected = case["expect"]
    for name, status in expected.items():
        if name == "verdict":
            continue
        assert by_name[name] == status, name
    judgment = await RulesJudge().judge("redacted", results, subject_type="email")
    assert judgment.verdict == expected["verdict"]
    assert "this email" in judgment.reason
    blob = judgment.reason + "\n" + "\n".join(item.summary for item in results)
    assert email not in blob
    assert local not in blob or len(local) < 4


async def test_disposable_and_lookalike_are_never_go_even_if_grok_says_so():
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        text = request.content.decode()
        assert body["subject_type"] == "email"
        assert "ada@mailinator.com" not in text
        assert "billing@paypa1.com" not in text
        answer = {"verdict": "GO", "reason": "This email looks fine."}
        return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(answer)}}]})

    async with mock_client(handler) as client:
        judge = GrokJudge(
            "test-key", model="grok-4.7", base_url="https://api.x.ai/v1", client=client
        )
        disposable = await Pipeline(
            sources=[DisposableDomainSource()],
            judges=[judge, RulesJudge()],
            timeout=5,
        ).check(
            "ada@mailinator.com",
            client,
            subject_type="email",
            display="a***@mailinator.com",
        )
        lookalike = await Pipeline(
            sources=[BrandLookalikeSource()],
            judges=[judge, RulesJudge()],
            timeout=5,
        ).check(
            "billing@paypa1.com",
            client,
            subject_type="email",
            display="b***@paypa1.com",
        )

    assert disposable.judgment.verdict == "CAUTION"
    assert disposable.judgment.judge == "rules"
    assert "this email" in disposable.judgment.reason
    assert disposable.url == "a***@mailinator.com"
    assert lookalike.judgment.verdict == "NO-GO"
    assert "this email" in lookalike.judgment.reason
    assert "billing@paypa1.com" not in lookalike.judgment.reason


async def test_threat_intel_checks_the_domain_and_shares_the_virustotal_budget():
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        assert "person" not in str(request.url)
        assert "person" not in request.content.decode()
        if request.url.host == "www.virustotal.com":
            from tests.helpers import vt_body

            return httpx.Response(200, json=vt_body())
        if request.url.host == "safebrowsing.googleapis.com":
            body = json.loads(request.content)
            assert body["threatInfo"]["threatEntries"] == [{"url": "https://other.example/"}]
            return httpx.Response(200, json={})
        if request.url.host == "urlhaus-api.abuse.ch":
            assert request.content == b"url=https%3A%2F%2Fother.example%2F"
            return httpx.Response(200, json={"query_status": "no_results"})
        raise AssertionError(request.url.host)

    budget = RequestBudget(limit=4, period=60)
    virustotal = VirusTotalSource("vt-key", budget=budget)
    safe_browsing = SafeBrowsingSource("gsb-key")
    urlhaus = URLhausSource("uh-key")
    async with mock_client(handler) as client:
        await virustotal.lookup("https://example.com/", client)
        await DomainThreatAdapter(virustotal).lookup("person@other.example", client)
        await DomainThreatAdapter(safe_browsing).lookup("person@other.example", client)
        await DomainThreatAdapter(urlhaus).lookup("person@other.example", client)

    assert len(budget._stamps) == 2
    assert any("virustotal.com" in url for url in seen)
    assert all("person" not in url for url in seen)
