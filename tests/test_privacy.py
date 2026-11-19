"""Raw email addresses and phone numbers are not stored or logged."""

import hashlib
import logging
import sqlite3
from datetime import UTC, datetime

import httpx

from scam_cemetery.bot import handle_text
from scam_cemetery.judges.rules import RulesJudge
from scam_cemetery.models import SourceResult
from scam_cemetery.pipeline import Checker, Pipeline
from scam_cemetery.sources.disposable import DisposableDomainSource
from scam_cemetery.sources.domain_age import DomainAgeSource
from scam_cemetery.sources.domain_target import DomainThreatAdapter
from scam_cemetery.sources.email_syntax import EmailSyntaxSource
from scam_cemetery.sources.lookalike import BrandLookalikeSource
from scam_cemetery.sources.mail_dns import MailDnsSource
from scam_cemetery.sources.numverify import NumverifySource
from scam_cemetery.sources.phone_info import PhoneNumberSource
from scam_cemetery.sources.safe_browsing import SafeBrowsingSource
from scam_cemetery.sources.urlhaus import URLhausSource
from scam_cemetery.sources.virustotal import RequestBudget, VirusTotalSource
from scam_cemetery.storage import CheckStore
from tests.helpers import FakeDns, mock_client, vt_body

_EMAIL = "zq7-raw-local-9f3c@long-lived-example.com"
_PHONE = "+19005551212"
_NOW = datetime(2026, 11, 18, tzinfo=UTC)


class _Echo:
    """A source that repeats whatever it was given. Storage must still be redacted."""

    name = "echo"
    display_name = "Echo"

    def is_configured(self) -> bool:
        return True

    async def lookup(self, target: str, client: httpx.AsyncClient) -> SourceResult:
        del client
        return SourceResult(
            source=self.name,
            display_name=self.display_name,
            status="clean",
            summary=f"saw {target}",
            detail={"raw": target},
        )


def test_an_echoing_source_cannot_write_the_raw_email_or_phone(tmp_path):
    import asyncio

    path = tmp_path / "checks.db"
    store = CheckStore(path)

    async def run() -> None:
        async with httpx.AsyncClient() as client:
            email = await Pipeline([_Echo()], [RulesJudge()], timeout=5).check(
                _EMAIL,
                client,
                subject_type="email",
                display="z***@long-lived-example.com",
            )
            phone = await Pipeline([_Echo()], [RulesJudge()], timeout=5).check(
                _PHONE,
                client,
                subject_type="phone",
                display="+1******1212",
            )
        assert _EMAIL not in email.sources[0].summary
        assert "z***@long-lived-example.com" in email.sources[0].summary
        assert email.sources[0].detail["raw"] == "z***@long-lived-example.com"
        assert _PHONE not in phone.sources[0].summary
        assert "900555" not in phone.sources[0].summary
        store.save(email, telegram_user_id=1)
        store.save(phone, telegram_user_id=1)

    asyncio.run(run())
    store.close()
    _assert_secrets_absent(path)


def test_migration_keeps_old_rows_and_archive_still_works(tmp_path):
    path = tmp_path / "legacy.db"
    conn = sqlite3.connect(path)
    conn.execute(
        """
        CREATE TABLE checks (
            id INTEGER PRIMARY KEY,
            url TEXT NOT NULL,
            checked_at TEXT NOT NULL,
            telegram_user_id INTEGER,
            source_results TEXT NOT NULL,
            verdict TEXT NOT NULL,
            reason TEXT NOT NULL,
            judge TEXT NOT NULL,
            archive INTEGER NOT NULL DEFAULT 0
        )
        """
    )
    conn.execute(
        """
        INSERT INTO checks (
            url, checked_at, telegram_user_id, source_results, verdict, reason, judge, archive
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 0)
        """,
        (
            "https://old.example/",
            "2000-01-01T00:00:00+00:00",
            7,
            "[]",
            "GO",
            "Clean.",
            "rules",
        ),
    )
    conn.execute(
        """
        INSERT INTO checks (
            url, checked_at, telegram_user_id, source_results, verdict, reason, judge, archive
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 0)
        """,
        (
            "https://kept.example/",
            "2026-11-01T00:00:00+00:00",
            7,
            "[]",
            "CAUTION",
            "Thin.",
            "rules",
        ),
    )
    conn.commit()
    conn.close()

    store = CheckStore(path)
    old = store.get(1)
    kept = store.get(2)
    assert old is not None and kept is not None
    assert old["subject_type"] == "url"
    assert old["subject_display"] == "https://old.example/"
    assert old["subject_hash"] == hashlib.sha256(b"https://old.example/").hexdigest()
    assert old["verdict"] == "GO"
    assert store.archive_latest(7) == 2
    removed = store.cleanup(now=datetime(2026, 11, 18, tzinfo=UTC))
    assert removed == 1
    assert store.get(1) is None
    assert store.get(2) is not None
    assert store.get(2)["archive"] == 1
    store.close()


async def test_a_real_check_does_not_store_or_log_the_raw_value(tmp_path, caplog):
    caplog.set_level(logging.INFO)
    path = tmp_path / "checks.db"
    store = CheckStore(path)
    sent: list[str] = []

    async def send(text: str) -> None:
        sent.append(text)

    checker = _checker()

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        body = request.content.decode()
        assert "zq7-raw-local-9f3c" not in url
        assert "zq7-raw-local-9f3c" not in body
        assert "19005551212" not in url
        assert "19005551212" not in body
        host = request.url.host
        if host == "safebrowsing.googleapis.com":
            return httpx.Response(200, json={})
        if host == "www.virustotal.com":
            return httpx.Response(200, json=vt_body())
        if host == "urlhaus-api.abuse.ch":
            return httpx.Response(200, json={"query_status": "no_results"})
        if host == "data.iana.org":
            return httpx.Response(
                200,
                json={"services": [[["com"], ["https://rdap.test/rdap/"]]]},
            )
        if host == "rdap.test":
            return httpx.Response(
                200,
                json={
                    "events": [{"eventAction": "registration", "eventDate": "2001-03-04T00:00:00Z"}]
                },
            )
        raise AssertionError(host)

    async with mock_client(handler) as client:
        await handle_text(
            user_id=7,
            text=f"please check {_EMAIL} and also {_PHONE}",
            allowed=frozenset({7}),
            pipeline=checker,
            store=store,
            client=client,
            send=send,
        )

    assert sent[0] == "checking 2 items..."
    reply = sent[1]
    assert "z***@long-lived-example.com" in reply
    assert "+1******1212" in reply
    assert _EMAIL not in reply
    assert _PHONE not in reply
    assert "zq7-raw-local-9f3c" not in reply
    assert "this email" in reply or "Email" in reply
    store.close()
    _assert_secrets_absent(path)
    assert "zq7-raw-local-9f3c" not in caplog.text
    assert _PHONE not in caplog.text
    assert "19005551212" not in caplog.text
    assert "900555" not in caplog.text


def _assert_secrets_absent(path) -> None:
    blob = path.read_bytes()
    assert b"zq7-raw-local-9f3c" not in blob
    assert _EMAIL.encode() not in blob
    assert _PHONE.encode() not in blob
    assert b"19005551212" not in blob
    assert b"9005551212" not in blob
    assert b"z***@long-lived-example.com" in blob
    assert b"+1******1212" in blob
    email_hash = hashlib.sha256(_EMAIL.encode()).hexdigest().encode()
    phone_hash = hashlib.sha256(_PHONE.encode()).hexdigest().encode()
    assert email_hash in blob
    assert phone_hash in blob


def _checker() -> Checker:
    safe_browsing = SafeBrowsingSource("gsb-key")
    virustotal = VirusTotalSource("vt-key", budget=RequestBudget(limit=10, period=60))
    urlhaus = URLhausSource("uh-key")
    judges = [RulesJudge()]
    resolver = FakeDns(
        {
            ("long-lived-example.com", "MX"): ["10 mx.long-lived-example.com."],
            ("long-lived-example.com", "TXT"): ["v=spf1 -all"],
            ("_dmarc.long-lived-example.com", "TXT"): ["v=DMARC1; p=none"],
        }
    )
    email = Pipeline(
        sources=[
            EmailSyntaxSource(),
            MailDnsSource(resolver),
            DomainAgeSource(now=lambda: _NOW),
            DisposableDomainSource(),
            BrandLookalikeSource(),
            DomainThreatAdapter(safe_browsing),
            DomainThreatAdapter(virustotal),
            DomainThreatAdapter(urlhaus),
        ],
        judges=judges,
        timeout=5,
    )
    phone = Pipeline(
        sources=[PhoneNumberSource(), NumverifySource(None)],
        judges=judges,
        timeout=5,
    )
    url = Pipeline(
        sources=[safe_browsing, virustotal, urlhaus],
        judges=judges,
        timeout=5,
    )
    return Checker(url, email, phone, virustotal=virustotal)
