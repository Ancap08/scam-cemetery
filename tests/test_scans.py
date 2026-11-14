"""VirusTotal submit, poll, rate limit, and the follow-up message."""

import httpx

from scam_cemetery.judges.rules import RulesJudge
from scam_cemetery.pipeline import Pipeline
from scam_cemetery.scans import watch_virustotal
from scam_cemetery.sources.safe_browsing import SafeBrowsingSource
from scam_cemetery.sources.urlhaus import URLhausSource
from scam_cemetery.sources.virustotal import RequestBudget, VirusTotalSource
from scam_cemetery.storage import CheckStore
from tests.helpers import mock_client


async def test_budget_allows_four_calls_then_waits_out_the_minute():
    clock = {"t": 0.0}
    slept: list[float] = []

    async def sleep(seconds: float) -> None:
        slept.append(seconds)
        clock["t"] += seconds

    budget = RequestBudget(limit=4, period=60)
    for _ in range(4):
        await budget.acquire(now=lambda: clock["t"], sleep=sleep)
    assert slept == []
    await budget.acquire(now=lambda: clock["t"], sleep=sleep)
    assert slept == [60.0]


async def test_finished_scan_follows_up_and_can_change_the_verdict(tmp_path):
    polls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            assert request.headers["x-apikey"] == "vt-key"
            assert b"url=https%3A%2F%2Fnew.example%2Fa" in request.content
            return httpx.Response(200, json={"data": {"type": "analysis", "id": "u-test-scan"}})
        polls["n"] += 1
        if polls["n"] == 1:
            return httpx.Response(200, json={"data": {"attributes": {"status": "queued"}}})
        return httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "status": "completed",
                        "stats": {
                            "malicious": 4,
                            "suspicious": 0,
                            "harmless": 60,
                            "undetected": 5,
                        },
                    }
                }
            },
        )

    store = CheckStore(tmp_path / "checks.db")
    source = VirusTotalSource("vt-key", budget=RequestBudget(limit=10, period=60))
    pipeline = Pipeline(sources=[source], judges=[RulesJudge()], timeout=5)
    sent: list[str] = []

    async def send(text: str) -> None:
        sent.append(text)

    async def no_wait(_seconds: float) -> None:
        return None

    prior = _prior()
    async with mock_client(handler) as client:
        await watch_virustotal(
            source=source,
            url="https://new.example/a",
            client=client,
            prior=prior,
            pipeline=pipeline,
            store=store,
            user_id=7,
            send=send,
            sleep=no_wait,
        )

    assert sent[0].startswith("VirusTotal finished scanning.")
    assert "NO-GO" in sent[0]
    assert "4 engines" in sent[0]
    saved = store.archive_latest(7)
    assert saved is not None
    assert store.get(saved)["verdict"] == "NO-GO"
    store.close()


async def test_scan_stops_at_the_deadline(tmp_path):
    clock = {"t": 0.0}
    polls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(200, json={"data": {"id": "u-slow"}})
        polls["n"] += 1
        return httpx.Response(200, json={"data": {"attributes": {"status": "queued"}}})

    async def sleep(seconds: float) -> None:
        clock["t"] += seconds

    store = CheckStore(tmp_path / "checks.db")
    source = VirusTotalSource("vt-key", budget=RequestBudget(limit=10, period=60))
    pipeline = Pipeline(sources=[source], judges=[RulesJudge()], timeout=5)
    sent: list[str] = []

    async def send(text: str) -> None:
        sent.append(text)

    async with mock_client(handler) as client:
        await watch_virustotal(
            source=source,
            url="https://new.example/a",
            client=client,
            prior=_prior(),
            pipeline=pipeline,
            store=store,
            user_id=7,
            send=send,
            deadline_seconds=60,
            poll_interval=20,
            now=lambda: clock["t"],
            sleep=sleep,
        )

    assert sent == ["VirusTotal is still scanning. I stopped waiting after 60 seconds."]
    assert polls["n"] == 3
    assert clock["t"] == 60
    store.close()


def _prior():
    from scam_cemetery.models import CheckResult, Judgment, SourceResult

    return CheckResult(
        url="https://new.example/a",
        sources=[
            SourceResult(
                source="google_safe_browsing",
                display_name="Google Safe Browsing",
                status="clean",
                summary="Google Safe Browsing: no matches",
            ),
            SourceResult(
                source="virustotal",
                display_name="VirusTotal",
                status="unknown",
                summary="VirusTotal: not scanned yet",
                detail={"needs_scan": True},
            ),
        ],
        judgment=Judgment(verdict="GO", reason="Clean enough.", judge="rules"),
    )


async def test_handle_text_schedules_a_scan_only_when_virus_total_has_no_report(tmp_path):
    from scam_cemetery.bot import handle_text

    calls = {"get": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        host = request.url.host
        if host == "safebrowsing.googleapis.com":
            return httpx.Response(200, json={})
        if host == "urlhaus-api.abuse.ch":
            return httpx.Response(200, json={"query_status": "no_results"})
        calls["get"] += 1
        if calls["get"] == 1:
            return httpx.Response(404, json={"error": "NotFoundError"})
        from tests.helpers import vt_body

        return httpx.Response(200, json=vt_body())

    store = CheckStore(tmp_path / "checks.db")
    pipeline = Pipeline(
        sources=[
            SafeBrowsingSource("gsb"),
            VirusTotalSource("vt-key", budget=RequestBudget(limit=10, period=60)),
            URLhausSource("uh"),
        ],
        judges=[RulesJudge()],
        timeout=5,
    )
    sent: list[str] = []
    scheduled: list[object] = []

    async def send(text: str) -> None:
        sent.append(text)

    def schedule(work: object) -> None:
        scheduled.append(work)

    async with mock_client(handler) as client:
        await handle_text(
            user_id=7,
            text="https://new.example/a",
            allowed={7},
            pipeline=pipeline,
            store=store,
            client=client,
            send=send,
            schedule=schedule,  # type: ignore[arg-type]
        )
        assert sent[0] == "checking..."
        assert sent[1].startswith("GO")
        assert "not scanned yet" in sent[1]
        assert len(scheduled) == 1
        scheduled[0].close()  # type: ignore[attr-defined]

        sent.clear()
        scheduled.clear()
        await handle_text(
            user_id=7,
            text="https://known.example/a",
            allowed={7},
            pipeline=pipeline,
            store=store,
            client=client,
            send=send,
            schedule=schedule,  # type: ignore[arg-type]
        )
    assert scheduled == []
    assert sent[1].startswith("GO")
    store.close()
