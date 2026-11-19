"""Checks are stored, and cleanup keeps archived rows past 90 days."""

import asyncio
import warnings
from datetime import UTC, datetime, timedelta

import httpx
from telegram import User

from scam_cemetery.bot import build_application
from scam_cemetery.config import Settings
from scam_cemetery.models import CheckResult, Judgment, SourceResult
from scam_cemetery.storage import CheckStore, cleanup_loop


def _result(url: str = "https://example.com/") -> CheckResult:
    return CheckResult(
        url=url,
        sources=[
            SourceResult(
                source="urlhaus",
                display_name="URLhaus",
                status="clean",
                summary="URLhaus: not listed",
            )
        ],
        judgment=Judgment(verdict="GO", reason="Clean.", judge="rules"),
    )


def test_cleanup_drops_old_rows_and_keeps_archived_ones(tmp_path):
    store = CheckStore(tmp_path / "checks.db")
    now = datetime(2026, 11, 14, tzinfo=UTC)
    old = store.save(
        _result("https://old.example/"),
        telegram_user_id=1,
        checked_at=now - timedelta(days=91),
    )
    kept = store.save(
        _result("https://kept.example/"),
        telegram_user_id=1,
        checked_at=now - timedelta(days=10),
    )
    archived = store.save(
        _result("https://archived.example/"),
        telegram_user_id=1,
        checked_at=now - timedelta(days=200),
    )
    assert store.archive_latest(1) == archived

    removed = store.cleanup(now=now)
    assert removed == 1
    assert store.get(old) is None
    assert store.get(kept) is not None
    assert store.get(kept)["archive"] == 0
    archived_row = store.get(archived)
    assert archived_row is not None
    assert archived_row["archive"] == 1
    assert archived_row["verdict"] == "GO"
    assert "not listed" in archived_row["source_results"]
    store.close()


async def test_cleanup_loop_deletes_expired_rows_then_stops(tmp_path):
    store = CheckStore(tmp_path / "checks.db")
    now = datetime.now(UTC)
    old = store.save(
        _result("https://old.example/"),
        telegram_user_id=1,
        checked_at=now - timedelta(days=91),
    )
    kept = store.save(
        _result("https://kept.example/"),
        telegram_user_id=1,
        checked_at=now - timedelta(days=1),
    )
    stop = asyncio.Event()
    task = asyncio.create_task(cleanup_loop(store, stop, interval=0.01))
    for _ in range(50):
        if store.get(old) is None:
            break
        await asyncio.sleep(0.01)
    assert store.get(old) is None
    assert store.get(kept) is not None
    stop.set()
    await asyncio.wait_for(task, timeout=1)
    store.close()


async def test_application_start_runs_cleanup_without_the_startup_warning(tmp_path):
    store = CheckStore(tmp_path / "checks.db")
    now = datetime.now(UTC)
    old = store.save(
        _result("https://old.example/"),
        telegram_user_id=1,
        checked_at=now - timedelta(days=200),
    )
    settings = Settings(
        telegram_bot_token="123456789:AAFakeTokenForTestsOnly",
        xai_api_key=None,
        xai_model="grok-4.7",
        xai_base_url="https://api.x.ai/v1",
        google_safe_browsing_key=None,
        virustotal_api_key=None,
        urlhaus_auth_key=None,
        numverify_api_key=None,
        default_phone_region="US",
        allowed_telegram_user_ids=frozenset({1}),
        database_path=str(store.path),
        source_timeout_seconds=8,
        judge_timeout_seconds=20,
    )

    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError(request.url)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    application = build_application(settings, store, _UnusedPipeline(), client)
    application.bot_data["cleanup_interval"] = 0.01
    application._initialized = True  # skip Telegram initialize(); start() only checks this flag
    application.bot._bot_user = User(id=123456789, is_bot=True, first_name="test")
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        await application.start()
        for _ in range(50):
            if store.get(old) is None:
                break
            await asyncio.sleep(0.01)
        assert store.get(old) is None
        await application.stop()
    assert not any("automatically awaited" in str(item.message) for item in caught)
    await client.aclose()
    store.close()


class _UnusedPipeline:
    def virustotal(self):
        return None


def test_archive_with_no_checks_is_a_noop(tmp_path):
    store = CheckStore(tmp_path / "checks.db")
    assert store.archive_latest(1) is None
    assert store.cleanup() == 0
    store.close()
