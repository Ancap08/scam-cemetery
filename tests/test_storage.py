"""Checks are stored, and cleanup keeps archived rows past 90 days."""

from datetime import UTC, datetime, timedelta

from scam_cemetery.models import CheckResult, Judgment, SourceResult
from scam_cemetery.storage import CheckStore


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


def test_archive_with_no_checks_is_a_noop(tmp_path):
    store = CheckStore(tmp_path / "checks.db")
    assert store.archive_latest(1) is None
    assert store.cleanup() == 0
    store.close()
