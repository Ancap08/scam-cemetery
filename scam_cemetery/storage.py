"""SQLite log of every check, with a 90-day cleanup and an archive exemption.

The schema is one table. Rows are small JSON blobs, not a normalized warehouse.
An existing production file is missing the subject columns; ``ALTER TABLE``
adds them without rewriting the rows. Email addresses and phone numbers are
stored as a SHA-256 of the canonical form and a redacted display form.
"""

import asyncio
import hashlib
import json
import logging
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

from scam_cemetery.models import CheckResult

logger = logging.getLogger(__name__)

RETENTION_DAYS = 90


class CheckStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        if self.path.parent != Path(""):
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS checks (
                id INTEGER PRIMARY KEY,
                url TEXT NOT NULL,
                checked_at TEXT NOT NULL,
                telegram_user_id INTEGER,
                source_results TEXT NOT NULL,
                verdict TEXT NOT NULL,
                reason TEXT NOT NULL,
                judge TEXT NOT NULL,
                archive INTEGER NOT NULL DEFAULT 0,
                subject_type TEXT NOT NULL DEFAULT 'url',
                subject_hash TEXT NOT NULL DEFAULT '',
                subject_display TEXT NOT NULL DEFAULT ''
            )
            """
        )
        self._migrate()
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def save(
        self,
        result: CheckResult,
        *,
        telegram_user_id: int,
        checked_at: datetime | None = None,
    ) -> int:
        when = checked_at or datetime.now(UTC)
        kind = result.subject_type or "url"
        # For an email or a phone, never fall back to ``result.url`` when the
        # redacted display is missing. That fallback is how a raw value would
        # land in the url column.
        if kind in {"email", "phone"}:
            display = result.subject_display or "[redacted]"
        else:
            display = result.subject_display or result.url
        digest = result.subject_hash
        if not digest and kind == "url":
            digest = hashlib.sha256(display.encode("utf-8")).hexdigest()
        cursor = self._conn.execute(
            """
            INSERT INTO checks (
                url, checked_at, telegram_user_id, source_results,
                verdict, reason, judge, archive,
                subject_type, subject_hash, subject_display
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)
            """,
            (
                display,
                _stamp(when),
                telegram_user_id,
                json.dumps([item.to_dict() for item in result.sources]),
                result.judgment.verdict,
                result.judgment.reason,
                result.judgment.judge,
                kind,
                digest,
                display,
            ),
        )
        self._conn.commit()
        return int(cursor.lastrowid)

    def archive_latest(self, telegram_user_id: int) -> int | None:
        """Set archive=1 on this user's newest check. Archived rows skip cleanup."""
        row = self._conn.execute(
            """
            SELECT id FROM checks
            WHERE telegram_user_id = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (telegram_user_id,),
        ).fetchone()
        if row is None:
            return None
        check_id = int(row["id"])
        self._conn.execute("UPDATE checks SET archive = 1 WHERE id = ?", (check_id,))
        self._conn.commit()
        return check_id

    def cleanup(self, *, now: datetime | None = None, retention_days: int = RETENTION_DAYS) -> int:
        """Delete non-archived checks older than ``retention_days``. Returns the count."""
        moment = now or datetime.now(UTC)
        cutoff = _stamp(moment - timedelta(days=retention_days))
        cursor = self._conn.execute(
            "DELETE FROM checks WHERE archive = 0 AND checked_at < ?",
            (cutoff,),
        )
        self._conn.commit()
        return int(cursor.rowcount)

    def get(self, check_id: int) -> sqlite3.Row | None:
        return self._conn.execute("SELECT * FROM checks WHERE id = ?", (check_id,)).fetchone()

    def _migrate(self) -> None:
        """Add subject columns to a database created before email and phone checks.

        ``ADD COLUMN ... DEFAULT`` keeps the existing rows. Link rows are backfilled
        so the hash and the display match the URL that was already stored.
        """
        columns = {row[1] for row in self._conn.execute("PRAGMA table_info(checks)")}
        statements: list[str] = []
        if "subject_type" not in columns:
            statements.append(
                "ALTER TABLE checks ADD COLUMN subject_type TEXT NOT NULL DEFAULT 'url'"
            )
        if "subject_hash" not in columns:
            statements.append("ALTER TABLE checks ADD COLUMN subject_hash TEXT NOT NULL DEFAULT ''")
        if "subject_display" not in columns:
            statements.append(
                "ALTER TABLE checks ADD COLUMN subject_display TEXT NOT NULL DEFAULT ''"
            )
        for statement in statements:
            self._conn.execute(statement)
        self._conn.execute(
            """
            UPDATE checks
            SET subject_display = url
            WHERE subject_display = '' AND subject_type = 'url'
            """
        )
        rows = self._conn.execute(
            "SELECT id, url FROM checks WHERE subject_type = 'url' AND subject_hash = ''"
        ).fetchall()
        for row in rows:
            digest = hashlib.sha256(str(row["url"]).encode("utf-8")).hexdigest()
            self._conn.execute(
                "UPDATE checks SET subject_hash = ? WHERE id = ?",
                (digest, row["id"]),
            )


async def cleanup_loop(
    store: CheckStore,
    stop: asyncio.Event,
    *,
    interval: float = 24 * 60 * 60,
) -> None:
    """Delete expired checks every ``interval`` seconds until ``stop`` is set.

    The wait is interruptible, so shutting the bot down does not sit on the
    full interval.
    """
    while True:
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
        except TimeoutError:
            pass
        else:
            return
        try:
            removed = store.cleanup()
        except Exception:
            logger.exception("daily cleanup failed")
            continue
        logger.info("daily cleanup removed %s checks", removed)


def _stamp(moment: datetime) -> str:
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC).isoformat(timespec="seconds")
