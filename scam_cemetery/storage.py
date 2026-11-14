"""SQLite log of every check, with a 90-day cleanup and an archive exemption.

The schema is one table. Rows are small JSON blobs, not a normalized warehouse.
"""

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

from scam_cemetery.models import CheckResult

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
                archive INTEGER NOT NULL DEFAULT 0
            )
            """
        )
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
        cursor = self._conn.execute(
            """
            INSERT INTO checks (
                url, checked_at, telegram_user_id, source_results,
                verdict, reason, judge, archive
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, 0)
            """,
            (
                result.url,
                _stamp(when),
                telegram_user_id,
                json.dumps([item.to_dict() for item in result.sources]),
                result.judgment.verdict,
                result.judgment.reason,
                result.judgment.judge,
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


def _stamp(moment: datetime) -> str:
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC).isoformat(timespec="seconds")
