"""Background VirusTotal scan. The first reply does not wait for this."""

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable

import httpx

from scam_cemetery.formatting import format_report, split_for_telegram
from scam_cemetery.models import CheckResult, SourceResult
from scam_cemetery.pipeline import Pipeline
from scam_cemetery.sources.base import SourceFailure
from scam_cemetery.sources.virustotal import DeadlineExceeded, VirusTotalSource
from scam_cemetery.storage import CheckStore

logger = logging.getLogger(__name__)

SCAN_DEADLINE_SECONDS = 60.0
POLL_INTERVAL_SECONDS = 20.0
SCAN_TIMEOUT_MESSAGE = "VirusTotal is still scanning. I stopped waiting after 60 seconds."
Send = Callable[[str], Awaitable[None]]


async def watch_virustotal(
    *,
    source: VirusTotalSource,
    url: str,
    client: httpx.AsyncClient,
    prior: CheckResult,
    pipeline: Pipeline,
    store: CheckStore,
    user_id: int,
    send: Send,
    deadline_seconds: float = SCAN_DEADLINE_SECONDS,
    poll_interval: float = POLL_INTERVAL_SECONDS,
    now: Callable[[], float] | None = None,
    sleep: Callable[[float], Awaitable[None]] | None = None,
) -> None:
    """Submit ``url``, poll until the scan finishes or ``deadline_seconds`` elapses, then reply."""
    clock = now or time.monotonic
    pause = sleep or asyncio.sleep
    started = clock()

    def remaining() -> float:
        return deadline_seconds - (clock() - started)

    try:
        if remaining() <= 0:
            raise DeadlineExceeded()
        analysis_id = await source.submit(url, client, timeout=remaining(), now=clock, sleep=pause)
    except DeadlineExceeded:
        await send(SCAN_TIMEOUT_MESSAGE)
        return
    except SourceFailure as exc:
        await send(f"VirusTotal scan was not submitted ({exc.reason}).")
        return
    except Exception as exc:
        logger.warning("virustotal submit failed (%s)", type(exc).__name__)
        await send("VirusTotal scan was not submitted.")
        return

    while True:
        left = remaining()
        if left <= 0:
            await send(SCAN_TIMEOUT_MESSAGE)
            return
        await pause(min(poll_interval, left))
        left = remaining()
        if left <= 0:
            await send(SCAN_TIMEOUT_MESSAGE)
            return
        try:
            polled = await source.poll(analysis_id, client, timeout=left, now=clock, sleep=pause)
        except DeadlineExceeded:
            await send(SCAN_TIMEOUT_MESSAGE)
            return
        except SourceFailure as exc:
            await send(f"VirusTotal scan check failed ({exc.reason}).")
            return
        except Exception as exc:
            logger.warning("virustotal poll failed (%s)", type(exc).__name__)
            await send("VirusTotal scan check failed.")
            return
        if polled is None:
            continue
        sources = _replace_source(prior.sources, polled)
        # Save the same display string as the first reply. For an email that is
        # the redacted address; ``url`` here is only what VirusTotal scanned.
        judgment = await pipeline.judge(prior.url, sources, subject_type=prior.subject_type)
        result = CheckResult(
            url=prior.url,
            sources=sources,
            judgment=judgment,
            subject_type=prior.subject_type,
            subject_hash=prior.subject_hash,
            subject_display=prior.subject_display or prior.url,
            scan_url=prior.scan_url,
        )
        store.save(result, telegram_user_id=user_id)
        text = "VirusTotal finished scanning.\n\n" + format_report(result)
        for chunk in split_for_telegram(text):
            await send(chunk)
        return


def _replace_source(sources: list[SourceResult], replacement: SourceResult) -> list[SourceResult]:
    return [replacement if item.source == replacement.source else item for item in sources]
