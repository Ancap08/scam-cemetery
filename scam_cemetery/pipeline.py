"""Run every configured source at once, then ask a judge for the verdict.

Each lookup gets the same timeout, and they run together. A slow or failed
source becomes a result and does not cancel the others. Judges are tried in
list order. The last one should be RulesJudge, which always answers.
"""

import asyncio
import logging

import httpx

from scam_cemetery.judges.base import Judge
from scam_cemetery.models import CheckResult, Judgment, SourceResult
from scam_cemetery.sources.base import (
    SourceFailure,
    ThreatSource,
    error_result,
    skipped_result,
    timeout_result,
)

logger = logging.getLogger(__name__)


class Pipeline:
    def __init__(
        self,
        sources: list[ThreatSource],
        judges: list[Judge],
        *,
        timeout: float,
    ) -> None:
        if not judges:
            raise ValueError("pipeline needs at least one judge")
        self._sources = sources
        self._judges = judges
        self._timeout = timeout

    async def check(self, url: str, client: httpx.AsyncClient) -> CheckResult:
        results = await asyncio.gather(
            *(self._run_source(source, url, client) for source in self._sources)
        )
        judgment = await self._judge(url, list(results))
        return CheckResult(url=url, sources=list(results), judgment=judgment)

    async def _run_source(
        self,
        source: ThreatSource,
        url: str,
        client: httpx.AsyncClient,
    ) -> SourceResult:
        if not source.is_configured():
            return skipped_result(source.name, source.display_name)
        try:
            return await asyncio.wait_for(source.lookup(url, client), timeout=self._timeout)
        except TimeoutError:
            logger.warning("%s lookup timed out", source.name)
            return timeout_result(source.name, source.display_name)
        except httpx.TimeoutException:
            logger.warning("%s lookup timed out", source.name)
            return timeout_result(source.name, source.display_name)
        except SourceFailure as exc:
            # reason is status code / query_status only. Never the key or the URL.
            logger.warning("%s lookup failed (%s)", source.name, exc.reason)
            return error_result(source.name, source.display_name, exc.reason)
        except Exception as exc:
            # Other exception text can include a request URL, and Safe Browsing
            # puts its key in that URL. Log the type only.
            logger.warning("%s lookup failed (%s)", source.name, type(exc).__name__)
            return error_result(source.name, source.display_name)

    async def _judge(self, url: str, results: list[SourceResult]) -> Judgment:
        malicious = any(item.status == "malicious" for item in results)
        for judge in self._judges:
            try:
                judgment = await judge.judge(url, results)
            except Exception as exc:
                logger.warning("judge %s failed (%s)", judge.name, type(exc).__name__)
                continue
            if judgment.verdict == "GO" and malicious:
                # A positive hit should not be waved through, even if the model says so.
                logger.warning("judge %s returned GO despite a malicious hit", judge.name)
                continue
            return judgment
        raise RuntimeError("no judge returned a verdict")
