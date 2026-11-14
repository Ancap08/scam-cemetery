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
from scam_cemetery.sources.virustotal import VirusTotalSource

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

    def virustotal(self) -> VirusTotalSource | None:
        for source in self._sources:
            if isinstance(source, VirusTotalSource) and source.is_configured():
                return source
        return None

    async def judge(self, url: str, results: list[SourceResult]) -> Judgment:
        return await self._judge(url, results)

    async def check(self, url: str, client: httpx.AsyncClient) -> CheckResult:
        results = await asyncio.gather(
            *(self._run_source(source, url, client) for source in self._sources)
        )
        judgment = await self.judge(url, list(results))
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
        rules = next((judge for judge in self._judges if judge.name == "rules"), None)
        rules_judgment = await rules.judge(url, results) if rules is not None else None
        for judge in self._judges:
            if judge.name == "rules":
                if rules_judgment is None:
                    raise RuntimeError("no judge returned a verdict")
                return rules_judgment
            try:
                judgment = await judge.judge(url, results)
            except Exception as exc:
                logger.warning("judge %s failed (%s)", judge.name, type(exc).__name__)
                continue
            if rules_judgment is not None and judgment.verdict != rules_judgment.verdict:
                # The documented table wins. Grok still writes the sentence when it agrees.
                logger.warning(
                    "judge %s returned %s; using rules verdict %s",
                    judge.name,
                    judgment.verdict,
                    rules_judgment.verdict,
                )
                return rules_judgment
            return judgment
        if rules_judgment is not None:
            return rules_judgment
        raise RuntimeError("no judge returned a verdict")
