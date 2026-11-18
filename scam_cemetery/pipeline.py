"""Run every configured source at once, then ask a judge for the verdict.

Each lookup gets the same timeout, and they run together. A slow or failed
source becomes a result and does not cancel the others. Judges are tried in
list order. The last one should be RulesJudge, which always answers.

``Checker`` picks the link, email, or phone pipeline. Email and phone results
store the redacted display form. The raw value is scrubbed out of summaries
before the judge sees them.
"""

import asyncio
import hashlib
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
from scam_cemetery.subjects import Subject, scrub_text, scrub_value

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

    async def judge(
        self,
        url: str,
        results: list[SourceResult],
        *,
        subject_type: str = "url",
    ) -> Judgment:
        return await self._judge(url, results, subject_type=subject_type)

    async def check(
        self,
        url: str,
        client: httpx.AsyncClient,
        *,
        subject_type: str = "url",
        display: str | None = None,
        subject_hash: str = "",
        scan_url: str = "",
    ) -> CheckResult:
        shown = url if display is None else display
        if subject_type != "url" and display is None:
            raise ValueError("email and phone checks need a redacted display")
        results = list(
            await asyncio.gather(
                *(self._run_source(source, url, client) for source in self._sources)
            )
        )
        if subject_type != "url":
            results = [_scrub_source(item, url, shown) for item in results]
        judgment = await self.judge(shown, results, subject_type=subject_type)
        if subject_type != "url":
            judgment = Judgment(
                verdict=judgment.verdict,
                reason=scrub_text(judgment.reason, url, shown),
                judge=judgment.judge,
            )
        digest = subject_hash or hashlib.sha256(url.encode("utf-8")).hexdigest()
        return CheckResult(
            url=shown,
            sources=results,
            judgment=judgment,
            subject_type=subject_type,
            subject_hash=digest,
            subject_display=shown,
            scan_url=scan_url,
        )

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

    async def _judge(
        self,
        url: str,
        results: list[SourceResult],
        *,
        subject_type: str = "url",
    ) -> Judgment:
        rules = next((judge for judge in self._judges if judge.name == "rules"), None)
        rules_judgment = (
            await rules.judge(url, results, subject_type=subject_type)
            if rules is not None
            else None
        )
        for judge in self._judges:
            if judge.name == "rules":
                if rules_judgment is None:
                    raise RuntimeError("no judge returned a verdict")
                return rules_judgment
            try:
                judgment = await judge.judge(url, results, subject_type=subject_type)
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


class Checker:
    """Send a link, an email address, or a phone number to the right pipeline.

    The three pipelines share one VirusTotal source, so link checks and email
    checks spend the same 4-per-minute budget.
    """

    def __init__(
        self,
        url: Pipeline,
        email: Pipeline,
        phone: Pipeline,
        *,
        virustotal: VirusTotalSource | None,
    ) -> None:
        self._url = url
        self._email = email
        self._phone = phone
        self._virustotal = virustotal

    def virustotal(self) -> VirusTotalSource | None:
        if self._virustotal is not None and self._virustotal.is_configured():
            return self._virustotal
        return None

    async def check(self, url: str, client: httpx.AsyncClient) -> CheckResult:
        return await self._url.check(url, client)

    async def judge(
        self,
        url: str,
        results: list[SourceResult],
        *,
        subject_type: str = "url",
    ) -> Judgment:
        pipeline = {"email": self._email, "phone": self._phone}.get(subject_type, self._url)
        return await pipeline.judge(url, results, subject_type=subject_type)

    async def check_subject(self, subject: Subject, client: httpx.AsyncClient) -> CheckResult:
        if subject.kind == "url":
            return await self._url.check(subject.canonical, client)
        pipeline = self._email if subject.kind == "email" else self._phone
        scan_url = ""
        if subject.kind == "email" and subject.domain:
            scan_url = f"https://{subject.domain}/"
        return await pipeline.check(
            subject.canonical,
            client,
            subject_type=subject.kind,
            display=subject.display,
            subject_hash=subject.digest,
            scan_url=scan_url,
        )


def _scrub_source(result: SourceResult, secret: str, replacement: str) -> SourceResult:
    return SourceResult(
        source=result.source,
        display_name=result.display_name,
        status=result.status,
        summary=scrub_text(result.summary, secret, replacement),
        detail=scrub_value(result.detail, secret, replacement),
    )
