"""Run an existing URL source against an email address's domain.

Safe Browsing, VirusTotal, and URLhaus stay URL sources. For an email they
see ``https://<domain>/``, not the mailbox. VirusTotal's 4-per-minute budget
is the one on the shared source object, so a link check and an email check
spend the same pool.
"""

import httpx

from scam_cemetery.models import SourceResult
from scam_cemetery.sources.base import SourceFailure, ThreatSource
from scam_cemetery.subjects import parse_email


class DomainThreatAdapter:
    def __init__(self, inner: ThreatSource) -> None:
        self._inner = inner
        self.name = inner.name
        self.display_name = inner.display_name

    def is_configured(self) -> bool:
        return self._inner.is_configured()

    async def lookup(self, target: str, client: httpx.AsyncClient) -> SourceResult:
        parsed = parse_email(target)
        if parsed is None:
            raise SourceFailure("not an email address")
        domain = parsed[1]
        return await self._inner.lookup(f"https://{domain}/", client)
