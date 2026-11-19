"""Judge interface.

v0.1 ships two implementations: Grok (xAI) and a deterministic rules fallback.
An open-source model, then OpenAI, can be added later as further backups by
implementing ``judge`` and inserting the class into the pipeline's judge list
ahead of ``RulesJudge``. Provider-specific HTTP stays inside the implementation.
"""

from typing import Protocol

from scam_cemetery.models import Judgment, SourceResult


class JudgeUnavailable(Exception):
    """This judge cannot answer. The pipeline should try the next one."""


class Judge(Protocol):
    name: str

    async def judge(
        self,
        url: str,
        results: list[SourceResult],
        *,
        subject_type: str = "url",
    ) -> Judgment:
        """Return a verdict and a plain-English reason, or raise if unavailable.

        ``subject_type`` is ``url``, ``email``, or ``phone``. The reason should
        say "this URL", "this email", or "this phone number".
        """
