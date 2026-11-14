"""Deterministic verdict used when no model judge can answer.

- any source flags malicious -> NO-GO
- unknown, suspicious, timeout, or error -> CAUTION
- every source that actually ran is clean -> GO
- every source was skipped -> CAUTION
"""

from scam_cemetery.models import Judgment, SourceResult

_PROBLEM = frozenset({"suspicious", "unknown", "error", "timeout"})


class RulesJudge:
    name = "rules"

    async def judge(self, url: str, results: list[SourceResult]) -> Judgment:
        del url  # The rules read statuses, not the URL string.
        malicious = [item for item in results if item.status == "malicious"]
        if malicious:
            names = _join([item.display_name for item in malicious])
            return Judgment(
                verdict="NO-GO",
                reason=f"{names} flagged this URL.",
                judge=self.name,
            )

        ran = [item for item in results if item.status != "skipped"]
        if not ran:
            return Judgment(
                verdict="CAUTION",
                reason="No threat-intel sources are configured, so this URL was not checked.",
                judge=self.name,
            )

        problems = [item for item in ran if item.status in _PROBLEM]
        if problems:
            detail = ", ".join(f"{item.display_name} ({item.status})" for item in problems)
            return Judgment(
                verdict="CAUTION",
                reason=f"Not enough clean data: {detail}.",
                judge=self.name,
            )

        return Judgment(
            verdict="GO",
            reason="Every configured source came back clean.",
            judge=self.name,
        )


def _join(names: list[str]) -> str:
    if len(names) == 1:
        return names[0]
    if len(names) == 2:
        return f"{names[0]} and {names[1]}"
    return ", ".join(names[:-1]) + f", and {names[-1]}"
