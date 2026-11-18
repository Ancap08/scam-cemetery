"""Deterministic verdict used when no model judge can answer.

- any source flags malicious -> NO-GO
- any source is suspicious, and nothing is malicious -> CAUTION
- at least one source is clean, and none are malicious or suspicious -> GO
- nothing came back clean -> CAUTION

An unscanned, timed-out, or failed source does not downgrade a result that
already has a clean source. Suspicion is the ambiguity that still means CAUTION.
"""

from scam_cemetery.models import Judgment, SourceResult


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

        suspicious = [item for item in results if item.status == "suspicious"]
        clean = [item for item in results if item.status == "clean"]
        if suspicious:
            names = _join([item.display_name for item in suspicious])
            return Judgment(
                verdict="CAUTION",
                reason=f"{names} found something suspicious, which is not a clear hit.",
                judge=self.name,
            )
        if clean:
            return Judgment(
                verdict="GO",
                reason="A source came back clean, and none reported a threat.",
                judge=self.name,
            )

        configured = [item for item in results if item.status != "skipped"]
        if not configured:
            return Judgment(
                verdict="CAUTION",
                reason="No threat-intel sources are configured, so this URL was not checked.",
                judge=self.name,
            )
        detail = ", ".join(f"{item.display_name} ({item.status})" for item in configured)
        return Judgment(
            verdict="CAUTION",
            reason=f"No source came back clean: {detail}.",
            judge=self.name,
        )


def _join(names: list[str]) -> str:
    if len(names) == 1:
        return names[0]
    if len(names) == 2:
        return f"{names[0]} and {names[1]}"
    return ", ".join(names[:-1]) + f", and {names[-1]}"
