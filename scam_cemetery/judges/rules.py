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

    async def judge(
        self,
        url: str,
        results: list[SourceResult],
        *,
        subject_type: str = "url",
    ) -> Judgment:
        del url  # The rules read statuses, not the address string.
        noun = _noun(subject_type)
        malicious = [item for item in results if item.status == "malicious"]
        if malicious:
            names = _join([item.display_name for item in malicious])
            return Judgment(
                verdict="NO-GO",
                reason=f"{names} flagged this {noun}.",
                judge=self.name,
            )

        suspicious = [item for item in results if item.status == "suspicious"]
        clean = [item for item in results if item.status == "clean"]
        if suspicious:
            names = _join([item.display_name for item in suspicious])
            return Judgment(
                verdict="CAUTION",
                reason=_suspicious_reason(names, noun, subject_type),
                judge=self.name,
            )
        if clean:
            return Judgment(
                verdict="GO",
                reason=_clean_reason(noun, subject_type),
                judge=self.name,
            )

        configured = [item for item in results if item.status != "skipped"]
        if not configured:
            return Judgment(
                verdict="CAUTION",
                reason=f"No threat-intel sources are configured, so this {noun} was not checked.",
                judge=self.name,
            )
        detail = ", ".join(f"{item.display_name} ({item.status})" for item in configured)
        return Judgment(
            verdict="CAUTION",
            reason=_empty_reason(detail, noun, subject_type),
            judge=self.name,
        )


def _noun(subject_type: str) -> str:
    if subject_type == "email":
        return "email"
    if subject_type == "phone":
        return "phone number"
    return "URL"


def _suspicious_reason(names: str, noun: str, subject_type: str) -> str:
    if subject_type == "url":
        return f"{names} found something suspicious, which is not a clear hit."
    return f"{names} found something suspicious about this {noun}, which is not a clear hit."


def _clean_reason(noun: str, subject_type: str) -> str:
    if subject_type == "url":
        return "A source came back clean, and none reported a threat."
    return f"A source came back clean for this {noun}, and none reported a threat."


def _empty_reason(detail: str, noun: str, subject_type: str) -> str:
    if subject_type == "url":
        return f"No source came back clean: {detail}."
    return f"No source came back clean for this {noun}: {detail}."


def _join(names: list[str]) -> str:
    if len(names) == 1:
        return names[0]
    if len(names) == 2:
        return f"{names[0]} and {names[1]}"
    return ", ".join(names[:-1]) + f", and {names[-1]}"
