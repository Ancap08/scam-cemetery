"""Turn a finished check into the Telegram follow-up."""

from scam_cemetery.models import CheckResult

_JUDGE_LABELS = {
    "grok": "Grok",
    "rules": "Rules",
}


def format_report(result: CheckResult) -> str:
    """Verdict, the URL, one line per source, then the judge's sentence."""
    label = _JUDGE_LABELS.get(result.judgment.judge, result.judgment.judge)
    source_lines = [item.summary.replace("\n", " ") for item in result.sources]
    reason = result.judgment.reason.replace("\n", " ")
    body = "\n".join(source_lines)
    return f"{result.judgment.verdict}\n{result.url}\n\n{body}\n\n{label}: {reason}"
