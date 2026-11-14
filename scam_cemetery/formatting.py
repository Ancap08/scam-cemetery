"""Turn a finished check into the Telegram follow-up."""

from scam_cemetery.models import CheckResult

# Telegram rejects a text message longer than this.
TELEGRAM_TEXT_LIMIT = 4096

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


def split_for_telegram(text: str, limit: int = TELEGRAM_TEXT_LIMIT) -> list[str]:
    """Break a reply into pieces Telegram will accept.

    Prefer a blank line, then any newline, then a hard cut. Nothing is dropped.
    """
    if limit < 1:
        raise ValueError("limit must be positive")
    if len(text) <= limit:
        return [text] if text else []

    chunks: list[str] = []
    remaining = text
    while remaining:
        if len(remaining) <= limit:
            chunks.append(remaining)
            break
        window = remaining[:limit]
        cut = window.rfind("\n\n")
        if cut < 1:
            cut = window.rfind("\n")
        if cut < 1:
            cut = limit
        chunk = remaining[:cut].rstrip("\n")
        remaining = remaining[cut:].lstrip("\n")
        if chunk:
            chunks.append(chunk)
    return chunks
