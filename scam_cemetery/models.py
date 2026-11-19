"""Shared data the sources, the judge, and the database all pass around."""

from dataclasses import dataclass, field
from typing import Any, Literal

Verdict = Literal["GO", "CAUTION", "NO-GO"]
SourceStatus = Literal[
    "clean",
    "malicious",
    "suspicious",
    "unknown",
    "error",
    "timeout",
    "skipped",
]

VERDICTS: tuple[Verdict, ...] = ("GO", "CAUTION", "NO-GO")


@dataclass(frozen=True)
class SourceResult:
    """What one source said about a link, an email address, or a phone number."""

    source: str
    display_name: str
    status: SourceStatus
    summary: str
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "display_name": self.display_name,
            "status": self.status,
            "summary": self.summary,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class Judgment:
    """A verdict plus the one sentence a person should read."""

    verdict: Verdict
    reason: str
    judge: str


@dataclass(frozen=True)
class CheckResult:
    """One finished check.

    ``url`` is what the reply shows. For an email or a phone number that is the
    redacted form, never the raw value. ``subject_hash`` is the SHA-256 of the
    canonical form (the link, the lowercased email, or E.164). ``scan_url`` is
    the domain URL a VirusTotal follow-up should submit. It is not stored.
    """

    url: str
    sources: list[SourceResult]
    judgment: Judgment
    subject_type: str = "url"
    subject_hash: str = ""
    subject_display: str = ""
    scan_url: str = ""
