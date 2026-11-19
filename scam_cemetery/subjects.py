"""Turn a chat message into links, email addresses, and phone numbers.

Links come first, then email addresses, then phone numbers. The raw email or
phone is only held in memory for the lookup. What gets stored and shown is a
hash of the canonical form and a redacted display form.
"""

import hashlib
import re
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import quote

import phonenumbers
from phonenumbers import (
    Leniency,
    PhoneNumberFormat,
    PhoneNumberMatcher,
    is_valid_number,
)

from scam_cemetery.url_extract import extract_urls, find_url_spans, refang

SubjectKind = Literal["url", "email", "phone"]

_EMAIL = re.compile(
    r"""(?ix)
    (?<![A-Za-z0-9._%+\-])
    (?P<local>[A-Za-z0-9](?:[A-Za-z0-9._%+\-]{0,62}[A-Za-z0-9])?)
    @
    (?P<domain>(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63})
    (?![A-Za-z0-9\-])
    """
)
_LOCAL = re.compile(r"[a-z0-9](?:[a-z0-9._%+\-]*[a-z0-9])?")
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?")


@dataclass(frozen=True)
class Subject:
    """One thing to check.

    ``canonical`` is the lookup key: the URL, the lowercased email, or E.164.
    ``display`` is safe to store and to put in a reply. For an email that is
    ``j***@paypal.com``. For a phone it keeps the country code and the last
    four digits.
    """

    kind: SubjectKind
    canonical: str
    display: str
    domain: str = ""

    @property
    def digest(self) -> str:
        """SHA-256 of the canonical form, hex encoded."""
        return digest(self.canonical)


def digest(canonical: str) -> str:
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def extract_subjects(text: str, *, default_region: str = "US") -> list[Subject]:
    """Return unique subjects: every link, then every email, then every phone.

    A link wins when an email or a phone number sits inside it, so a credential
    in a URL is not also treated as an address to check. Phone numbers have to
    pass ``is_valid_number``. National numbers are read in ``default_region``.
    """
    if not text or not text.strip():
        return []

    links = [Subject(kind="url", canonical=url, display=url) for url in extract_urls(text)]
    prepared = refang(text)
    scheme_spans, bare_spans = find_url_spans(prepared)
    emails = _emails(prepared, scheme_spans)
    occupied = [*scheme_spans, *bare_spans, *(item[0] for item in emails)]
    phones = _phones(prepared, default_region, occupied)
    return [*links, *(item[1] for item in emails), *phones]


def parse_email(value: str) -> tuple[str, str] | None:
    """Return ``(local, domain)`` lowercased, or None if it is not a plain address."""
    if value.count("@") != 1:
        return None
    local, domain = value.split("@")
    local = local.strip().lower()
    domain = domain.strip().lower().rstrip(".")
    if not local or not domain or len(local) > 64 or len(domain) > 253:
        return None
    if ".." in local or not _LOCAL.fullmatch(local):
        return None
    labels = domain.split(".")
    if len(labels) < 2 or not _LABEL.fullmatch(labels[-1]) or len(labels[-1]) < 2:
        return None
    if any(not label or len(label) > 63 or not _LABEL.fullmatch(label) for label in labels):
        return None
    return local, domain


def redact_email(canonical: str) -> str:
    local, _, domain = canonical.partition("@")
    head = local[:1] or "*"
    return f"{head}***@{domain}"


def redact_phone(e164: str, country_code: int) -> str:
    """Keep the country code and the last four digits. Mask the rest.

    ``+14155552671`` becomes ``+1******2671``. The star count follows the
    national number, so it is not a fixed width.
    """
    digits = e164[1:] if e164.startswith("+") else e164
    prefix = str(country_code)
    national = digits[len(prefix) :] if digits.startswith(prefix) else digits
    if len(national) <= 4:
        return f"+{prefix}{'*' * max(len(national), 1)}"
    return f"+{prefix}{'*' * (len(national) - 4)}{national[-4:]}"


def scrub_text(text: str, secret: str, replacement: str) -> str:
    """Replace a raw email or phone number with its redacted display form."""
    if not secret or secret == replacement:
        return text
    for variant in _secret_variants(secret):
        text = text.replace(variant, replacement)
    return text


def scrub_value(value: Any, secret: str, replacement: str) -> Any:
    if isinstance(value, str):
        return scrub_text(value, secret, replacement)
    if isinstance(value, dict):
        return {key: scrub_value(item, secret, replacement) for key, item in value.items()}
    if isinstance(value, list):
        return [scrub_value(item, secret, replacement) for item in value]
    return value


def _emails(
    prepared: str, scheme_spans: list[tuple[int, int]]
) -> list[tuple[tuple[int, int], Subject]]:
    found: list[tuple[tuple[int, int], Subject]] = []
    seen: set[str] = set()
    for match in _EMAIL.finditer(prepared):
        span = match.span()
        if _overlaps(span[0], span[1], scheme_spans):
            continue
        parsed = parse_email(match.group(0))
        if parsed is None:
            continue
        local, domain = parsed
        canonical = f"{local}@{domain}"
        if canonical in seen:
            continue
        seen.add(canonical)
        found.append(
            (
                span,
                Subject(
                    kind="email",
                    canonical=canonical,
                    display=redact_email(canonical),
                    domain=domain,
                ),
            )
        )
    return found


def _phones(
    prepared: str,
    region: str,
    occupied: list[tuple[int, int]],
) -> list[Subject]:
    found: list[Subject] = []
    seen: set[str] = set()
    for match in PhoneNumberMatcher(prepared, region.upper(), leniency=Leniency.VALID):
        if _overlaps(match.start, match.end, occupied):
            continue
        number = match.number
        if not is_valid_number(number):
            continue
        canonical = phonenumbers.format_number(number, PhoneNumberFormat.E164)
        if canonical in seen:
            continue
        seen.add(canonical)
        found.append(
            Subject(
                kind="phone",
                canonical=canonical,
                display=redact_phone(canonical, number.country_code),
            )
        )
    return found


def _secret_variants(secret: str) -> list[str]:
    variants = [secret]
    if "@" in secret:
        local = secret.split("@", 1)[0]
        # A long local part is itself identifying. Short ones ("ann") are not
        # worth blanking out of unrelated words.
        if len(local) >= 8:
            variants.append(local)
        variants.append(quote(secret))
    elif secret.startswith("+") and secret[1:].isdigit():
        variants.append(secret[1:])
    return sorted(set(variants), key=len, reverse=True)


def _overlaps(start: int, end: int, spans: list[tuple[int, int]]) -> bool:
    return any(start < span_end and end > span_start for span_start, span_end in spans)
