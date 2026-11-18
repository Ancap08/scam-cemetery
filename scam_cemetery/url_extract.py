"""Pull http(s) URLs out of a chat message, including common defangs.

Security write-ups often paste links as ``hxxp://evil[.]example`` so a reader
does not click them. This module turns those back into real URLs before the
checkers run. It only returns http and https links.
"""

import re
from urllib.parse import urlsplit, urlunsplit

# Bracket-style defangs used in mailing lists and tweet-sized write-ups.
_DOT_DEFANG = re.compile(
    r"\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\[\s*dot\s*\]|\(\s*dot\s*\)",
    re.I,
)
_COLON_DEFANG = re.compile(r"\[\s*:\s*\]")
_HXXPS = re.compile(r"hxxps", re.I)
_HXXP = re.compile(r"hxxp", re.I)
_AT_DEFANG = re.compile(r"\[\s*at\s*\]|\(\s*at\s*\)|\{\s*at\s*\}", re.I)

# A schemed URL runs until whitespace or a wrapper that usually ends a sentence.
_SCHEME_URL = re.compile(
    r"""(?ix)
    (?<![\w/])
    (?P<url>https?://[^\s<>"'`]+)
    """
)

# A bare host: example.com or example.com/path. The lookbehind skips emails
# and the middle of a hyphenated name, so user@long-lived-example.com is not
# also the link lived-example.com.
_BARE_URL = re.compile(
    r"""(?ix)
    (?<!@)
    (?<![\w:/-])
    (?P<host>(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,})
    (?P<rest>(?::\d{2,5})?(?:/[^\s<>"'`]*)?(?:\?[^\s<>"'`]*)?)
    """
)

# Bare "notes.txt" is a filename, not a site. Real public suffixes we still
# want (dev, app, io, ...) are not in this set.
_BARE_FILE_SUFFIXES = frozenset(
    {
        "csv",
        "doc",
        "docx",
        "exe",
        "gif",
        "html",
        "jpeg",
        "jpg",
        "json",
        "log",
        "md",
        "pdf",
        "png",
        "py",
        "txt",
        "xml",
        "zip",
    }
)

_TRAILING = ".,;:!?\"'>`"
_MAX_URL_LENGTH = 2000


def extract_urls(text: str) -> list[str]:
    """Return unique http(s) URLs in the order they appear.

    A missing scheme becomes ``https://``. Fragments are dropped. The same
    URL pasted twice is returned once.
    """
    if not text or not text.strip():
        return []

    refanged = refang(text)
    found: list[tuple[int, str]] = []
    occupied: list[tuple[int, int]] = []

    for match in _SCHEME_URL.finditer(refanged):
        url = _normalize(match.group("url"), had_scheme=True)
        if url is None:
            continue
        found.append((match.start(), url))
        occupied.append((match.start(), match.end()))

    for match in _BARE_URL.finditer(refanged):
        if _overlaps(match.start(), match.end(), occupied):
            continue
        raw = match.group("host") + match.group("rest")
        if _bare_looks_like_filename(match.group("host"), match.group("rest")):
            continue
        url = _normalize(raw, had_scheme=False)
        if url is None:
            continue
        found.append((match.start(), url))

    found.sort(key=lambda item: item[0])
    unique: list[str] = []
    seen: set[str] = set()
    for _, url in found:
        if url in seen:
            continue
        seen.add(url)
        unique.append(url)
    return unique


def refang(text: str) -> str:
    """Undo the defangs this bot knows about. Other text is left as-is."""
    text = _DOT_DEFANG.sub(".", text)
    text = _COLON_DEFANG.sub(":", text)
    text = _AT_DEFANG.sub("@", text)
    text = _HXXPS.sub("https", text)
    text = _HXXP.sub("http", text)
    return text


def _normalize(raw: str, *, had_scheme: bool) -> str | None:
    """Return a canonical http(s) URL, or None if this candidate is not one.

    ``urlsplit`` and ``.port`` raise ``ValueError`` for a bad port or an
    unmatched bracket. One bad paste must not abort the rest of the message.
    """
    try:
        return _normalize_or_raise(raw, had_scheme=had_scheme)
    except ValueError:
        return None


def _normalize_or_raise(raw: str, *, had_scheme: bool) -> str | None:
    candidate = _strip_trailing(raw.strip())
    if not candidate or len(candidate) > _MAX_URL_LENGTH:
        return None
    if not had_scheme:
        candidate = "https://" + candidate
    parts = urlsplit(candidate)
    if parts.scheme not in {"http", "https"}:
        return None
    host = parts.hostname
    if not host or "." not in host:
        return None
    if any(label == "" or len(label) > 63 for label in host.split(".")):
        return None
    netloc = host.lower()
    if parts.port:
        netloc = f"{netloc}:{parts.port}"
    path = parts.path or ""
    return urlunsplit((parts.scheme.lower(), netloc, path, parts.query, ""))


def _strip_trailing(value: str) -> str:
    """Drop sentence punctuation that stuck to the end of a pasted URL.

    A closing paren is only removed when it has no match inside the URL, so
    ``wiki/Foo_(bar)`` stays intact while ``(https://example.com).`` does not.
    """
    while value:
        if value[-1] in _TRAILING:
            value = value[:-1]
            continue
        if value.endswith(")") and value.count("(") < value.count(")"):
            value = value[:-1]
            continue
        if value.endswith("]") and value.count("[") < value.count("]"):
            value = value[:-1]
            continue
        break
    return value


def _bare_looks_like_filename(host: str, rest: str) -> bool:
    if rest:
        return False
    suffix = host.rsplit(".", 1)[-1].lower()
    return suffix in _BARE_FILE_SUFFIXES


def find_url_spans(refanged: str) -> tuple[list[tuple[int, int]], list[tuple[int, int]]]:
    """Return ``(scheme spans, bare spans)`` in already-refanged text.

    Bare spans include the host of an email address (``ada@example.com``).
    Callers that want to keep the email should not treat that overlap as a URL.
    """
    scheme = [match.span() for match in _SCHEME_URL.finditer(refanged)]
    bare: list[tuple[int, int]] = []
    for match in _BARE_URL.finditer(refanged):
        if _overlaps(match.start(), match.end(), scheme):
            continue
        if _bare_looks_like_filename(match.group("host"), match.group("rest")):
            continue
        bare.append(match.span())
    return scheme, bare


def _overlaps(start: int, end: int, spans: list[tuple[int, int]]) -> bool:
    return any(start < span_end and end > span_start for span_start, span_end in spans)
