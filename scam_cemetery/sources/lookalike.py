"""Typosquats of a small set of brands people get phished as.

A hit is malicious, so the verdict is NO-GO. The real brand domain, including
its own subdomains, is clean. Short names (apple, ups, chase) are not
fuzzy-matched: one edit would flag ordinary words. They are still caught by a
homoglyph, a bait word (paypal-secure), or the brand domain embedded in a
longer host (paypal.com.evil.example).
"""

import httpx

from scam_cemetery.models import SourceResult
from scam_cemetery.subjects import parse_email

# (display name, canonical domain). The domain is the one a real mail would use.
WATCHED_BRANDS: tuple[tuple[str, str], ...] = (
    ("PayPal", "paypal.com"),
    ("Apple", "apple.com"),
    ("Apple", "icloud.com"),
    ("Microsoft", "microsoft.com"),
    ("Microsoft", "live.com"),
    ("Microsoft", "outlook.com"),
    ("Microsoft", "office.com"),
    ("Microsoft", "hotmail.com"),
    ("Amazon", "amazon.com"),
    ("Google", "google.com"),
    ("Google", "gmail.com"),
    ("Chase", "chase.com"),
    ("Bank of America", "bankofamerica.com"),
    ("Wells Fargo", "wellsfargo.com"),
    ("Citi", "citibank.com"),
    ("Citi", "citi.com"),
    ("Capital One", "capitalone.com"),
    ("U.S. Bank", "usbank.com"),
    ("American Express", "americanexpress.com"),
    ("UPS", "ups.com"),
    ("FedEx", "fedex.com"),
    ("USPS", "usps.com"),
    ("DHL", "dhl.com"),
)

# Extra tokens that turn brand-secure.example into a phish, not apple-pie.example.
_BAIT = frozenset(
    {
        "account",
        "accounts",
        "alert",
        "alerts",
        "auth",
        "authentication",
        "billing",
        "confirm",
        "customer",
        "delivery",
        "email",
        "express",
        "help",
        "info",
        "invoice",
        "limited",
        "login",
        "logon",
        "mail",
        "notice",
        "official",
        "online",
        "order",
        "package",
        "parcel",
        "payment",
        "payments",
        "refund",
        "secure",
        "security",
        "service",
        "services",
        "ship",
        "shipping",
        "signin",
        "store",
        "support",
        "suspended",
        "team",
        "tracking",
        "unlock",
        "update",
        "verification",
        "verify",
        "wallet",
        "web",
    }
)

_MULTI_SUFFIXES = frozenset(
    {
        "ac.uk",
        "co.in",
        "co.jp",
        "co.nz",
        "co.uk",
        "co.za",
        "com.ar",
        "com.au",
        "com.br",
        "com.co",
        "com.hk",
        "com.mx",
        "com.sg",
        "com.tr",
        "com.tw",
        "gov.uk",
        "net.au",
        "org.au",
        "org.uk",
    }
)

# Digits and letters that show up in homoglyph domains. Folding is one way:
# the original has to change, so the real brand is not flagged.
_FOLD = str.maketrans(
    {
        "0": "o",
        "1": "l",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "а": "a",
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "х": "x",
        "у": "y",
        "і": "i",
        "ѕ": "s",
        "һ": "h",
        "ј": "j",
    }
)

_EDIT_MIN_LENGTH = 6
_OTHER_TLD_MIN_LENGTH = 5


class BrandLookalikeSource:
    name = "brand_lookalike"
    display_name = "Brand lookalike"

    def is_configured(self) -> bool:
        return True

    async def lookup(self, target: str, client: httpx.AsyncClient) -> SourceResult:
        del client
        parsed = parse_email(target)
        if parsed is None:
            return SourceResult(
                source=self.name,
                display_name=self.display_name,
                status="suspicious",
                summary="Brand lookalike: address syntax is not valid",
            )
        return assess_domain(parsed[1])


def assess_domain(domain: str) -> SourceResult:
    host = domain.lower().strip(".")
    real = _real_brand(host)
    if real is not None:
        name, brand_domain = real
        summary = f"Brand lookalike: {host} is {name}, not a lookalike."
        return _clean(host, summary, name, brand_domain)
    hit = _lookalike(host)
    if hit is None:
        return SourceResult(
            source=BrandLookalikeSource.name,
            display_name=BrandLookalikeSource.display_name,
            status="clean",
            summary=f"Brand lookalike: {host} does not resemble a watched brand",
            detail={"domain": host},
        )
    name, brand_domain, how = hit
    return SourceResult(
        source=BrandLookalikeSource.name,
        display_name=BrandLookalikeSource.display_name,
        status="malicious",
        summary=f"Brand lookalike: {host} resembles {name} ({brand_domain}) by {how}",
        detail={"domain": host, "brand": name, "brand_domain": brand_domain, "how": how},
    )


def _clean(host: str, summary: str, name: str, brand_domain: str) -> SourceResult:
    return SourceResult(
        source=BrandLookalikeSource.name,
        display_name=BrandLookalikeSource.display_name,
        status="clean",
        summary=summary,
        detail={"domain": host, "brand": name, "brand_domain": brand_domain},
    )


def _lookalike(host: str) -> tuple[str, str, str] | None:
    labels = tuple(label for label in host.split(".") if label)
    folded_labels = tuple(label.translate(_FOLD) for label in labels)
    folded_host = ".".join(folded_labels)
    if folded_host != host:
        folded_real = _real_brand(folded_host)
        if folded_real is not None:
            name, brand_domain = folded_real
            return name, brand_domain, "homoglyph"
    embedded = _embedded(labels) or (_embedded(folded_labels) if folded_labels != labels else None)
    if embedded is not None:
        name, brand_domain = embedded
        return name, brand_domain, "embedded domain"
    sld, suffix = _registrable(labels)
    hyphen = _hyphen_bait(sld)
    if hyphen is not None:
        name, brand_domain = hyphen
        return name, brand_domain, "added words"
    folded_sld = sld.translate(_FOLD)
    if folded_sld != sld:
        for name, brand_domain, brand_sld in _brands():
            if folded_sld == brand_sld:
                return name, brand_domain, "homoglyph"
    if len(sld) >= _OTHER_TLD_MIN_LENGTH:
        for name, brand_domain, brand_sld in _brands():
            brand_suffix = brand_domain.split(".", 1)[1]
            if sld == brand_sld and suffix != brand_suffix:
                return name, brand_domain, "different top-level domain"
    if "-" not in sld and len(sld) >= _EDIT_MIN_LENGTH:
        for name, brand_domain, brand_sld in _brands():
            if len(brand_sld) < _EDIT_MIN_LENGTH or sld[0] != brand_sld[0] or sld == brand_sld:
                continue
            if not len(brand_sld) <= len(sld) <= len(brand_sld) + 1:
                continue
            if _edit_distance(sld, brand_sld) <= 1:
                return name, brand_domain, "one-character typo"
    return None


def _brands() -> list[tuple[str, str, str]]:
    return [(name, domain, domain.split(".", 1)[0]) for name, domain in WATCHED_BRANDS]


def _real_brand(host: str) -> tuple[str, str] | None:
    for name, domain in WATCHED_BRANDS:
        if host == domain or host.endswith("." + domain):
            return name, domain
    return None


def _embedded(labels: tuple[str, ...]) -> tuple[str, str] | None:
    for name, domain in WATCHED_BRANDS:
        brand = tuple(domain.split("."))
        width = len(brand)
        # The final `width` labels are the domain itself. That case is "real".
        for index in range(0, len(labels) - width):
            if labels[index : index + width] == brand:
                return name, domain
    return None


def _registrable(labels: tuple[str, ...]) -> tuple[str, str]:
    if len(labels) < 2:
        return ".".join(labels), ""
    suffix2 = ".".join(labels[-2:])
    if suffix2 in _MULTI_SUFFIXES and len(labels) >= 3:
        return labels[-3], suffix2
    return labels[-2], labels[-1]


def _hyphen_bait(sld: str) -> tuple[str, str] | None:
    if "-" not in sld:
        return None
    tokens = [token for token in sld.split("-") if token]
    if len(tokens) < 2:
        return None
    by_sld = {brand_sld: (name, domain) for name, domain, brand_sld in _brands()}
    for token in tokens:
        if token not in by_sld:
            continue
        if any(other in _BAIT for other in tokens if other != token):
            return by_sld[token]
    return None


def _edit_distance(left: str, right: str, limit: int = 1) -> int:
    """Damerau-Levenshtein, or ``limit + 1`` once the distance is past ``limit``."""
    if abs(len(left) - len(right)) > limit:
        return limit + 1
    previous = list(range(len(right) + 1))
    two_back: list[int] | None = None
    for i, left_char in enumerate(left, start=1):
        current = [i]
        for j, right_char in enumerate(right, start=1):
            cost = 0 if left_char == right_char else 1
            best = min(current[j - 1] + 1, previous[j] + 1, previous[j - 1] + cost)
            if (
                two_back is not None
                and i > 1
                and j > 1
                and left_char == right[j - 2]
                and left[i - 2] == right_char
            ):
                best = min(best, two_back[j - 2] + 1)
            current.append(best)
        two_back = previous
        previous = current
        if min(current) > limit:
            return limit + 1
    return previous[-1]
