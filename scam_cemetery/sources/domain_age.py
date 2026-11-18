"""Domain age from RDAP, using the IANA bootstrap file. No API key.

A domain registered less than 30 days ago is suspicious. A missing date is
"unknown": under the verdict table that does not, by itself, turn a clean
result into CAUTION.
"""

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import httpx

from scam_cemetery.models import SourceResult, SourceStatus
from scam_cemetery.sources.base import SourceFailure
from scam_cemetery.subjects import parse_email

IANA_DNS_BOOTSTRAP = "https://data.iana.org/rdap/dns.json"
NEW_DOMAIN_DAYS = 30
_REGISTRATION = frozenset({"registration", "registered"})

# Same small set the lookalike check uses. This is not the public suffix list.
# It only stops the parent walk from asking RDAP for ``co.uk`` itself.
_MULTI_PART_SUFFIXES = frozenset(
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


class DomainAgeSource:
    name = "domain_age"
    display_name = "Domain age"

    def __init__(self, *, now: Callable[[], datetime] | None = None) -> None:
        self._now = now or (lambda: datetime.now(UTC))
        self._bootstrap: dict[str, str] | None = None

    def is_configured(self) -> bool:
        return True

    async def lookup(self, target: str, client: httpx.AsyncClient) -> SourceResult:
        parsed = parse_email(target)
        if parsed is None:
            return _result("suspicious", "Domain age: address syntax is not valid")
        domain = parsed[1]
        tld = domain.rsplit(".", 1)[-1]
        servers = await self._servers(client)
        base = servers.get(tld)
        if not base:
            return _result("unknown", f"Domain age: no RDAP server for .{tld}", domain=domain)
        # A mail host such as mail.new-domain.com is not the registered name.
        # Ask for that name, then its parents, and stop before the public suffix.
        found_name: str | None = None
        registered: datetime | None = None
        for name in _rdap_names(domain):
            response = await client.get(
                f"{base}domain/{name}",
                headers={"Accept": "application/rdap+json"},
                follow_redirects=True,
            )
            if response.status_code == 404:
                continue
            if response.status_code >= 400:
                raise SourceFailure(f"HTTP {response.status_code}")
            registered = _registration_date(_json_object(response))
            found_name = name
            break
        if found_name is None:
            return _result("unknown", f"Domain age: {domain} was not found in RDAP", domain=domain)
        if registered is None:
            return _result(
                "unknown",
                f"Domain age: RDAP had no registration date for {found_name}",
                domain=domain,
            )
        moment = self._now()
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=UTC)
        days = max((moment.astimezone(UTC) - registered).days, 0)
        when = registered.date().isoformat()
        detail = {
            "domain": domain,
            "registered_domain": found_name,
            "registered": when,
            "age_days": days,
        }
        named = found_name if found_name == domain else f"{found_name} (parent of {domain})"
        if days < NEW_DOMAIN_DAYS:
            return _result(
                "suspicious",
                (
                    f"Domain age: {named} was registered {when} ({days} days ago). "
                    f"Under {NEW_DOMAIN_DAYS} days is suspicious."
                ),
                detail=detail,
            )
        return _result(
            "clean",
            f"Domain age: {named} was registered {when} ({days} days ago).",
            detail=detail,
        )

    async def _servers(self, client: httpx.AsyncClient) -> dict[str, str]:
        if self._bootstrap is not None:
            return self._bootstrap
        response = await client.get(IANA_DNS_BOOTSTRAP, follow_redirects=True)
        if response.status_code >= 400:
            raise SourceFailure(f"HTTP {response.status_code}")
        self._bootstrap = _bootstrap_map(_json_object(response))
        return self._bootstrap


def _result(
    status: SourceStatus,
    summary: str,
    *,
    domain: str | None = None,
    detail: dict[str, Any] | None = None,
) -> SourceResult:
    payload = detail if detail is not None else ({"domain": domain} if domain else {})
    return SourceResult(
        source=DomainAgeSource.name,
        display_name=DomainAgeSource.display_name,
        status=status,
        summary=summary,
        detail=payload,
    )


def _rdap_names(domain: str) -> list[str]:
    """The domain, then each parent, stopping before a public suffix.

    ``mail.new-domain.com`` is asked as itself and then as ``new-domain.com``.
    ``example.co.uk`` is not followed by a query for ``co.uk``.
    """
    labels = [part for part in domain.lower().strip(".").split(".") if part]
    names: list[str] = []
    for start in range(len(labels)):
        rest = labels[start:]
        if len(rest) < 2:
            break
        candidate = ".".join(rest)
        if candidate in _MULTI_PART_SUFFIXES:
            break
        names.append(candidate)
    return names


def _json_object(response: httpx.Response) -> dict[str, Any]:
    try:
        payload = response.json()
    except ValueError:
        return {}
    return payload if isinstance(payload, dict) else {}


def _bootstrap_map(payload: dict[str, Any]) -> dict[str, str]:
    mapping: dict[str, str] = {}
    services = payload.get("services")
    if not isinstance(services, list):
        return mapping
    for entry in services:
        if not isinstance(entry, list) or len(entry) < 2:
            continue
        tlds, urls = entry[0], entry[1]
        if not isinstance(tlds, list) or not isinstance(urls, list):
            continue
        base = _https_base(urls)
        if base is None:
            continue
        for tld in tlds:
            if isinstance(tld, str) and tld:
                mapping[tld.lower()] = base
    return mapping


def _https_base(urls: list[Any]) -> str | None:
    strings = [item for item in urls if isinstance(item, str) and item]
    chosen = next((item for item in strings if item.startswith("https://")), None)
    if chosen is None and strings:
        chosen = strings[0]
    if chosen is None:
        return None
    return chosen if chosen.endswith("/") else chosen + "/"


def _registration_date(payload: dict[str, Any]) -> datetime | None:
    events = payload.get("events")
    if not isinstance(events, list):
        return None
    for event in events:
        if not isinstance(event, dict):
            continue
        action = str(event.get("eventAction") or "").lower()
        if action not in _REGISTRATION:
            continue
        parsed = _parse_time(event.get("eventDate"))
        if parsed is not None:
            return parsed
    return None


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)
