"""MX, SPF, and DMARC presence for an email domain.

Missing MX means the domain does not accept mail, which is suspicious.
Missing SPF or DMARC is reported and does not change the verdict on its own:
plenty of real domains still have neither. This is a DNS lookup, not a
mailbox check.
"""

import asyncio
from typing import Protocol

import httpx

from scam_cemetery.models import SourceResult
from scam_cemetery.sources.base import SourceFailure
from scam_cemetery.subjects import parse_email


class DnsLookup(Protocol):
    async def lookup(self, name: str, record_type: str) -> list[str]:
        """Record strings. Empty means no data. Raise if the lookup failed."""


class SystemDnsResolver:
    """The host resolver, via dnspython. Tests pass a fake instead."""

    async def lookup(self, name: str, record_type: str) -> list[str]:
        try:
            return await asyncio.to_thread(_resolve, name, record_type)
        except SourceFailure:
            raise
        except Exception as exc:
            raise SourceFailure("DNS lookup failed") from exc


class MailDnsSource:
    name = "mail_dns"
    display_name = "Mail DNS"

    def __init__(self, resolver: DnsLookup | None = None) -> None:
        self._resolver = resolver or SystemDnsResolver()

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
                summary="Mail DNS: address syntax is not valid",
            )
        domain = parsed[1]
        mx = await self._resolver.lookup(domain, "MX")
        txt = await self._resolver.lookup(domain, "TXT")
        dmarc = await self._resolver.lookup(f"_dmarc.{domain}", "TXT")
        has_mx = _has_usable_mx(mx)
        null_mx = bool(mx) and not has_mx
        has_spf = any(_is_spf(record) for record in txt)
        has_dmarc = any(_is_dmarc(record) for record in dmarc)
        if has_mx:
            mx_note = "MX"
        elif null_mx:
            # RFC 7505: a single ``0 .`` record means the domain does not accept mail.
            mx_note = "null MX"
        else:
            mx_note = "no MX"
        notes = [
            mx_note,
            "SPF" if has_spf else "no SPF",
            "DMARC" if has_dmarc else "no DMARC",
        ]
        summary = f"Mail DNS: {domain} has {', '.join(notes)}"
        detail = {"domain": domain, "mx": has_mx, "spf": has_spf, "dmarc": has_dmarc}
        if not has_mx:
            return SourceResult(
                source=self.name,
                display_name=self.display_name,
                status="suspicious",
                summary=summary,
                detail=detail,
            )
        return SourceResult(
            source=self.name,
            display_name=self.display_name,
            status="clean",
            summary=summary,
            detail=detail,
        )


def _resolve(name: str, record_type: str) -> list[str]:
    import dns.exception
    import dns.resolver

    try:
        answer = dns.resolver.resolve(name, record_type, lifetime=5.0)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except dns.exception.DNSException as exc:
        raise SourceFailure("DNS lookup failed") from exc
    if record_type.upper() == "TXT":
        return [_txt(record) for record in answer]
    return [str(record) for record in answer]


def _txt(record: object) -> str:
    chunks = getattr(record, "strings", None)
    if not chunks:
        return str(record).strip('"')
    parts: list[str] = []
    for chunk in chunks:
        if isinstance(chunk, bytes):
            parts.append(chunk.decode("utf-8", "replace"))
        else:
            parts.append(str(chunk))
    return "".join(parts)


def _has_usable_mx(records: list[str]) -> bool:
    """True when an exchanger is a real host.

    A null MX (``0 .``) is a nonempty answer that means "do not deliver".
    """
    for record in records:
        parts = record.strip().split()
        if not parts:
            continue
        exchange = parts[-1].rstrip(".").lower()
        if exchange:
            return True
    return False


def _is_spf(record: str) -> bool:
    return record.strip().lower().startswith("v=spf1")


def _is_dmarc(record: str) -> bool:
    return record.strip().lower().startswith("v=dmarc1")
