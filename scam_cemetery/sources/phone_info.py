"""Offline phone facts from libphonenumber.

Validity, region, and line type come from prefix data shipped with the
library. That is not a live carrier lookup, and the summary says so. The
carrier table in libphonenumber is not consulted. Premium-rate, shared-cost,
VoIP, and invalid numbers are suspicious, so they are not a GO.
"""

import httpx
import phonenumbers
from phonenumbers import (
    PhoneNumberType,
    geocoder,
    is_valid_number,
    number_type,
    region_code_for_number,
)

from scam_cemetery.models import SourceResult

_LINE_TYPES = {
    PhoneNumberType.FIXED_LINE: "fixed line",
    PhoneNumberType.MOBILE: "mobile",
    PhoneNumberType.FIXED_LINE_OR_MOBILE: "fixed line or mobile",
    PhoneNumberType.TOLL_FREE: "toll-free",
    PhoneNumberType.PREMIUM_RATE: "premium-rate",
    PhoneNumberType.SHARED_COST: "shared-cost",
    PhoneNumberType.VOIP: "VoIP",
    PhoneNumberType.PERSONAL_NUMBER: "personal",
    PhoneNumberType.PAGER: "pager",
    PhoneNumberType.UAN: "UAN",
    PhoneNumberType.VOICEMAIL: "voicemail",
    PhoneNumberType.UNKNOWN: "unknown",
}

_FLAGGED = {
    "premium-rate": "Premium-rate calls cost extra and show up often in phone scams.",
    "shared-cost": "Shared-cost calls cost extra.",
    "VoIP": "VoIP numbers are cheap to create.",
}

_OFFLINE = "Line type is offline prefix data, not a live carrier lookup."


class PhoneNumberSource:
    name = "phone_number"
    display_name = "Phone"

    def __init__(self, *, region: str = "US") -> None:
        self._region = region.upper()

    def is_configured(self) -> bool:
        return True

    async def lookup(self, target: str, client: httpx.AsyncClient) -> SourceResult:
        del client
        return inspect_phone(target, region=self._region)


def inspect_phone(raw: str, *, region: str = "US") -> SourceResult:
    try:
        number = phonenumbers.parse(raw, region.upper())
    except phonenumbers.NumberParseException:
        return _invalid()
    if not is_valid_number(number):
        return _invalid()
    line = _LINE_TYPES.get(number_type(number), "unknown")
    region_code = region_code_for_number(number) or "unknown"
    country = geocoder.country_name_for_number(number, "en") or ""
    place = f"{region_code} ({country})" if country else region_code
    detail = {"region": region_code, "line_type": line, "offline": True}
    note = _FLAGGED.get(line)
    if note:
        return SourceResult(
            source=PhoneNumberSource.name,
            display_name=PhoneNumberSource.display_name,
            status="suspicious",
            summary=f"Phone: {line} number in {place}. {note} {_OFFLINE}",
            detail=detail,
        )
    return SourceResult(
        source=PhoneNumberSource.name,
        display_name=PhoneNumberSource.display_name,
        status="clean",
        summary=f"Phone: valid {line} number in {place}. {_OFFLINE}",
        detail=detail,
    )


def _invalid() -> SourceResult:
    return SourceResult(
        source=PhoneNumberSource.name,
        display_name=PhoneNumberSource.display_name,
        status="suspicious",
        summary=(
            "Phone: invalid number. It failed the offline validity check. "
            "This is not a live carrier lookup."
        ),
        detail={"offline": True},
    )
