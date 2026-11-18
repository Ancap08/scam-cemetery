"""Confirm an email address parses, and name the domain it uses."""

import httpx

from scam_cemetery.models import SourceResult
from scam_cemetery.subjects import parse_email


class EmailSyntaxSource:
    name = "email_syntax"
    display_name = "Email"

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
                summary="Email: address syntax is not valid",
            )
        _local, domain = parsed
        return SourceResult(
            source=self.name,
            display_name=self.display_name,
            status="clean",
            summary=f"Email: valid syntax, domain {domain}",
            detail={"domain": domain},
        )
