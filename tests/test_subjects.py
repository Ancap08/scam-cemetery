"""Finding links, email addresses, and phone numbers in a pasted message."""

import hashlib

import httpx

from scam_cemetery.bot import HELP_MESSAGE, NO_LINK_MESSAGE, handle_text
from scam_cemetery.models import CheckResult, Judgment, SourceResult
from scam_cemetery.storage import CheckStore
from scam_cemetery.subjects import extract_subjects, parse_email, redact_email, redact_phone
from scam_cemetery.url_extract import extract_urls


def test_urls_come_first_then_emails_then_phones():
    text = "call +1 415 555 2671 or ada@example.com and see https://example.com/a"
    subjects = extract_subjects(text)
    assert [item.kind for item in subjects] == ["url", "email", "phone"]
    assert subjects[0].canonical == "https://example.com/a"
    assert subjects[1].canonical == "ada@example.com"
    assert subjects[1].display == "a***@example.com"
    assert subjects[2].canonical == "+14155552671"
    assert subjects[2].display == "+1******2671"


def test_a_link_only_message_matches_the_existing_extractor():
    text = "hey can you check https://phish.example/login?id=1 thanks"
    assert [item.canonical for item in extract_subjects(text)] == extract_urls(text)


def test_email_is_not_a_link_and_is_a_subject():
    subjects = extract_subjects("mail me at Ada@Example.com")
    assert extract_urls("mail me at Ada@Example.com") == []
    assert [item.canonical for item in subjects] == ["ada@example.com"]
    assert subjects[0].display == "a***@example.com"
    assert subjects[0].digest == hashlib.sha256(b"ada@example.com").hexdigest()


def test_defanged_email():
    assert extract_urls("ada[at]example[.]com") == []
    assert [item.canonical for item in extract_subjects("ada[at]example[.]com")] == [
        "ada@example.com"
    ]


def test_a_hyphenated_email_domain_is_not_also_a_link():
    text = "zq7-raw-local-9f3c@long-lived-example.com"
    assert extract_urls(text) == []
    subjects = extract_subjects(text)
    assert [item.kind for item in subjects] == ["email"]
    assert extract_urls("long-lived-example.com") == ["https://long-lived-example.com"]


def test_email_inside_a_url_is_not_a_second_subject():
    text = "https://user:secret@example.com/a"
    subjects = extract_subjects(text)
    assert [item.kind for item in subjects] == ["url"]
    assert subjects[0].canonical == "https://example.com/a"


def test_a_phone_inside_a_url_is_not_a_second_subject():
    text = "https://example.com/1-800-555-0199"
    subjects = extract_subjects(text)
    assert [item.kind for item in subjects] == ["url"]


def test_phone_formats_collapse_to_one_e164_number():
    text = "+1 415 555 2671 and (415) 555-2671"
    subjects = extract_subjects(text)
    assert [item.canonical for item in subjects] == ["+14155552671"]


def test_invalid_phone_is_not_extracted_and_region_changes_national_numbers():
    assert extract_subjects("+1 000 000 0000") == []
    assert extract_subjects("12345") == []
    assert extract_subjects("020 7946 0958", default_region="US") == []
    uk = extract_subjects("020 7946 0958", default_region="GB")
    assert [item.canonical for item in uk] == ["+442079460958"]
    assert extract_subjects("+44 20 7946 0958", default_region="US")[0].canonical == (
        "+442079460958"
    )


def test_redaction_keeps_the_domain_and_the_last_four_digits():
    assert redact_email("john.smith@paypal.com") == "j***@paypal.com"
    assert parse_email("not an email") is None
    assert redact_phone("+14155552671", 1) == "+1******2671"
    assert redact_phone("+442079460958", 44) == "+44******0958"
    assert "4155552671" not in redact_phone("+14155552671", 1)


def test_the_prompt_mentions_email_and_phone():
    assert "email" in NO_LINK_MESSAGE.lower()
    assert "phone" in NO_LINK_MESSAGE.lower()
    assert "email" in HELP_MESSAGE.lower()
    assert "phone" in HELP_MESSAGE.lower()


async def test_three_item_cap_checks_urls_before_emails(tmp_path):
    store = CheckStore(tmp_path / "checks.db")
    sent: list[str] = []
    seen: list[str] = []

    async def send(text: str) -> None:
        sent.append(text)

    class _Record:
        async def check(self, url: str, client: httpx.AsyncClient) -> CheckResult:
            del client
            seen.append(url)
            return CheckResult(
                url=url,
                sources=[
                    SourceResult(
                        source="google_safe_browsing",
                        display_name="Google Safe Browsing",
                        status="clean",
                        summary="Google Safe Browsing: no matches",
                    )
                ],
                judgment=Judgment(verdict="GO", reason="Clean.", judge="rules"),
            )

    emails = " ".join(f"user{i}@example.com" for i in range(4))
    async with httpx.AsyncClient() as client:
        await handle_text(
            user_id=42,
            text=f"https://one.example/ https://two.example/ {emails}",
            allowed=frozenset({42}),
            pipeline=_Record(),  # type: ignore[arg-type]
            store=store,
            client=client,
            send=send,
        )
    assert sent[0] == "checking 3 items..."
    assert seen == [
        "https://one.example/",
        "https://two.example/",
        "user0@example.com",
    ]
    assert "I only checked the first 3." in sent[1]
    store.close()
