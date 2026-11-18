"""Only the configured Telegram users, and only in a private chat, get a reply."""

import httpx
import pytest

from scam_cemetery.bot import CHECKING_MESSAGE, NO_LINK_MESSAGE, handle_text, should_respond
from scam_cemetery.config import ConfigError, Settings
from scam_cemetery.formatting import split_for_telegram
from scam_cemetery.models import CheckResult, Judgment, SourceResult
from scam_cemetery.storage import CheckStore

ALLOWED = frozenset({42})


def test_allowlist_matrix():
    assert should_respond(42, "private", ALLOWED) is True
    assert should_respond(7, "private", ALLOWED) is False
    assert should_respond(42, "group", ALLOWED) is False
    assert should_respond(42, "supergroup", ALLOWED) is False
    assert should_respond(None, "private", ALLOWED) is False


def test_settings_repr_does_not_include_secrets():
    settings = Settings.from_env(
        _env(
            XAI_API_KEY="super-secret",
            GOOGLE_SAFE_BROWSING_KEY="gsb-secret",
            NUMVERIFY_API_KEY="nv-secret",
        )
    )
    text = repr(settings)
    assert "super-secret" not in text
    assert "gsb-secret" not in text
    assert "nv-secret" not in text
    assert "123:abc" not in text
    assert "google_safe_browsing" in text
    assert "numverify" in text
    assert "grok" in text
    assert settings.default_phone_region == "US"


def test_main_refuses_to_start_without_a_token(monkeypatch):
    from scam_cemetery.main import main

    for name in (
        "TELEGRAM_BOT_TOKEN",
        "ALLOWED_TELEGRAM_USER_IDS",
        "XAI_API_KEY",
        "GOOGLE_SAFE_BROWSING_KEY",
        "VIRUSTOTAL_API_KEY",
        "URLHAUS_AUTH_KEY",
    ):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(SystemExit) as caught:
        main()
    assert caught.value.code == 1


def test_settings_parse_the_allowlist_and_reject_garbage():
    settings = Settings.from_env(_env(ALLOWED_TELEGRAM_USER_IDS="42, 7"))
    assert settings.allowed_telegram_user_ids == frozenset({42, 7})

    with pytest.raises(ConfigError):
        Settings.from_env(_env(ALLOWED_TELEGRAM_USER_IDS=""))
    with pytest.raises(ConfigError):
        Settings.from_env(_env(ALLOWED_TELEGRAM_USER_IDS="nope"))
    with pytest.raises(ConfigError):
        Settings.from_env(_env(ALLOWED_TELEGRAM_USER_IDS="0"))
    with pytest.raises(ConfigError):
        Settings.from_env(_env(TELEGRAM_BOT_TOKEN=""))
    with pytest.raises(ConfigError):
        Settings.from_env(_env(DEFAULT_PHONE_REGION="NOPE"))


async def test_stranger_gets_silence_and_nothing_is_stored(tmp_path):
    store = CheckStore(tmp_path / "checks.db")
    sent: list[str] = []

    async def send(text: str) -> None:
        sent.append(text)

    await handle_text(
        user_id=999,
        text="https://evil.example/phish",
        allowed=ALLOWED,
        pipeline=_BoomPipeline(),
        store=store,
        client=_unused_client(),
        send=send,
    )
    assert sent == []
    assert store.archive_latest(999) is None
    store.close()


async def test_allowed_user_gets_checking_before_the_verdict(tmp_path):
    store = CheckStore(tmp_path / "checks.db")
    sent: list[str] = []

    async def send(text: str) -> None:
        sent.append(text)

    pipeline = _ScriptedPipeline(sent)
    await handle_text(
        user_id=42,
        text="please check https://example.com/docs",
        allowed=ALLOWED,
        pipeline=pipeline,
        store=store,
        client=_unused_client(),
        send=send,
    )
    assert sent[0] == CHECKING_MESSAGE
    assert pipeline.saw_checking_first is True
    assert sent[1].startswith("GO")
    assert "https://example.com/docs" in sent[1]
    assert store.archive_latest(42) is not None
    store.close()


async def test_no_link_asks_for_one_and_multiple_links_are_counted(tmp_path):
    store = CheckStore(tmp_path / "checks.db")
    sent: list[str] = []

    async def send(text: str) -> None:
        sent.append(text)

    await handle_text(
        user_id=42,
        text="nothing to see here",
        allowed=ALLOWED,
        pipeline=_ScriptedPipeline(sent),
        store=store,
        client=_unused_client(),
        send=send,
    )
    assert sent == [NO_LINK_MESSAGE]

    sent.clear()
    await handle_text(
        user_id=42,
        text="https://a.example/ and https://b.example/",
        allowed=ALLOWED,
        pipeline=_ScriptedPipeline(sent),
        store=store,
        client=_unused_client(),
        send=send,
    )
    assert sent[0] == "checking 2 links..."

    sent.clear()
    links = " ".join(f"https://ex{i}.example/" for i in range(5))
    await handle_text(
        user_id=42,
        text=links,
        allowed=ALLOWED,
        pipeline=_ScriptedPipeline(sent),
        store=store,
        client=_unused_client(),
        send=send,
    )
    assert sent[0] == "checking 3 links..."
    assert "https://ex0.example/" in sent[1]
    assert "https://ex2.example/" in sent[1]
    assert "https://ex3.example/" not in sent[1]
    assert "I only checked the first 3 links." in sent[1]
    store.close()


async def test_a_malformed_link_does_not_block_the_valid_one(tmp_path):
    store = CheckStore(tmp_path / "checks.db")
    sent: list[str] = []

    async def send(text: str) -> None:
        sent.append(text)

    await handle_text(
        user_id=42,
        text="https://example.com:abc/a https://ok.example/x",
        allowed=ALLOWED,
        pipeline=_ScriptedPipeline(sent),
        store=store,
        client=_unused_client(),
        send=send,
    )
    assert sent[0] == CHECKING_MESSAGE
    assert "https://ok.example/x" in sent[1]
    assert "example.com:abc" not in sent[1]
    store.close()


async def test_a_long_reply_is_split_under_the_telegram_limit(tmp_path):
    store = CheckStore(tmp_path / "checks.db")
    sent: list[str] = []

    async def send(text: str) -> None:
        sent.append(text)

    links = " ".join(f"https://ex{i}.example/{'a' * 1800}" for i in range(3))
    await handle_text(
        user_id=42,
        text=links,
        allowed=ALLOWED,
        pipeline=_ScriptedPipeline(sent),
        store=store,
        client=_unused_client(),
        send=send,
    )
    followups = sent[1:]
    assert len(followups) >= 2
    assert all(len(part) <= 4096 for part in followups)
    joined = "\n".join(followups)
    assert "https://ex0.example/" in joined
    assert "https://ex2.example/" in joined
    store.close()


def test_split_for_telegram_prefers_a_blank_line_and_hard_cuts():
    assert split_for_telegram("short") == ["short"]
    left = "A" * 3000
    right = "B" * 3000
    parts = split_for_telegram(f"{left}\n\n{right}", limit=4096)
    assert parts == [left, right]
    huge = "C" * 5000
    pieces = split_for_telegram(huge, limit=4096)
    assert [len(piece) for piece in pieces] == [4096, 5000 - 4096]
    assert "".join(pieces) == huge


class _BoomPipeline:
    async def check(self, url: str, client: httpx.AsyncClient) -> CheckResult:
        raise AssertionError(f"stranger triggered a check of {url}")


class _ScriptedPipeline:
    def __init__(self, sent: list[str]) -> None:
        self.sent = sent
        self.saw_checking_first = False

    async def check(self, url: str, client: httpx.AsyncClient) -> CheckResult:
        del client
        self.saw_checking_first = bool(self.sent) and self.sent[0].startswith("checking")
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


def _unused_client() -> httpx.AsyncClient:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"unexpected request {request.url}")

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _env(**overrides: str) -> dict[str, str]:
    values = {
        "TELEGRAM_BOT_TOKEN": "123:abc",
        "ALLOWED_TELEGRAM_USER_IDS": "42",
    }
    values.update(overrides)
    return values
