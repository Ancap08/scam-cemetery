"""Read settings from the environment. Secrets never have defaults."""

import os
from collections.abc import Mapping
from dataclasses import dataclass

DEFAULT_DATABASE_PATH = "data/checks.db"
DEFAULT_XAI_MODEL = "grok-4.7"
DEFAULT_SOURCE_TIMEOUT_SECONDS = 8.0
DEFAULT_XAI_TIMEOUT_SECONDS = 20.0
XAI_BASE_URL = "https://api.x.ai/v1"


class ConfigError(Exception):
    """The process cannot start with the environment it was given."""


@dataclass(frozen=True)
class Settings:
    telegram_bot_token: str
    xai_api_key: str | None
    xai_model: str
    xai_base_url: str
    google_safe_browsing_key: str | None
    virustotal_api_key: str | None
    urlhaus_auth_key: str | None
    allowed_telegram_user_ids: frozenset[int]
    database_path: str
    source_timeout_seconds: float
    judge_timeout_seconds: float

    def __repr__(self) -> str:
        # Never include tokens or API keys in logs.
        configured = []
        if self.google_safe_browsing_key:
            configured.append("google_safe_browsing")
        if self.virustotal_api_key:
            configured.append("virustotal")
        if self.urlhaus_auth_key:
            configured.append("urlhaus")
        judge = "grok" if self.xai_api_key else "rules-only"
        allowed = ",".join(str(user_id) for user_id in sorted(self.allowed_telegram_user_ids))
        return (
            "Settings("
            f"allowed=[{allowed}], "
            f"database_path={self.database_path!r}, "
            f"sources={configured}, "
            f"judge={judge}, "
            f"model={self.xai_model!r})"
        )

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "Settings":
        values = os.environ if env is None else env
        token = _required(values, "TELEGRAM_BOT_TOKEN")
        allowed = _parse_user_ids(_required(values, "ALLOWED_TELEGRAM_USER_IDS"))
        return cls(
            telegram_bot_token=token,
            xai_api_key=_optional(values, "XAI_API_KEY"),
            xai_model=_optional(values, "XAI_MODEL") or DEFAULT_XAI_MODEL,
            xai_base_url=XAI_BASE_URL,
            google_safe_browsing_key=_optional(values, "GOOGLE_SAFE_BROWSING_KEY"),
            virustotal_api_key=_optional(values, "VIRUSTOTAL_API_KEY"),
            urlhaus_auth_key=_optional(values, "URLHAUS_AUTH_KEY"),
            allowed_telegram_user_ids=allowed,
            database_path=_optional(values, "DATABASE_PATH") or DEFAULT_DATABASE_PATH,
            source_timeout_seconds=_positive_float(
                values, "SOURCE_TIMEOUT_SECONDS", DEFAULT_SOURCE_TIMEOUT_SECONDS
            ),
            judge_timeout_seconds=_positive_float(
                values, "XAI_TIMEOUT_SECONDS", DEFAULT_XAI_TIMEOUT_SECONDS
            ),
        )


def _required(env: Mapping[str, str], name: str) -> str:
    value = env.get(name, "").strip()
    if not value:
        raise ConfigError(f"{name} is required")
    return value


def _optional(env: Mapping[str, str], name: str) -> str | None:
    value = env.get(name, "").strip()
    return value or None


def _parse_user_ids(raw: str) -> frozenset[int]:
    parts = [part.strip() for part in raw.replace(";", ",").split(",")]
    parts = [part for part in parts if part]
    if not parts:
        raise ConfigError("ALLOWED_TELEGRAM_USER_IDS must list at least one user id")
    ids: set[int] = set()
    for part in parts:
        try:
            user_id = int(part)
        except ValueError as exc:
            raise ConfigError(
                f"ALLOWED_TELEGRAM_USER_IDS has a non-integer entry: {part!r}"
            ) from exc
        if user_id <= 0:
            raise ConfigError(
                f"ALLOWED_TELEGRAM_USER_IDS must be positive Telegram user ids, got {user_id}"
            )
        ids.add(user_id)
    return frozenset(ids)


def _positive_float(env: Mapping[str, str], name: str, default: float) -> float:
    raw = env.get(name, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be a number, got {raw!r}") from exc
    if value <= 0:
        raise ConfigError(f"{name} must be greater than zero, got {value}")
    return value
