"""Telegram adapter.

Only private chats from ALLOWED_TELEGRAM_USER_IDS get a reply. Everyone else
is ignored, including /start. The handler sends "checking..." immediately,
then a second message with the verdict, so a slow source does not look like
a dead bot.
"""

import asyncio
import logging
from collections.abc import Awaitable, Callable

import httpx
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes, MessageHandler, filters

from scam_cemetery.config import Settings
from scam_cemetery.formatting import format_report
from scam_cemetery.pipeline import Pipeline
from scam_cemetery.storage import CheckStore
from scam_cemetery.url_extract import extract_urls

logger = logging.getLogger(__name__)

CHECKING_MESSAGE = "checking..."
NO_LINK_MESSAGE = "Send me a link and I'll check it. A bare domain is fine."
HELP_MESSAGE = (
    "Paste a link and I'll check it with Google Safe Browsing, VirusTotal, and URLhaus.\n"
    "\n"
    "Verdicts are GO, CAUTION, or NO-GO.\n"
    "/archive keeps your latest check past the 90-day cleanup."
)
MAX_URLS_PER_MESSAGE = 3

Send = Callable[[str], Awaitable[None]]


def should_respond(user_id: int | None, chat_type: str, allowed: frozenset[int] | set[int]) -> bool:
    """The allowlist. Group chats and unknown users get silence, not an error."""
    return chat_type == "private" and user_id is not None and user_id in allowed


async def handle_text(
    *,
    user_id: int,
    text: str,
    allowed: frozenset[int] | set[int],
    pipeline: Pipeline,
    store: CheckStore,
    client: httpx.AsyncClient,
    send: Send,
) -> None:
    if user_id not in allowed:
        return
    urls = extract_urls(text)
    if not urls:
        await send(NO_LINK_MESSAGE)
        return

    shown = urls[:MAX_URLS_PER_MESSAGE]
    extra = len(urls) - len(shown)
    if len(shown) == 1:
        await send(CHECKING_MESSAGE)
    else:
        await send(f"checking {len(shown)} links...")

    blocks: list[str] = []
    for url in shown:
        try:
            result = await pipeline.check(url, client)
            store.save(result, telegram_user_id=user_id)
        except Exception:
            # The user already saw "checking...". Always send a follow-up.
            # Pipeline failures are caught lower down; this is a bug in our code.
            logger.exception("check failed for user=%s", user_id)
            blocks.append(f"I couldn't finish checking {url}.")
            continue
        blocks.append(format_report(result))
        logger.info("check user=%s verdict=%s url=%s", user_id, result.judgment.verdict, url)
    if extra:
        blocks.append(f"I only checked the first {MAX_URLS_PER_MESSAGE} links.")
    await send("\n\n".join(blocks))


async def handle_archive(
    *,
    user_id: int,
    allowed: frozenset[int] | set[int],
    store: CheckStore,
    send: Send,
) -> None:
    if user_id not in allowed:
        return
    check_id = store.archive_latest(user_id)
    if check_id is None:
        await send("No checks to archive yet.")
        return
    await send(f"Archived check #{check_id} so it will not be deleted after 90 days.")


def build_application(
    settings: Settings,
    store: CheckStore,
    pipeline: Pipeline,
    client: httpx.AsyncClient,
    extra_clients: list[httpx.AsyncClient] | None = None,
) -> Application:
    application = (
        Application.builder()
        .token(settings.telegram_bot_token)
        .post_init(_post_init)
        .post_shutdown(_post_shutdown)
        .build()
    )
    application.bot_data["settings"] = settings
    application.bot_data["store"] = store
    application.bot_data["pipeline"] = pipeline
    application.bot_data["client"] = client
    application.bot_data["clients"] = [client, *(extra_clients or [])]
    application.add_handler(CommandHandler("start", _on_start))
    application.add_handler(CommandHandler("help", _on_start))
    application.add_handler(CommandHandler("archive", _on_archive))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, _on_text))
    return application


async def _post_init(application: Application) -> None:
    application.create_task(_cleanup_loop(application.bot_data["store"]), name="cleanup")


async def _post_shutdown(application: Application) -> None:
    for client in application.bot_data.get("clients", []):
        if isinstance(client, httpx.AsyncClient):
            await client.aclose()


async def _cleanup_loop(store: CheckStore) -> None:
    while True:
        await asyncio.sleep(24 * 60 * 60)
        try:
            removed = store.cleanup()
        except Exception:
            logger.exception("daily cleanup failed")
            continue
        logger.info("daily cleanup removed %s checks", removed)


async def _on_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    message = update.effective_message
    user = update.effective_user
    if message is None or user is None or not message.text:
        return
    settings: Settings = context.bot_data["settings"]
    if not should_respond(user.id, message.chat.type, settings.allowed_telegram_user_ids):
        return

    async def send(text: str) -> None:
        await message.reply_text(text)

    await handle_text(
        user_id=user.id,
        text=message.text,
        allowed=settings.allowed_telegram_user_ids,
        pipeline=context.bot_data["pipeline"],
        store=context.bot_data["store"],
        client=context.bot_data["client"],
        send=send,
    )


async def _on_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    message = update.effective_message
    user = update.effective_user
    if message is None or user is None:
        return
    settings: Settings = context.bot_data["settings"]
    if not should_respond(user.id, message.chat.type, settings.allowed_telegram_user_ids):
        return
    await message.reply_text(HELP_MESSAGE)


async def _on_archive(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    message = update.effective_message
    user = update.effective_user
    if message is None or user is None:
        return
    settings: Settings = context.bot_data["settings"]
    if not should_respond(user.id, message.chat.type, settings.allowed_telegram_user_ids):
        return

    async def send(text: str) -> None:
        await message.reply_text(text)

    await handle_archive(
        user_id=user.id,
        allowed=settings.allowed_telegram_user_ids,
        store=context.bot_data["store"],
        send=send,
    )
