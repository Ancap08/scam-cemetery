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
from scam_cemetery.formatting import format_report, split_for_telegram
from scam_cemetery.models import CheckResult
from scam_cemetery.pipeline import Checker, Pipeline
from scam_cemetery.scans import watch_virustotal
from scam_cemetery.storage import CheckStore, cleanup_loop
from scam_cemetery.subjects import extract_subjects

logger = logging.getLogger(__name__)

CHECKING_MESSAGE = "checking..."
NO_LINK_MESSAGE = (
    "Send me a link, an email address, or a phone number and I'll check it. A bare domain is fine."
)
HELP_MESSAGE = (
    "Paste a link, an email address, or a phone number and I'll check it.\n"
    "\n"
    "Links use Google Safe Browsing, VirusTotal, and URLhaus.\n"
    "Email addresses also get DNS, domain age, disposable-domain, and lookalike checks.\n"
    "Phone numbers are checked offline. Numverify runs only if a key is set.\n"
    "\n"
    "Verdicts are GO, CAUTION, or NO-GO.\n"
    "Email addresses and phone numbers are stored redacted, not in full.\n"
    "/archive keeps your latest check past the 90-day cleanup."
)
MAX_ITEMS_PER_MESSAGE = 3

Send = Callable[[str], Awaitable[None]]
Schedule = Callable[[Awaitable[None]], None]


def should_respond(user_id: int | None, chat_type: str, allowed: frozenset[int] | set[int]) -> bool:
    """The allowlist. Group chats and unknown users get silence, not an error."""
    return chat_type == "private" and user_id is not None and user_id in allowed


async def handle_text(
    *,
    user_id: int,
    text: str,
    allowed: frozenset[int] | set[int],
    pipeline: Pipeline | Checker,
    store: CheckStore,
    client: httpx.AsyncClient,
    send: Send,
    schedule: Schedule | None = None,
    default_phone_region: str = "US",
) -> None:
    if user_id not in allowed:
        return
    subjects = extract_subjects(text, default_region=default_phone_region)
    if not subjects:
        await send(NO_LINK_MESSAGE)
        return

    shown = subjects[:MAX_ITEMS_PER_MESSAGE]
    extra = len(subjects) - len(shown)
    if len(shown) == 1:
        await send(CHECKING_MESSAGE)
    elif all(item.kind == "url" for item in shown):
        await send(f"checking {len(shown)} links...")
    else:
        await send(f"checking {len(shown)} items...")

    blocks: list[str] = []
    pending_scans: list[CheckResult] = []
    for subject in shown:
        try:
            if isinstance(pipeline, Checker):
                result = await pipeline.check_subject(subject, client)
            else:
                result = await pipeline.check(subject.canonical, client)
            store.save(result, telegram_user_id=user_id)
        except Exception:
            # The user already saw "checking...". Always send a follow-up.
            # Pipeline failures are caught lower down; this is a bug in our code.
            # Log the type only. The message text can be an email or a phone number.
            logger.exception("check failed for user=%s type=%s", user_id, subject.kind)
            blocks.append(f"I couldn't finish checking {subject.display}.")
            continue
        blocks.append(format_report(result))
        logger.info(
            "check user=%s verdict=%s type=%s subject=%s",
            user_id,
            result.judgment.verdict,
            subject.kind,
            subject.display,
        )
        if _needs_virus_total_scan(result):
            pending_scans.append(result)
    if extra:
        if all(item.kind == "url" for item in subjects):
            blocks.append(f"I only checked the first {MAX_ITEMS_PER_MESSAGE} links.")
        else:
            blocks.append(f"I only checked the first {MAX_ITEMS_PER_MESSAGE}.")
    # Several long URLs can push one reply past Telegram's 4096-character cap.
    for chunk in split_for_telegram("\n\n".join(blocks)):
        await send(chunk)
    if schedule is None:
        return
    scanner = pipeline.virustotal()
    if scanner is None:
        return
    for result in pending_scans:
        # An email follow-up scans the domain, not the mailbox. ``result.url``
        # stays the redacted address in the saved row.
        schedule(
            watch_virustotal(
                source=scanner,
                url=result.scan_url or result.url,
                client=client,
                prior=result,
                pipeline=pipeline,
                store=store,
                user_id=user_id,
                send=send,
            )
        )


def _needs_virus_total_scan(result: CheckResult) -> bool:
    return any(
        item.source == "virustotal" and item.detail.get("needs_scan") for item in result.sources
    )


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


class ScamCemeteryApplication(Application):
    """Starts the retention loop only after the bot is running.

    ``Application.create_task`` during ``post_init`` runs before ``start`` sets
    ``running``, so python-telegram-bot warns and will not await the task.
    """

    async def start(self) -> None:
        await super().start()
        store = self.bot_data.get("store")
        if not isinstance(store, CheckStore) or self.bot_data.get("cleanup_stop") is not None:
            return
        stop = asyncio.Event()
        self.bot_data["cleanup_stop"] = stop
        interval = self.bot_data.get("cleanup_interval", 24 * 60 * 60)
        self.create_task(cleanup_loop(store, stop, interval=float(interval)), name="cleanup")

    async def stop(self) -> None:
        stop = self.bot_data.get("cleanup_stop")
        if isinstance(stop, asyncio.Event):
            stop.set()
        await super().stop()


def build_application(
    settings: Settings,
    store: CheckStore,
    pipeline: Pipeline | Checker,
    client: httpx.AsyncClient,
    extra_clients: list[httpx.AsyncClient] | None = None,
) -> Application:
    application = (
        Application.builder()
        .token(settings.telegram_bot_token)
        .application_class(ScamCemeteryApplication)
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


async def _post_shutdown(application: Application) -> None:
    for client in application.bot_data.get("clients", []):
        if isinstance(client, httpx.AsyncClient):
            await client.aclose()


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

    def schedule(work: Awaitable[None]) -> None:
        # The application is running here, so create_task tracks the scan until shutdown.
        context.application.create_task(work, name="virustotal-scan")

    await handle_text(
        user_id=user.id,
        text=message.text,
        allowed=settings.allowed_telegram_user_ids,
        pipeline=context.bot_data["pipeline"],
        store=context.bot_data["store"],
        client=context.bot_data["client"],
        send=send,
        schedule=schedule,
        default_phone_region=settings.default_phone_region,
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
