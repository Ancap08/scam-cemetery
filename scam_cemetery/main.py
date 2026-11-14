"""Process entrypoint. Long polling only; nothing listens for inbound traffic."""

import logging
import sys

import httpx

from scam_cemetery import __version__
from scam_cemetery.bot import build_application
from scam_cemetery.config import ConfigError, Settings
from scam_cemetery.judges.grok import GrokJudge
from scam_cemetery.judges.rules import RulesJudge
from scam_cemetery.pipeline import Pipeline
from scam_cemetery.sources.safe_browsing import SafeBrowsingSource
from scam_cemetery.sources.urlhaus import URLhausSource
from scam_cemetery.sources.virustotal import VirusTotalSource
from scam_cemetery.storage import CheckStore

logger = logging.getLogger(__name__)


def build_pipeline(settings: Settings, judge_client: httpx.AsyncClient) -> Pipeline:
    """Wire the three sources and the judge chain.

    Order is the fallback order: Grok first, rules last. Insert an open-source
    model and then OpenAI between them when those backups exist.
    ``judge_client`` is separate from the source client so the model call can
    have its own timeout and the xAI key is not on the source client.
    """
    sources = [
        SafeBrowsingSource(settings.google_safe_browsing_key),
        VirusTotalSource(settings.virustotal_api_key),
        URLhausSource(settings.urlhaus_auth_key),
    ]
    grok = GrokJudge(
        api_key=settings.xai_api_key,
        model=settings.xai_model,
        base_url=settings.xai_base_url,
        client=judge_client,
    )
    return Pipeline(
        sources=sources,
        judges=[grok, RulesJudge()],
        timeout=settings.source_timeout_seconds,
    )


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # httpx logs full request URLs at INFO. Safe Browsing puts the API key there.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)

    try:
        settings = Settings.from_env()
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

    logger.info("starting scam-cemetery %s %s", __version__, settings)
    store = CheckStore(settings.database_path)
    removed = store.cleanup()
    logger.info("startup cleanup removed %s checks", removed)

    headers = {"User-Agent": f"scam-cemetery/{__version__}"}
    source_client = httpx.AsyncClient(
        timeout=httpx.Timeout(settings.source_timeout_seconds + 1),
        headers=headers,
        follow_redirects=False,
    )
    judge_client = httpx.AsyncClient(
        timeout=httpx.Timeout(settings.judge_timeout_seconds),
        headers=headers,
    )
    application = build_application(
        settings,
        store,
        build_pipeline(settings, judge_client),
        source_client,
        extra_clients=[judge_client],
    )
    # drop_pending_updates: a restart should not replay every link sent while we were down.
    application.run_polling(drop_pending_updates=True, allowed_updates=["message"])


if __name__ == "__main__":
    main()
