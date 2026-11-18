"""Process entrypoint. Long polling only; nothing listens for inbound traffic."""

import logging
import sys

import httpx

from scam_cemetery import __version__
from scam_cemetery.bot import build_application
from scam_cemetery.config import ConfigError, Settings
from scam_cemetery.judges.grok import GrokJudge
from scam_cemetery.judges.rules import RulesJudge
from scam_cemetery.pipeline import Checker, Pipeline
from scam_cemetery.sources.disposable import DisposableDomainSource
from scam_cemetery.sources.domain_age import DomainAgeSource
from scam_cemetery.sources.domain_target import DomainThreatAdapter
from scam_cemetery.sources.email_syntax import EmailSyntaxSource
from scam_cemetery.sources.lookalike import BrandLookalikeSource
from scam_cemetery.sources.mail_dns import MailDnsSource
from scam_cemetery.sources.numverify import NumverifySource
from scam_cemetery.sources.phone_info import PhoneNumberSource
from scam_cemetery.sources.safe_browsing import SafeBrowsingSource
from scam_cemetery.sources.urlhaus import URLhausSource
from scam_cemetery.sources.virustotal import VirusTotalSource
from scam_cemetery.storage import CheckStore

logger = logging.getLogger(__name__)


def build_pipeline(settings: Settings, judge_client: httpx.AsyncClient) -> Checker:
    """Wire link, email, and phone checks, and the judge chain.

    Order is the fallback order: Grok first, rules last. Insert an open-source
    model and then OpenAI between them when those backups exist.
    ``judge_client`` is separate from the source client so the model call can
    have its own timeout and the xAI key is not on the source client.

    One VirusTotal source is shared, so a link and an email spend the same
    4-per-minute budget. Email threat-intel calls look up ``https://<domain>/``.
    """
    safe_browsing = SafeBrowsingSource(settings.google_safe_browsing_key)
    virustotal = VirusTotalSource(settings.virustotal_api_key)
    urlhaus = URLhausSource(settings.urlhaus_auth_key)
    grok = GrokJudge(
        api_key=settings.xai_api_key,
        model=settings.xai_model,
        base_url=settings.xai_base_url,
        client=judge_client,
    )
    judges = [grok, RulesJudge()]
    timeout = settings.source_timeout_seconds
    url_pipeline = Pipeline(
        sources=[safe_browsing, virustotal, urlhaus],
        judges=judges,
        timeout=timeout,
    )
    email_pipeline = Pipeline(
        sources=[
            EmailSyntaxSource(),
            MailDnsSource(),
            DomainAgeSource(),
            DisposableDomainSource(),
            BrandLookalikeSource(),
            DomainThreatAdapter(safe_browsing),
            DomainThreatAdapter(virustotal),
            DomainThreatAdapter(urlhaus),
        ],
        judges=judges,
        timeout=timeout,
    )
    phone_pipeline = Pipeline(
        sources=[
            PhoneNumberSource(region=settings.default_phone_region),
            NumverifySource(settings.numverify_api_key),
        ],
        judges=judges,
        timeout=timeout,
    )
    return Checker(
        url_pipeline,
        email_pipeline,
        phone_pipeline,
        virustotal=virustotal,
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
