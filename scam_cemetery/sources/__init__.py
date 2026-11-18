"""Sources. Link checks ask if a URL is known-bad. Email and phone checks add their own."""

from scam_cemetery.sources.base import ThreatSource
from scam_cemetery.sources.safe_browsing import SafeBrowsingSource
from scam_cemetery.sources.urlhaus import URLhausSource
from scam_cemetery.sources.virustotal import VirusTotalSource

__all__ = [
    "SafeBrowsingSource",
    "ThreatSource",
    "URLhausSource",
    "VirusTotalSource",
]
