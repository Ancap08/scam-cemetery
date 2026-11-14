"""Threat-intel sources. Each one answers the same question: is this URL known-bad?"""

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
