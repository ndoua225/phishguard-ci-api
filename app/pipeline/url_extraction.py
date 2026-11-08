"""URL extraction and normalization utilities."""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

from app.config import settings


@dataclass(slots=True)
class ExtractedURL:
    """Extracted URL with metadata."""

    original: str
    normalized: str
    scheme: str | None
    host: str | None
    port: int | None
    path: str
    query: str
    fragment: str
    is_ip_literal: bool
    tld: str | None
    punycode_host: str | None


# RFC 3986 inspired regex for URL extraction
# Matches URLs with scheme or bare domains with TLD
URL_PATTERN = re.compile(
    r"""
    (?:
        # With scheme
        (?:https?|ftp)://
        [^\s/$.?#].[^\s]*
    |
        # Bare domain with TLD (simplified)
        (?:www\.)?
        [a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?
        (?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+
        (?:
            /[^\s]*
        )?
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)

# IP literal pattern (IPv4 and IPv6 in brackets)
IP_LITERAL_PATTERN = re.compile(
    r"^(?:"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}"
    r"|"
    r"\[(?:[0-9a-fA-F:]+)\]"
    r")$"
)

# Suspicious TLDs (statistical watchlist - PROPOSITION_NON_VALIDEE)
SUSPICIOUS_TLDS = frozenset({
    "top", "xyz", "click", "loan", "work", "party", "gdn", "bid",
    "racing", "stream", "download", "link", "science", "review",
    "country", "trade", "faith", "date", "account", "win", "cricket",
    "men", "mom", "webcam", "zip", "mov", "nexus", "phd", "prof",
    "esq", "foo", "bar", "dev", "app", "page", "new", "ing",
})

# Official Ivorian domains (for brand verification)
OFFICIAL_CI_DOMAINS = frozenset({
    "orange-money.ci", "mtn.ci", "moov.ci", "orange.ci",
    "mtnci.net", "moovafrica.ci",
})

# Known shortener domains
SHORTENER_DOMAINS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "shorte.st", "cutt.ly",
    "rb.gy", "s.id", "v.gd", "tr.im", "u.to", "tiny.cc",
})


def extract_urls(text: str, max_urls: int | None = None) -> list[ExtractedURL]:
    """Extract and normalize URLs from text.

    Args:
        text: Input text to scan for URLs.
        max_urls: Maximum number of URLs to extract (default from settings).

    Returns:
        List of extracted and normalized URLs.
    """
    if max_urls is None:
        max_urls = settings.max_urls_per_analysis

    matches = URL_PATTERN.findall(text)
    urls: list[ExtractedURL] = []

    for match in matches[:max_urls]:
        extracted = _normalize_url(match.strip())
        if extracted:
            urls.append(extracted)

    return urls


def _normalize_url(raw: str) -> ExtractedURL | None:
    """Normalize a raw URL string."""
    # Add scheme if missing
    url_to_parse = raw
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        url_to_parse = "http://" + raw

    try:
        parsed = urlparse(url_to_parse)
    except Exception:
        return None

    if not parsed.netloc:
        return None

    host = parsed.hostname or ""
    is_ip = bool(IP_LITERAL_PATTERN.match(host))

    # Extract TLD
    tld = _extract_tld(host)

    # Punycode conversion for IDN
    punycode_host = None
    try:
        if host and any(ord(c) > 127 for c in host):
            punycode_host = host.encode("idna").decode("ascii")
    except Exception:
        pass

    return ExtractedURL(
        original=raw,
        normalized=parsed.geturl(),
        scheme=parsed.scheme or None,
        host=host.lower() if host else None,
        port=parsed.port,
        path=parsed.path,
        query=parsed.query,
        fragment=parsed.fragment,
        is_ip_literal=is_ip,
        tld=tld,
        punycode_host=punycode_host,
    )


def _extract_tld(host: str) -> str | None:
    """Extract TLD from hostname."""
    if not host:
        return None

    # Handle IP literals
    if IP_LITERAL_PATTERN.match(host):
        return None

    parts = host.lower().split(".")
    if len(parts) < 2:
        return None

    # Simple TLD extraction (last part)
    # For production, consider using publicsuffixlist
    return parts[-1]


def is_suspicious_tld(tld: str | None) -> bool:
    """Check if TLD is on the statistical watchlist."""
    if not tld:
        return False
    return tld.lower() in SUSPICIOUS_TLDS


def is_shortener_domain(host: str | None) -> bool:
    """Check if domain is a known URL shortener."""
    if not host:
        return False
    return host.lower() in SHORTENER_DOMAINS


def is_official_ci_domain(host: str | None) -> bool:
    """Check if domain is an official Ivorian domain."""
    if not host:
        return False
    return host.lower() in OFFICIAL_CI_DOMAINS


def calculate_url_entropy(url: str) -> float:
    """Calculate Shannon entropy of URL string."""
    if not url:
        return 0.0

    from math import log2

    freq: dict[str, int] = {}
    for char in url:
        freq[char] = freq.get(char, 0) + 1

    entropy = 0.0
    length = len(url)
    for count in freq.values():
        p = count / length
        entropy -= p * log2(p)

    return entropy