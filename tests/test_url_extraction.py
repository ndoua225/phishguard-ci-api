"""Tests for URL extraction pipeline."""

from __future__ import annotations

from app.pipeline.url_extraction import (
    calculate_url_entropy,
    extract_urls,
    is_official_ci_domain,
    is_shortener_domain,
    is_suspicious_tld,
)


class TestURLExtraction:
    """Tests for URL extraction and normalization."""

    def test_extract_single_url_with_scheme(self):
        text = "Check this link: https://example.com/path"
        urls = extract_urls(text)
        assert len(urls) == 1
        assert urls[0].original == "https://example.com/path"
        assert urls[0].normalized == "https://example.com/path"
        assert urls[0].scheme == "https"
        assert urls[0].host == "example.com"

    def test_extract_bare_domain(self):
        text = "Visit example.com for more info"
        urls = extract_urls(text)
        assert len(urls) == 1
        assert urls[0].original == "example.com"
        # Normalized URL may or may not have trailing slash
        assert urls[0].normalized in ("http://example.com", "http://example.com/")
        assert urls[0].scheme == "http"
        assert urls[0].host == "example.com"

    def test_extract_multiple_urls(self):
        text = "Links: https://a.com and http://b.org and c.net"
        urls = extract_urls(text)
        assert len(urls) == 3

    def test_max_urls_limit(self):
        text = " ".join([f"site{i}.com" for i in range(15)])
        urls = extract_urls(text, max_urls=10)
        assert len(urls) == 10

    def test_ip_literal_detection(self):
        text = "Go to http://192.168.1.1/admin"
        urls = extract_urls(text)
        assert len(urls) == 1
        assert urls[0].is_ip_literal is True
        assert urls[0].host == "192.168.1.1"

    def test_suspicious_tld_detection(self):
        text = "Check http://malicious.top and http://safe.com"
        urls = extract_urls(text)
        assert len(urls) == 2
        top_url = next(u for u in urls if u.tld == "top")
        com_url = next(u for u in urls if u.tld == "com")
        assert is_suspicious_tld(top_url.tld) is True
        assert is_suspicious_tld(com_url.tld) is False

    def test_shortener_domain_detection(self):
        text = "Link: https://bit.ly/abc123"
        urls = extract_urls(text)
        assert len(urls) == 1
        assert is_shortener_domain(urls[0].host) is True

    def test_official_ci_domain_detection(self):
        text = "Official: https://orange-money.ci/login"
        urls = extract_urls(text)
        assert len(urls) == 1
        assert is_official_ci_domain(urls[0].host) is True

    def test_url_entropy_calculation(self):
        # Low entropy - repetitive
        low_entropy = calculate_url_entropy("http://aaaaaaaaaa.com")
        # High entropy - random looking
        high_entropy = calculate_url_entropy("http://x7k9m2p4q8w1z3.com")
        assert high_entropy > low_entropy

    def test_invalid_urls_not_extracted(self):
        text = "Not a url: just text here"
        urls = extract_urls(text)
        assert len(urls) == 0

    def test_url_with_query_and_fragment(self):
        text = "https://example.com/path?query=value#fragment"
        urls = extract_urls(text)
        assert len(urls) == 1
        assert urls[0].path == "/path"
        assert urls[0].query == "query=value"
        assert urls[0].fragment == "fragment"

    def test_url_with_port(self):
        text = "https://example.com:8443/path"
        urls = extract_urls(text)
        assert len(urls) == 1
        assert urls[0].port == 8443


class TestHelperFunctions:
    """Tests for helper functions."""

    def test_is_suspicious_tld_known_bad(self):
        assert is_suspicious_tld("top") is True
        assert is_suspicious_tld("xyz") is True
        assert is_suspicious_tld("click") is True

    def test_is_suspicious_tld_known_good(self):
        assert is_suspicious_tld("com") is False
        assert is_suspicious_tld("org") is False
        assert is_suspicious_tld("fr") is False
        assert is_suspicious_tld("ci") is False

    def test_is_shortener_domain(self):
        assert is_shortener_domain("bit.ly") is True
        assert is_shortener_domain("tinyurl.com") is True
        assert is_shortener_domain("example.com") is False

    def test_is_official_ci_domain(self):
        assert is_official_ci_domain("orange-money.ci") is True
        assert is_official_ci_domain("mtn.ci") is True
        assert is_official_ci_domain("example.com") is False