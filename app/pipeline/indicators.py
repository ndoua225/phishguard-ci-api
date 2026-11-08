"""Indicator extraction and classification for PhishGuard CI."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

from app.pipeline.url_extraction import (
    ExtractedURL,
    calculate_url_entropy,
    is_official_ci_domain,
    is_shortener_domain,
    is_suspicious_tld,
)
from app.schemas.analysis import (
    Indicator,
    IndicatorNature,
    RuleValidationStatus,
)

# Patterns for heuristic detection
OTP_PATTERNS: Final[list[re.Pattern[str]]] = [
    re.compile(r"\b(?:code|pin|mot de passe|password|secret)\b.{0,20}\b(?:orange money|mtn|moov|mobile money|momo|wave|floor)\b", re.IGNORECASE),
    re.compile(r"\b(?:orange money|mtn|moov|mobile money|momo|wave|floor)\b.{0,20}\b(?:code|pin|mot de passe|password|secret)\b", re.IGNORECASE),
    re.compile(r"\b(?:veuillez|merci de|saisir|entrer|fournir|communiquer|transmettre)\b.{0,30}\b(?:code|pin|mot de passe|secret)\b", re.IGNORECASE),
    re.compile(r"\b(?:code\s*(?:secret|pin|de\s*validation|de\s*sécurité)|pin\s*(?:secret|code)|mot\s*de\s*passe)\b", re.IGNORECASE),
]

URGENCY_PATTERNS: Final[list[re.Pattern[str]]] = [
    re.compile(r"\b(?:urgent|immédiat|tout de suite|maintenant|sans délai|rapidement)\b", re.IGNORECASE),
    re.compile(r"\b(?:bloqu[ée]|suspend[u]|fermé|désactivé|supprimé)\b.{0,30}\b(?:dans|sous|avant)\b.{0,20}\b(?:heure|h|minute|mn|jour|j)\b", re.IGNORECASE),
    re.compile(r"\b(?:dernier|dernière)\b.{0,10}\b(?:délai|chance|avertissement|rappel)\b", re.IGNORECASE),
    re.compile(r"\b(?:24\s*h|48\s*h|72\s*h|une\s*heure|deux\s*heures)\b", re.IGNORECASE),
]

BRAND_PATTERNS: Final[dict[str, list[re.Pattern[str]]]] = {
    "ORANGE_MONEY": [
        re.compile(r"\borange\s*money\b", re.IGNORECASE),
        re.compile(r"\borange\s*money\b", re.IGNORECASE),
        re.compile(r"\bom\b(?:\s*(?:ci|money))?", re.IGNORECASE),
    ],
    "MTN": [
        re.compile(r"\bmtn\b(?:\s*(?:ci|money|momo))?", re.IGNORECASE),
        re.compile(r"\bmomo\b", re.IGNORECASE),
        re.compile(r"\bmtn\s*momo\b", re.IGNORECASE),
    ],
    "MOOV": [
        re.compile(r"\bmoov\b(?:\s*(?:ci|money|africa))?", re.IGNORECASE),
        re.compile(r"\bmoov\s*africa\b", re.IGNORECASE),
        re.compile(r"\bfloor\b", re.IGNORECASE),
    ],
    "WAVE": [
        re.compile(r"\bwave\b(?:\s*(?:ci|money|mobile))?", re.IGNORECASE),
    ],
}

SENSITIVE_DATA_PATTERNS: Final[list[re.Pattern[str]]] = [
    re.compile(r"\b(?:numéro|numero)\s*(?:de\s*)?(?:carte|compte|identité|national|passeport)\b", re.IGNORECASE),
    re.compile(r"\b(?:cvc|cvv|code\s*de\s*sécurité)\b", re.IGNORECASE),
    re.compile(r"\b(?:date\s*d'?expiration|expiry)\b", re.IGNORECASE),
]

# URL structural anomaly patterns
URL_ANOMALY_PATTERNS: Final[list[tuple[str, re.Pattern[str], int, RuleValidationStatus]]] = [
    ("PUBLIC_IP_LITERAL", re.compile(r"^https?://\d{1,3}(?:\.\d{1,3}){3}"), 15, RuleValidationStatus.PROPOSITION_NON_VALIDEE),
    ("SUSPICIOUS_TLD", re.compile(r"\.(?:top|xyz|click|loan|work|party|gdn|bid|racing|stream|download|link|science|review|country|trade|faith|date|account|win|cricket|men|mom|webcam|zip|mov|nexus|phd|prof|esq|foo|bar)(?:/|$)"), 5, RuleValidationStatus.PROPOSITION_NON_VALIDEE),
    ("EXCESSIVE_SUBDOMAINS", re.compile(r"^(?:https?://)(?:[a-z0-9-]+\.){4,}"), 10, RuleValidationStatus.PROPOSITION_NON_VALIDEE),
    ("NON_STANDARD_PORT", re.compile(r":(?:8080|8443|8888|9000|9090|3000|5000)(?:/|$)"), 5, RuleValidationStatus.PROPOSITION_NON_VALIDEE),
    ("URL_SHORTENER", re.compile(r"(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly|adf\.ly|shorte\.st|cutt\.ly|rb\.gy|s\.id|v\.gd|tr\.im|u\.to|tiny\.cc)"), 10, RuleValidationStatus.PROPOSITION_NON_VALIDEE),
    ("MIXED_SCRIPT_DOMAIN", re.compile(r"[^\x00-\x7F]"), 10, RuleValidationStatus.PROPOSITION_NON_VALIDEE),
    ("LONG_URL", re.compile(r".{200,}"), 5, RuleValidationStatus.PROPOSITION_NON_VALIDEE),
    ("HIGH_ENTROPY", re.compile(r""), 5, RuleValidationStatus.PROPOSITION_NON_VALIDEE),  # Checked separately
]


@dataclass(slots=True)
class ExtractionResult:
    """Result of indicator extraction."""

    indicators: list[Indicator]
    url_anomalies: list[tuple[str, str]]  # (indicator_code, matched_url)
    brand_mentions: list[str]
    otp_requests: list[str]
    urgency_signals: list[str]


def extract_indicators(
    text: str,
    urls: list[ExtractedURL],
    verification_facts: list[dict[str, str]],
) -> ExtractionResult:
    """Extract all indicators from text and URLs.

    Args:
        text: Normalized input text.
        urls: Extracted URLs from text.
        verification_facts: Results from reputation providers.

    Returns:
        ExtractionResult with all detected indicators.
    """
    indicators: list[Indicator] = []
    url_anomalies: list[tuple[str, str]] = []
    brand_mentions: list[str] = []
    otp_requests: list[str] = []
    urgency_signals: list[str] = []

    # 1. Reputation indicators from verification facts
    for fact in verification_facts:
        if fact.get("outcome") == "MALICIOUS":
            indicators.append(Indicator(
                code="REPUTATION_MALICIOUS_EXTERNAL",
                category="REPUTATION_URL_DOMAIN",
                nature=IndicatorNature.PROVIDER_SIGNAL,
                label="Lien signalé malveillant par un service de réputation",
                points_awarded=30,
                evidence_snippet=None,
                validation_status=RuleValidationStatus.VALIDEE,
            ))
        elif fact.get("outcome") == "SUSPICIOUS":
            indicators.append(Indicator(
                code="REPUTATION_SUSPICIOUS_EXTERNAL",
                category="REPUTATION_URL_DOMAIN",
                nature=IndicatorNature.PROVIDER_SIGNAL,
                label="Lien signalé suspect par un service de réputation",
                points_awarded=15,
                evidence_snippet=None,
                validation_status=RuleValidationStatus.VALIDEE,
            ))

    # 2. URL structural anomalies
    for url in urls:
        _check_url_anomalies(url, indicators, url_anomalies)

    # 3. Brand mentions
    brand_mentions = _extract_brand_mentions(text, urls)
    for brand in brand_mentions:
        is_official = any(
            is_official_ci_domain(url.host) and brand.lower() in (url.host or "").lower()
            for url in urls
        )
        if is_official:
            # Official domain mentioned - no points, informative only
            indicators.append(Indicator(
                code="BRAND_OFFICIAL_DOMAIN_MATCH",
                category="BRAND_IMPERSONATION_MISMATCH",
                nature=IndicatorNature.INFORMATIVE_SIGNAL,
                label=f"Domaine officiel {brand} détecté",
                points_awarded=0,
                evidence_snippet=None,
                validation_status=RuleValidationStatus.VALIDEE,
            ))
        else:
            # Brand mention without official domain
            indicators.append(Indicator(
                code="BRAND_MENTION_INFORMATIVE",
                category="BRAND_IMPERSONATION_MISMATCH",
                nature=IndicatorNature.INFORMATIVE_SIGNAL,
                label=f"Mention textuelle de {brand} sans domaine officiel rattaché",
                points_awarded=0,
                evidence_snippet=None,
                validation_status=RuleValidationStatus.VALIDEE,
            ))

    # 4. OTP/PIN requests
    otp_requests = _extract_otp_requests(text)
    for snippet in otp_requests:
        indicators.append(Indicator(
            code="OTP_PIN_REQUEST",
            category="SENSITIVE_DATA_REQUEST",
            nature=IndicatorNature.HEURISTIC_DETECTION,
            label="Formulation explicite de demande de code PIN",
            points_awarded=20,
            evidence_snippet=snippet[:200],
            validation_status=RuleValidationStatus.VALIDEE,
        ))

    # 5. Urgency manipulation
    urgency_signals = _extract_urgency_signals(text)
    for snippet in urgency_signals:
        indicators.append(Indicator(
            code="URGENCY_PRESSURE",
            category="URGENCY_MANIPULATION",
            nature=IndicatorNature.HEURISTIC_DETECTION,
            label="Menace de blocage sous délai court",
            points_awarded=15,
            evidence_snippet=snippet[:200],
            validation_status=RuleValidationStatus.VALIDEE,
        ))

    # 6. Sensitive data requests (other than OTP)
    _extract_sensitive_data_requests(text, indicators)

    return ExtractionResult(
        indicators=indicators,
        url_anomalies=url_anomalies,
        brand_mentions=brand_mentions,
        otp_requests=otp_requests,
        urgency_signals=urgency_signals,
    )


def _check_url_anomalies(
    url: ExtractedURL,
    indicators: list[Indicator],
    url_anomalies: list[tuple[str, str]],
) -> None:
    """Check URL for structural anomalies."""
    normalized = url.normalized
    host = url.host or ""

    for code, pattern, points, status in URL_ANOMALY_PATTERNS:
        if code == "HIGH_ENTROPY":
            entropy = calculate_url_entropy(normalized)
            if entropy > 4.0:  # High entropy threshold
                indicators.append(Indicator(
                    code=code,
                    category="URL_STRUCTURE_ANOMALIES",
                    nature=IndicatorNature.STRUCTURAL_SIGNAL,
                    label="Entropie élevée dans l'URL (caractères aléatoires suspects)",
                    points_awarded=points,
                    evidence_snippet=None,
                    validation_status=status,
                ))
                url_anomalies.append((code, normalized))
        elif code == "URL_SHORTENER":
            if is_shortener_domain(host):
                indicators.append(Indicator(
                    code=code,
                    category="URL_STRUCTURE_ANOMALIES",
                    nature=IndicatorNature.STRUCTURAL_SIGNAL,
                    label="Utilisation d'un raccourcisseur d'URL",
                    points_awarded=points,
                    evidence_snippet=None,
                    validation_status=status,
                ))
                url_anomalies.append((code, normalized))
        elif code == "SUSPICIOUS_TLD":
            if is_suspicious_tld(url.tld):
                indicators.append(Indicator(
                    code=code,
                    category="URL_STRUCTURE_ANOMALIES",
                    nature=IndicatorNature.STRUCTURAL_SIGNAL,
                    label=f"Extension de domaine .{url.tld} figurant sur la liste de surveillance statistique",
                    points_awarded=points,
                    evidence_snippet=None,
                    validation_status=status,
                ))
                url_anomalies.append((code, normalized))
        elif code == "PUBLIC_IP_LITERAL":
            if url.is_ip_literal:
                indicators.append(Indicator(
                    code=code,
                    category="URL_STRUCTURE_ANOMALIES",
                    nature=IndicatorNature.STRUCTURAL_SIGNAL,
                    label="Lien utilisant une adresse IP publique",
                    points_awarded=points,
                    evidence_snippet=None,
                    validation_status=status,
                ))
                url_anomalies.append((code, normalized))
        elif pattern.search(normalized):
            indicators.append(Indicator(
                code=code,
                category="URL_STRUCTURE_ANOMALIES",
                nature=IndicatorNature.STRUCTURAL_SIGNAL,
                label=_get_anomaly_label(code),
                points_awarded=points,
                evidence_snippet=None,
                validation_status=status,
            ))
            url_anomalies.append((code, normalized))


def _get_anomaly_label(code: str) -> str:
    """Get label for anomaly code."""
    labels = {
        "EXCESSIVE_SUBDOMAINS": "Nombre excessif de sous-domaines",
        "NON_STANDARD_PORT": "Port non standard dans l'URL",
        "MIXED_SCRIPT_DOMAIN": "Domaine utilisant des scripts mixtes (homographe potentiel)",
        "LONG_URL": "URL anormalement longue",
    }
    return labels.get(code, "Anomalie structurelle d'URL")


def _extract_brand_mentions(text: str, urls: list[ExtractedURL]) -> list[str]:
    """Extract brand mentions from text."""
    mentions: set[str] = set()
    text_lower = text.lower()

    for brand, patterns in BRAND_PATTERNS.items():
        for pattern in patterns:
            if pattern.search(text_lower):
                mentions.add(brand)
                break

    # Also check URLs for brand in domain
    for url in urls:
        host = (url.host or "").lower()
        for brand, patterns in BRAND_PATTERNS.items():
            brand_key = brand.lower().replace("_", "")
            if brand_key in host:
                mentions.add(brand)
                break

    return list(mentions)


def _extract_otp_requests(text: str) -> list[str]:
    """Extract OTP/PIN request snippets from text."""
    snippets: list[str] = []
    text_lower = text.lower()

    for pattern in OTP_PATTERNS:
        for match in pattern.finditer(text_lower):
            # Extract context around match
            start = max(0, match.start() - 30)
            end = min(len(text), match.end() + 30)
            snippet = text[start:end].strip()
            if snippet and snippet not in snippets:
                snippets.append(snippet)

    return snippets


def _extract_urgency_signals(text: str) -> list[str]:
    """Extract urgency manipulation signals from text."""
    snippets: list[str] = []
    text_lower = text.lower()

    for pattern in URGENCY_PATTERNS:
        for match in pattern.finditer(text_lower):
            start = max(0, match.start() - 30)
            end = min(len(text), match.end() + 30)
            snippet = text[start:end].strip()
            if snippet and snippet not in snippets:
                snippets.append(snippet)

    return snippets


def _extract_sensitive_data_requests(text: str, indicators: list[Indicator]) -> None:
    """Extract other sensitive data requests."""
    text_lower = text.lower()

    for pattern in SENSITIVE_DATA_PATTERNS:
        for match in pattern.finditer(text_lower):
            start = max(0, match.start() - 30)
            end = min(len(text), match.end() + 30)
            snippet = text[start:end].strip()

            indicators.append(Indicator(
                code="SENSITIVE_DATA_REQUEST",
                category="SENSITIVE_DATA_REQUEST",
                nature=IndicatorNature.HEURISTIC_DETECTION,
                label="Demande de données sensibles (carte, identité, etc.)",
                points_awarded=15,
                evidence_snippet=snippet[:200],
                validation_status=RuleValidationStatus.VALIDEE,
            ))
            break  # One indicator per category is enough