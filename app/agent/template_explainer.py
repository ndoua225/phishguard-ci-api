"""Deterministic TemplateExplainer for PhishGuard CI.

This is the sole fallback explanation mechanism. It does not call any LLM.
"""

from __future__ import annotations

from typing import Final

from app.schemas.analysis import (
    AssessmentStatus,
    Classification,
    ExplainRequest,
    ExplainResponse,
    ExplainResponseStatus,
    ReliabilityLevel,
)

# Explanation templates per indicator code
INDICATOR_EXPLANATIONS: Final[dict[str, str]] = {
    "REPUTATION_MALICIOUS_EXTERNAL": (
        "Le service tiers Google Web Risk signale cette adresse dans sa catégorie "
        "d'ingénierie sociale (contribuant pour 30 points). Ce signalement externe "
        "indique que le lien a déjà été répertorié comme suspect par ce fournisseur."
    ),
    "REPUTATION_SUSPICIOUS_EXTERNAL": (
        "Un service de réputation signale cette adresse comme suspecte (contribuant "
        "pour 15 points). Ce signal indique un risque potentiel sans confirmation formelle "
        "de malveillance."
    ),
    "PUBLIC_IP_LITERAL": (
        "Le lien utilise directement une adresse IP publique au lieu d'un nom de domaine "
        "officiel (pondération illustrative de 15 points en attente de validation). "
        "Bien qu'une adresse IP ne prouve pas en soi une malveillance, cette pratique "
        "est anormale et déconseillée pour un service officiel."
    ),
    "SUSPICIOUS_TLD": (
        "L'adresse utilise une extension de domaine figurant sur la liste de surveillance "
        "statistique (pondération illustrative de 5 points en attente de validation). "
        "Une extension ne constitue jamais à elle seule une preuve de fraude, mais "
        "représente un indice de risque supplémentaire."
    ),
    "EXCESSIVE_SUBDOMAINS": (
        "L'URL présente un nombre excessif de sous-domaines (pondération illustrative "
        "de 10 points en attente de validation). Cette technique peut masquer le domaine "
        "réel et tromper l'utilisateur sur l'identité du site."
    ),
    "NON_STANDARD_PORT": (
        "L'URL utilise un port non standard (pondération illustrative de 5 points en "
        "attente de validation). Les services officiels utilisent généralement les ports "
        "standards (80, 443)."
    ),
    "URL_SHORTENER": (
        "Le lien utilise un raccourcisseur d'URL (pondération illustrative de 10 points "
        "en attente de validation). Cela masque la destination réelle du lien."
    ),
    "MIXED_SCRIPT_DOMAIN": (
        "Le domaine utilise des caractères de scripts différents (pondération illustrative "
        "de 10 points en attente de validation). Cela peut indiquer une tentative "
        "d'homographe pour imiter un domaine légitime."
    ),
    "LONG_URL": (
        "L'URL est anormalement longue (pondération illustrative de 5 points en attente "
        "de validation). Cela peut indiquer une tentative de masquage ou de "
        "manipulation technique."
    ),
    "HIGH_ENTROPY": (
        "L'URL présente une entropie élevée, suggérant des caractères aléatoires "
        "(pondération illustrative de 5 points en attente de validation). Cela peut "
        "indiquer un domaine généré algorithmiquement."
    ),
    "OTP_PIN_REQUEST": (
        "Une formulation demandant expressément un code PIN a été repérée (contribuant "
        "pour 20 points). Par mesure de sécurité absolue, un utilisateur ne doit jamais "
        "transmettre son code secret PIN ou mot de passe en réponse à un message, quel "
        "que soit l'expéditeur déclaré."
    ),
    "URGENCY_PRESSURE": (
        "La mention d'un blocage sous délai court (contribuant pour 15 points) relève "
        "d'un procédé de manipulation psychologique classique visant à précipiter une "
        "action sans vérification préalable."
    ),
    "BRAND_MENTION_INFORMATIVE": (
        "Le nom de la marque apparaît dans le texte. Conformément aux règles d'analyse, "
        "cette simple citation ne constitue pas une preuve d'usurpation technique et "
        "n'ajoute aucun point au score de risque."
    ),
    "BRAND_OFFICIAL_DOMAIN_MATCH": (
        "Le domaine officiel de la marque a été détecté dans les liens. Cela ne "
        "garantit pas la légitimité du message mais indique une correspondance de domaine."
    ),
    "SENSITIVE_DATA_REQUEST": (
        "Une demande de données sensibles (numéro de carte, identité, code de sécurité) "
        "a été détectée (contribuant pour 15 points). Les services légitimes ne demandent "
        "jamais ces informations par message."
    ),
}


LIMITATIONS_TEMPLATES: Final[dict[str, str]] = {
    "simulation": (
        "Ce résultat est issu d'une simulation illustrative conditionnelle et repose sur "
        "des pondérations de structure d'URL en attente de décision humaine formelle."
    ),
    "partial_pipeline": (
        "L'exécution technique du pipeline est PARTIAL : au moins une vérification de "
        "réputation n'a pas pu aboutir ; cette source n'a pas contribué à l'évaluation."
    ),
    "provider_third_party": (
        "Le signalement de réputation représente un indice externe fourni par un tiers "
        "et non une expertise contradictoire absolue."
    ),
    "structural_indicative": (
        "Les anomalies structurelles d'URL (adresse IP, extension surveillée, etc.) "
        "constituent des indices indicatifs et ne démontrent pas à elles seules le "
        "caractère frauduleux du serveur."
    ),
    "ci_domain_exclusion": (
        "L'exclusion du domaine national .ci de la liste des extensions surveillées "
        "signifie simplement qu'il ne reçoit aucun point de pénalité à ce titre ; elle "
        "ne constitue pas une garantie de légitimité pour les sites utilisant cette "
        "extension."
    ),
    "heuristic_detection": (
        "La détection de la demande de code PIN ou de l'urgence repose sur une analyse "
        "heuristique du texte et ne constitue pas une preuve formelle d'intention "
        "malveillante."
    ),
}


RECOMMENDATIONS_TEMPLATES: Final[list[str]] = [
    "Ne cliquez sous aucun prétexte sur le lien fourni.",
    "Par mesure de prudence fondamentale, ne transmettez et ne saisissez jamais votre "
    "code secret PIN Mobile Money à la suite d'une sollicitation par message.",
    "Pour toute vérification concernant votre compte, utilisez exclusivement "
    "l'application officielle de l'opérateur ou contactez son service client par les "
    "canaux officiels.",
]


def generate_explanation(request: ExplainRequest) -> ExplainResponse:
    """Generate deterministic explanation from analysis result.

    Args:
        request: Validated ExplainRequest from FastAPI.

    Returns:
        ExplainResponse with status OK and full explanation.
    """
    indicators = request.indicators

    # Build summary
    summary = _build_summary(request)

    # Build per-indicator explanations
    explanations = []
    for indicator in indicators:
        template = INDICATOR_EXPLANATIONS.get(indicator.code)
        if template:
            explanations.append({
                "indicator_code": indicator.code,
                "text": template,
            })

    # Build limitations
    limitations = _build_limitations(request)

    # Recommendations (always the same base set)
    recommendations = RECOMMENDATIONS_TEMPLATES.copy()

    return ExplainResponse(
        status=ExplainResponseStatus.OK,
        summary=summary,
        explanations=explanations,
        limitations=limitations,
        recommendations=recommendations,
        reason_code=None,
    )


def _build_summary(request: ExplainRequest) -> str:
    """Build concise French summary."""
    result = request.deterministic_result
    content_type = request.content_type.value

    classification_fr = {
        Classification.CLEAN: "FAIBLE",
        Classification.SUSPICIOUS: "MODÉRÉ",
        Classification.CRITICAL: "CRITICAL",
    }[result.classification]

    pipeline_fr = {
        "COMPLETED": "COMPLÈTE",
        "PARTIAL": "PARTIELLE",
        "FAILED": "ÉCHOUÉE",
    }[result.pipeline_status.value]

    reliability_fr = {
        ReliabilityLevel.LOW: "FAIBLE",
        ReliabilityLevel.MEDIUM: "MOYENNE",
        ReliabilityLevel.HIGH: "FORTE",
    }[result.reliability_level]

    assessment_fr = {
        AssessmentStatus.CONCLUSIVE: "CONCLUSIVE",
        AssessmentStatus.INCONCLUSIVE: "INCONCLUSIVE",
    }[result.assessment_status]

    return (
        f"Ce {content_type.lower()} présente un niveau de risque {classification_fr} "
        f"(score simulé de {result.score}/100). L'exécution du pipeline est {pipeline_fr}, "
        f"la couverture des vérifications est {reliability_fr}, et l'évaluation est jugée "
        f"{assessment_fr} sur les signaux observés."
    )


def _build_limitations(request: ExplainRequest) -> list[str]:
    """Build limitations based on analysis context."""
    result = request.deterministic_result
    indicators = request.indicators
    limitations = []

    # Always include simulation limitation
    limitations.append(LIMITATIONS_TEMPLATES["simulation"])

    # Pipeline status
    if result.pipeline_status.value == "PARTIAL":
        limitations.append(LIMITATIONS_TEMPLATES["partial_pipeline"])

    # Provider signal present
    has_provider_signal = any(
        i.nature.value == "PROVIDER_SIGNAL" for i in indicators
    )
    if has_provider_signal:
        limitations.append(LIMITATIONS_TEMPLATES["provider_third_party"])

    # Structural signals present
    has_structural = any(
        i.nature.value == "STRUCTURAL_SIGNAL" for i in indicators
    )
    if has_structural:
        limitations.append(LIMITATIONS_TEMPLATES["structural_indicative"])

    # CI domain exclusion
    has_ci_exclusion = any(
        i.code == "BRAND_OFFICIAL_DOMAIN_MATCH" for i in indicators
    )
    if has_ci_exclusion:
        limitations.append(LIMITATIONS_TEMPLATES["ci_domain_exclusion"])

    # Heuristic detection
    has_heuristic = any(
        i.nature.value == "HEURISTIC_DETECTION" for i in indicators
    )
    if has_heuristic:
        limitations.append(LIMITATIONS_TEMPLATES["heuristic_detection"])

    return limitations


# Template version for history regeneration
TEMPLATE_VERSION = "1.0.0"