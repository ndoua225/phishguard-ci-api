# Plan de préparation P1 — PhishGuard CI

**Statut :** plan préparé; implémentation P1 non commencée.
**Condition d'entrée :** P0 reste OPEN jusqu'à la levée documentée de ses blocages. Les décisions métier/juridiques manquantes restent des gates.

## Séquence proposée

1. **Geler les contrats d'entrée/sortie.** Documenter schémas, tailles maximales, types de contenu, limites d'extraction, normalisation, erreurs et versions. Ne pas accepter de champ `untrusted_content` dans le contrat Hermes.
2. **Construire le noyau déterministe local.** Ajouter validation et normalisation d'entrées synthétiques; extraire les URL sous forme de chaînes seulement. Ne jamais effectuer de requête réseau, résolution DNS, ouverture de navigateur ou suivi de redirection.
3. **Définir le modèle de résultats.** Représenter contrôle applicable, désactivé, réussi, échoué, inconnu et erreur sans interpréter un état non spécifié. Maintenir fiabilité et score séparés.
4. **Formaliser L1–L8.** Décider en revue technique la précédence, les contrôles applicables et les états `UNKNOWN`/`ERROR`; couvrir les chevauchements par tests synthétiques avant implémentation. L'option A demeure une base de revue, pas une spécification complète.
5. **Garder le scoring désactivé.** F1/F2 (70/45) restent inactifs tant qu'une décision explicite et une évaluation synthétique ne les adoptent pas. Aucun seuil ne doit être codé par défaut.
6. **Préparer des interfaces sûres.** Définir des interfaces internes pour `TemplateExplainer` et un futur adaptateur Hermes sans implémenter d'appel fournisseur. La configuration de démarrage ne doit pas autoriser l'envoi de contenu réel; D16 est un gate indépendant.
7. **Ajouter les tests d'acceptation locaux.** Couvrir validation, limites, extraction non exécutée, minimisation, erreurs, absence de réseau et absence d'appel LLM avec données synthétiques uniquement.
8. **Sécurité avant intégration.** Définir auth, quotas, CORS, journalisation avec redaction, rétention, stockage et modèle de menace avant toute exposition réseau ou persistance.
9. **Réévaluer les gates.** Gitleaks, CI réelle, tests de sécurité et choix de dépendances doivent produire des preuves reproductibles avant toute déclaration P0 CLOSED.

## Architecture cible locale (proposée)

`API FastAPI → validation/normalisation → extraction passive d'indicateurs → évaluateurs déterministes configurés → résultat structuré → TemplateExplainer`

L'adaptateur Hermes reste absent/désactivé jusqu'à approbations et preuves séparées. FastAPI possède toute orchestration et décision. Aucun second LLM, accès outil ou transmission externe n'est prévu dans le travail local P1 décrit ici.

## Critères de sortie P1

- Contrats versionnés, validation des limites et réponses d'erreur stables.
- Extraction d'URL purement textuelle, prouvée sans réseau.
- L1–L8 complètement spécifiées, puis testées par cas et chevauchements avant activation.
- Aucun seuil F1/F2 implicite.
- Tests synthétiques démontrant absence d'appel réseau, stockage indu, fuite de canari et invocation Hermes en configuration sûre.
- Ruff, mypy, pytest et scan de secrets reproductibles; CI distante observée avant fusion/publication.
- D21 clarifiée comme décision de revue; D16 explicitement approuvée séparément avant tout contenu réel.

## Gates non résolus

- D16 : revue juridique/contractuelle, rétention, entraînement, sous-traitants et transferts.
- D21/K1–K3 : statut final de démarrage après configuration et modalités exactes.
- L1–L8 : précédence et sémantique des états incomplets.
- F1/F2 : adoption ou rejet des seuils candidats.
- Dépendances de test : traiter l'avertissement Starlette/httpx avec preuve de compatibilité.

