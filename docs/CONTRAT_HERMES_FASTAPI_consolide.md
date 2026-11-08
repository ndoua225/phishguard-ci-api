# Contrat Hermes ↔ FastAPI — PhishGuard CI

**Version documentaire :** 1.0 — 6 novembre 2026
**Statut :** PROPOSED / validation humaine requise

## 1. Responsabilités

- FastAPI orchestre, valide, calcule le score et la classification, applique les quotas et décide si Hermes peut être appelé.
- Hermes explique uniquement les résultats structurés. Il ne détecte pas, ne note pas, ne décide pas et ne pilote pas le pipeline.
- `explanation_source` est fixé par FastAPI et vaut `HERMES` ou `TEMPLATE`.
- FastAPI valide et filtre la réponse Hermes. Toute erreur, réponse invalide, refus ou timeout déclenche uniquement `TemplateExplainer`.

## 2. Champs d'entrée conceptuels

| Champ | Statut | Règle |
|---|---|---|
| `contract_version` | Requis | Version du contrat |
| `analysis_ref` | Requis | Identifiant interne opaque |
| `content_type` | Requis | Type de contenu |
| `language` | Requis | Langue de l'explication |
| `deterministic_result` | Requis | Résultat calculé par FastAPI |
| `indicators` | Requis | Indicateurs structurés minimisés |
| `reliability_level` | À spécifier | Seulement après validation de la matrice |
| `evidence_snippet` | Facultatif | C7 : masqué, minimisé, éphémère, désactivé par défaut |
| `untrusted_content` | INTERDIT | Ne doit pas exister dans le schéma |

Ne pas transmettre à Hermes : URL ou domaine en clair, identifiants fournisseur, secrets, décomposition du score, poids ou planchers.

## 3. C7 et D16

C7 est facultatif, désactivé par défaut, limité au strict nécessaire et masqué avant transmission. Il est conservé en mémoire de requête uniquement puis effacé. Il ne doit apparaître ni en base, ni dans les journaux, ni dans les traces, ni dans une mémoire persistante.

C7 ne contourne jamais D16 : aucun contenu réel n'est envoyé à un LLM tant que le fournisseur, le contrat, la rétention, l'entraînement, les sous-traitants et la revue juridique ne sont pas formellement approuvés. D22, y compris l'enregistrement d'une approbation, ne vaut jamais approbation de D16; D16 exige une approbation explicite et indépendante.

## 4. Sortie conceptuelle

- `status`: `OK` ou `CANNOT_EXPLAIN`.
- `explanation`: explication française concise, bornée et fondée sur les seules données reçues.
- `reason_code` en cas de refus : `PROHIBITED_REQUEST`, `INSUFFICIENT_INPUT` ou `INTERNAL_LIMIT`.

Hermes ne renvoie ni score ni nouvelle classification. FastAPI reste maître de la réponse finale.

## 5. Fiabilité L1–L8

Statut : `SELECTED_FOR_REVIEW` — option A retenue par l'utilisateur comme base de travail à intégrer après revue technique. Les règles ci-dessous restent candidates; elles ne sont ni implémentées ni testées d'après les preuves disponibles.

| Situation proposée | Fiabilité proposée |
|---|---|
| Aucun URL dans le contenu | `MEDIUM` |
| Aucun fournisseur configuré | `LOW` |
| Aucun contrôle applicable | `MEDIUM` |
| Contrôles applicables, mais tous désactivés | `LOW` |
| Tous les contrôles tentés ont échoué | `LOW` |
| Certains contrôles réussissent et d'autres échouent | `MEDIUM` |
| Aucun échec, mais certains contrôles sont désactivés | `MEDIUM` |
| Tous les contrôles applicables sont exécutés avec succès, sans inconnue | `HIGH` |
| L'applicabilité d'au moins un contrôle reste inconnue | `MEDIUM` |

La revue technique doit préciser l'ordre d'application et les combinaisons de cas, notamment les chevauchements entre « aucun URL » et « aucun contrôle applicable », entre « aucun fournisseur configuré » et « contrôles désactivés », ainsi que le traitement des états `UNKNOWN` et `ERROR`. Aucun ordre ou résultat supplémentaire n'est présumé ici. La fiabilité reste indépendante du score de risque : un verdict `MALICIOUS` ne l'augmente pas artificiellement et `CLEAN` ne garantit pas l'absence de menace.

## 6. Activation et statut D21

D21 : option B sélectionnée par l'utilisateur pour revue (`SELECTED_FOR_REVIEW`) — Hermes pourrait être activé par défaut après configuration technique; cette portée reste à valider et n'est pas une approbation de production. K1 (`HERMES_ENABLED=false` sur une installation neuve) peut coexister avec cette orientation; K2/K3 et les modalités d'activation restent ouverts. Le démarrage ou la configuration technique de l'application/adaptateur est distinct de l'envoi de contenu réel. Sans approbation indépendante de D16, tout transfert de contenu réel à un LLM reste interdit.

D16 reste un préalable indépendant : aucun contenu réel ne doit être transmis tant que D16 n'est pas explicitement approuvée. Aucun accès Hermes à PostgreSQL, secrets, fichiers, shell, navigateur, web, outils ou fournisseurs.

## 7. Statut

Document de consolidation, non implémenté et non testé. Une approbation humaine et des preuves techniques restent nécessaires.
