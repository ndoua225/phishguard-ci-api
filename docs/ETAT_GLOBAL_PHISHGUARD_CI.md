# État global — PhishGuard CI

**État au 6 novembre 2026 (Europe/Paris)**
**Dépôt :** `C:\Users\Stanislas\Projects\phishguard-ci-api`
**P0 : OPEN / PARTIALLY_VALIDATED. P1 : plan préparé, non commencé.**

## État par critère

| Domaine | Statut | Preuve / limite |
|---|---|---|
| Dépôt et état Git | Vérifié | Dépôt accessible, branche `master`, aucun commit, fichiers non suivis. Git diff ne représente pas les modifications antérieures. |
| API `/health` | Validé pour le squelette seulement | `pytest`: 1 test passé. Pas de fonctionnalité d'analyse. |
| Ruff | PASS | `ruff check .`, Ruff 0.17.4. |
| mypy | PASS | `mypy app`, mypy 1.20.2, 3 fichiers source; cache redirigé vers l'espace de travail. |
| pytest | PASS avec avertissement | 1 passé; avertissement de dépréciation Starlette/httpx non résolu. |
| Gitleaks | BLOCKED | Binaire absent; aucun scan actuel. |
| CI | Partiellement vérifiée | YAML parse localement; aucun run GitHub Actions. Expression du token corrigée localement, mais action distante non vérifiée. |
| Installation reproductible | Non vérifiée | Environnement préexistant; réinstallation non effectuée. |
| T-L1, T-H1–H10, T-P1 | NOT_IMPLEMENTED / BLOCKED | Pas de pipeline, client Hermes ni stockage dans le code présent. |
| T-D21 | Revue documentaire seulement | D21 reste `SELECTED_FOR_REVIEW`; D16 indépendante, ouverte et non approuvée. |
| Hermes et fournisseurs | Non implémentés / non activés | L'API ne fait aucun appel; les restrictions documentaires ne sont pas des contrôles runtime testés. |
| L1–L8 | Candidats à revoir | Aucune implémentation ni preuve de test; précédence et états limites restent à définir. |
| F1/F2 | Inactifs | Seuils 70/45 non adoptés et non codés. |
| Sécurité pré-exposition | Non validée | Auth, quotas, CORS, persistance et exposition réseau absents ou non vérifiés. |

## Décisions et interprétation de sécurité

- **D21 option B :** `SELECTED_FOR_REVIEW`, pas d'approbation finale. K1 peut rester `HERMES_ENABLED=false` sur installation neuve; une activation après configuration technique est une décision de configuration distincte, encore à valider. K2/K3 demeurent ouverts.
- **Démarrage vs transfert :** démarrer/configurer l'application ou un adaptateur ne prouve ni n'autorise l'envoi de contenu réel. Sans D16 approuvée séparément, tout transfert réel doit rester bloqué.
- **D22 / D16 :** D22 ne vaut jamais approbation de D16. D16 requiert sa propre décision explicite, juridique et contractuelle.
- **L1–L8 :** option A reste une base proposée pour revue technique, non une preuve de comportement.
- **F1/F2 :** les seuils candidats restent désactivés.
- **Hermes :** le contrat documentaire limite Hermes à l'explication et réserve à FastAPI orchestration et décisions. Comme Hermes n'est pas implémenté, ces barrières ne sont pas prouvées en exécution.

## Bloqueurs P0

1. Installer ou rendre disponible Gitleaks et archiver un scan réel.
2. Examiner l'avertissement Starlette/httpx et choisir une combinaison compatible avec preuve locale.
3. Exécuter CI sur un runner représentatif; la validation YAML seule ne suffit pas.
4. Réconcilier l'absence d'implémentations avec T-L1, T-H1–H10, T-P1 : ces critères sont bloqués/non implémentés et ne peuvent pas être déclarés réussis.
5. Refaire une vérification d'espaces et de secrets sur l'ensemble des fichiers; dépôt sans commit et fichiers non suivis.

## État P1 et prochaines étapes

Le plan détaillé est dans `docs/PLAN_P1.md`. Aucun code P1 n'a été ajouté car le gate P0 reste ouvert et des décisions techniques/juridiques ne sont pas résolues. La prochaine progression sûre est de rendre les contrôles de qualité et scan reproductibles, puis de cadrer les contrats synthétiques déterministes, sans réseau ni LLM.

Les preuves de commandes et leurs limites figurent dans `docs/TEST_EVIDENCE.md`. Aucun service externe n'a été appelé, aucune donnée réelle n'a été transmise, et aucun commit/push n'a été fait.

