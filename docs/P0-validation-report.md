# Rapport de validation P0 — PhishGuard CI

**Date :** 6 novembre 2026 (Europe/Paris)
**Statut :** OPEN / PARTIALLY_VALIDATED — clôture P0 non prononcée.
**Dépôt :** `C:\Users\Stanislas\Projects\phishguard-ci-api`.

## Environnement et exécutions de cette passe

Windows, Python 3.12.10; environnement virtuel local préexistant. Versions : Ruff 0.17.4, mypy 1.20.2, pytest 8.4.2, FastAPI 0.162.0, Starlette 1.10.0, httpx 0.28.1.

| Contrôle | Résultat | Preuve / limite |
|---|---|---|
| `ruff check .` | PASS | `All checks passed!` |
| `mypy app` | PASS | `Success: no issues found in 3 source files`; cache redirigé vers le workspace inscriptible. |
| `pytest -W default` | PASS avec avertissement | `1 passed`; `StarletteDeprecationWarning` conseille `httpx2`; non résolu. |
| Analyse YAML CI | PASS syntaxique | PyYAML 6.0.3 a chargé le workflow après correction de l'expression GITHUB_TOKEN. Ne prouve pas un run GitHub Actions. |
| Gitleaks | BLOCKED / non exécuté | Exécutable absent de l'environnement. Aucun résultat de scan affirmé. |
| Installation editable reproductible | NON EXÉCUTÉE | Venv existant; aucune installation ou résolution réseau exécutée. |
| `git diff --check` | Code 0, portée limitée | Dépôt sans commit et fichiers non suivis; commande ne couvre pas correctement le contenu existant. |

Les commandes exactes et les sorties/limites sont consignées dans `docs/TEST_EVIDENCE.md`.

## Tests produit / sécurité

- T-L1, T-H1 à T-H10 et T-P1 : NOT_IMPLEMENTED / BLOCKED. L'application ne contient ni pipeline d'analyse, ni intégration Hermes, ni stockage associé; aucune barrière d'exécution n'est démontrable.
- T-D21 : revue documentaire seulement. D21 reste `SELECTED_FOR_REVIEW`; D16 reste séparée, ouverte et non approuvée. Cela ne constitue pas un test d'intégration.
- `GET /health` : le test synthétique existant passe; il prouve seulement le fonctionnement du squelette local.
- Aucune donnée réelle n'a été envoyée à un LLM ou à un service tiers. Aucun fournisseur n'a été activé.

## Avertissements et blocages

1. L'avertissement Starlette/httpx demeure; aucune dépendance n'a été changée sans preuve locale de compatibilité.
2. Gitleaks n'est pas installé et aucun scan actuel de secrets n'est disponible.
3. Le workflow a été syntaxiquement analysé, mais la CI distante n'a pas été exécutée.
4. Les tests Hermes et de fuite ne peuvent pas passer tant que les composants correspondants n'existent pas.
5. Sans commit, l'état Git ne permet pas d'isoler les changements préexistants; fichiers non suivis préservés.

## Conclusion

**P0 reste OPEN.** Ruff, mypy et le test de santé ont passé localement. Les critères de sécurité non implémentés, Gitleaks absent, l'avertissement de dépendance et l'absence d'exécution CI empêchent de prononcer la clôture. P1 est préparée par un plan, mais non commencée.

