# Preuves de vérification — PhishGuard CI

**Date :** 6 novembre 2026 (Europe/Paris)
**Dépôt examiné :** `C:\Users\Stanislas\Projects\phishguard-ci-api`
**Environnement :** Windows, Python 3.12.10, environnement virtuel local préexistant.

## Contrôles exécutés

Les commandes ci-dessous ont été lancées depuis la racine du dépôt. Aucun service externe ni fournisseur LLM n'a été appelé.

| Contrôle | Commande / version | Résultat observé | Portée et limites |
|---|---|---|---|
| Ruff | `.venv\Scripts\ruff.exe check .` — Ruff 0.17.4 | PASS — `All checks passed!` | Analyse statique locale. |
| mypy | `MYPY_CACHE_DIR=<workspace>\.mypy-cache-phishguard .venv\Scripts\mypy.exe app` — mypy 1.20.2 | PASS — `Success: no issues found in 3 source files` | Le cache a été redirigé hors du dépôt car son emplacement habituel n'était pas inscriptible. |
| pytest | `PYTHONDONTWRITEBYTECODE=1 .venv\Scripts\pytest.exe -W default` — pytest 8.4.2 | PASS — 1 passed | Un avertissement `StarletteDeprecationWarning` subsiste : Starlette indique que son `TestClient` avec httpx est déprécié et recommande `httpx2`. Aucun remplacement de dépendance n'a été effectué sans validation locale de compatibilité. |
| CI YAML | `python -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml', encoding='utf-8'))"` — PyYAML 6.0.3 | PASS — analyse YAML syntaxique | Ne lance pas GitHub Actions. L'accès distant, le runner Linux et l'action Gitleaks n'ont pas été vérifiés. |
| Gitleaks | `gitleaks detect --source . --no-git --redact` | NON EXÉCUTÉ — exécutable absent (`GITLEAKS_NOT_INSTALLED`) | Aucun résultat de scan de secrets n'est affirmé. |
| Installation reproductible | `python -m pip install -e ".[dev]"` | NON EXÉCUTÉ | L'environnement virtuel existait déjà; aucun téléchargement ou changement de dépendances n'a été fait. |
| `git diff --check` | `git diff --check` | Code de sortie 0 | Le dépôt n'a aucun commit et ses fichiers sont non suivis; le diff Git est donc insuffisant pour contrôler l'ensemble des fichiers. Une vérification directe des espaces est à refaire après les modifications. |

Versions installées pertinentes : FastAPI 0.162.0, Starlette 1.10.0, httpx 0.28.1, pydantic-settings 2.16.2. Les contraintes déclarées du projet restent FastAPI `>=0.115,<1.0` et httpx `>=0.27,<1.0`.

## Contrôles produit et sécurité

| Critère | Statut | Motif |
|---|---|---|
| T-L1 — canari de fuite | NOT_IMPLEMENTED / BLOCKED | Aucun pipeline d'analyse ni transfert Hermes n'existe dans l'application présente. |
| T-H1 à T-H10 — barrières Hermes | NOT_IMPLEMENTED / BLOCKED | Aucun client Hermes, outil, shell, navigateur, accès web, filesystem, PostgreSQL ou fournisseur n'est implémenté. Des barrières d'exécution ne peuvent donc pas être testées. |
| T-P1 — stockage Hermes | NOT_IMPLEMENTED / BLOCKED | Aucun stockage ou intégration Hermes n'existe. |
| T-D21 — statut d'approbation | Revue documentaire uniquement | D21 est `SELECTED_FOR_REVIEW`; D16 reste distincte, ouverte et non approuvée. Aucune transmission n'a eu lieu. Ce constat documentaire n'est pas un test d'intégration. |
| `GET /health` | PASS — test local | Le test synthétique existant obtient HTTP 200 et le corps attendu. Il ne valide que le squelette de l'API. |

Les résultats communiqués dans l'ancien rapport avant cette passe ne sont pas repris comme exécutions actuelles. Aucun contenu utilisateur réel, secret ou URL réelle n'a été envoyé à un service tiers.

