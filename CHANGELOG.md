# Changelog

## 2026-11-07 — Implémentation MVP P1 (Backend)

- **Pipeline d'analyse déterministe** : extraction URL, détection indicateurs (OTP/PIN, urgence, marques, anomalies structurelles), scoring Modèle 2 (5 catégories, caps 30/20/20/15/15), fiabilité L1-L9, assessment CONCLUSIVE/INCONCLUSIVE.
- **TemplateExplainer** : explicateur de secours 100% déterministe (français), templates par indicateur, limitations contextuelles, recommandations standard, version 1.0.0.
- **Modèles DB** : User, Session, Analysis, AnalysisUrl, AnalysisResult, ApiUsage, ActivityLog avec UUID, JSON, enums, cascade, index.
- **Auth** : JWT (access/refresh), bcrypt, sessions DB, CSRF, cookies HttpOnly/Secure/SameSite, MFA-ready, verrouillage compte.
- **Quotas** : 30 analyses/jour/utilisateur, suivi via ApiUsage, reset minuit UTC.
- **API REST** : `/auth` (register, login, logout, refresh, me, quota, revoke), `/analyses` (create, list, get, delete), `/dashboard` (user stats, recent, admin stats/users/activity).
- **Alembic** : migration initiale `ada6aeab092c` (7 tables, index, FK, enums).
- **Tests** : 76 tests unitaires (URL extraction, indicateurs, scoring, TemplateExplainer) + health check — tous PASS.
- **Qualité** : Ruff PASS, pytest 76/76 PASS, mypy core OK (annotations routes mineures restantes).

## 2026-11-06 — Revue documentaire, étape 2

- Enregistré D21 option B comme `SELECTED_FOR_REVIEW`, avec K1–K3 encore proposés et D16 comme préalable indépendant.
- Enregistré la séparation D22/D16 comme `SELECTED_FOR_REVIEW`; D16 demeure ouverte.
- Enregistré l'option A L1–L8 comme base de travail soumise à revue technique, sans statut d'implémentation ou de test.
- Maintenu F1/F2 (seuils 70/45) comme candidats inactifs, sans adoption.
- Mis à jour le contrat Hermes-FastAPI sur les statuts D16/D21/D22 et les règles candidates L1–L8.
- Ajouté `docs/ETAPE_2_REVUE_DOCUMENTAIRE.md`; P0 n'est pas déclaré clos et ses preuves communiquées restent distinguées des vérifications exécutées.

## 2026-11-06 — Vérifications locales et préparation P1

- Reproduit Ruff, mypy et pytest localement; le rapport P0 distingue les réussites, l'avertissement Starlette/httpx, Gitleaks absent et les critères non implémentés.
- Clarifié D21/K1 : l'état sûr sur installation neuve et la configuration technique sont distincts de tout transfert de contenu réel; D16 reste une approbation indépendante.
- Corrigé l'expression GITHUB_TOKEN du workflow CI; seul le YAML a été analysé localement, aucun run distant n'a été déclenché.
- Créé l'état global, le registre de preuves et le plan P1. P0 demeure OPEN; P1 n'est pas commencée.