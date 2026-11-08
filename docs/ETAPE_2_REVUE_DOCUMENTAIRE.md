# Étape 2 — Revue documentaire PhishGuard CI

**Date :** 6 novembre 2026
**Périmètre :** revue documentaire seulement; aucun code applicatif modifié, aucun fournisseur/LLM/service externe activé, P1 non démarrée.

## Fichiers et sources effectivement examinés

Fichiers présents et lus dans le dépôt `C:\Users\Stanislas\Projects\phishguard-ci-api` :

- `docs/CONTRAT_HERMES_FASTAPI_consolide.md`
- `docs/P0-validation-report.md`
- `DECISIONS.md`
- `CHANGELOG.md`
- `README.md` et `SECURITY.md` (contexte de périmètre et de contrôle)
- `Documents/PhishGuard CI/v2.2/README.md`

Avant la création de ce rapport, l'inventaire récursif a trouvé seulement deux fichiers dans `docs/`. `Documents/` ne contient pas les documents sources annoncés par son README. Les fichiers PRD, Agent Spec et Orchestrateur ont été lus depuis les pièces jointes de la conversation référencée (copies temporaires locales); elles ne sont pas présentes dans le dépôt et n'ont donc pas été modifiées :

- `PRD_PhishGuard_CI_Agent_v2.2.md`
- `AGENT_SPEC_PhishGuard_CI_v1.1.md`
- `ORCHESTRATEUR_PhishGuard_CI_v1.1.md`

Le rapport P0 du dépôt indique lui-même que les trois documents officiels sont PRD, Agent Spec et Orchestrateur. La comparaison avec ces sources est donc documentaire, mais les versions modifiées ne peuvent pas être resynchronisées dans ce checkout tant que les fichiers ne s'y trouvent pas.

## Tableau de cohérence

| Sujet | Constat de la revue | Statut |
|---|---|---|
| Autorité et rôles | PRD, Agent Spec, Orchestrateur et contrat concordent : FastAPI orchestre et fixe le score; Hermes ne fait qu'expliquer; TemplateExplainer est le seul secours. | Cohérent |
| Données et C7 | Les sources concordent sur la minimisation, le caractère éphémère des extraits C7 et l'absence de contenu réel transmis avant approbation de D16. | Cohérent, D16 ouverte |
| D21 | L'utilisateur a choisi B pour revue. Les sources conservent K1 (`HERMES_ENABLED=false` par défaut) ainsi que K2/K3 comme propositions. La portée de B et le statut de K1 doivent être réconciliés; le choix ne vaut pas approbation finale de production. | À résoudre avant validation finale |
| D22 / D16 | L'utilisateur exige une approbation explicite et séparée de D16. Les sources indiquent D22 comme proposée et disent qu'un enregistrement seul ne prouve pas la conformité du fournisseur. D16 reste indépendante et ouverte. | Choix inscrit; D16 en attente |
| Fiabilité L1–L8 | L'option A retient les règles proposées comme base de travail. Les cas et niveaux sont maintenant consignés dans le contrat, sans les présenter comme implémentés/testés. La précédence des cas chevauchants et la sémantique de `UNKNOWN`/`ERROR` ne sont pas définies par les sources. | Base retenue pour revue technique |
| Scoring F1/F2 | Le PRD décrit 70 et 45 comme candidats à tester, non validés. Aucun choix utilisateur; ils restent inactifs et non adoptés. | Cohérent, décision ouverte |
| Périmètre fournisseurs | Les documents disent que les fournisseurs externes restent conditionnels et désactivés avant vérifications de conditions, transferts et rétention. | Cohérent; non activés |
| P0 | Le rapport local se déclare partiellement validé et ne prononce pas la clôture. Il sépare déjà résultats communiqués et contrôles non exécutés. Aucun élément consulté ne justifie de relever ce statut. | Non clos |
| Présence des sources dans le dépôt | PRD, Agent Spec et Orchestrateur ne sont pas dans le dépôt; le dossier `Documents/` n'a qu'un README. Le rapport P0 local affirme pourtant que ces documents sont les références officielles. | Lacune de distribution documentaire |

## Modifications réalisées

- `DECISIONS.md` : ajout des choix D21, D22/D16 et L1–L8 au statut `SELECTED_FOR_REVIEW`; D16 reste ouverte; F1/F2 restent des candidats inactifs.
- `docs/CONTRAT_HERMES_FASTAPI_consolide.md` : clarification de l'indépendance D22/D16; consignation de l'orientation D21 et de l'ambiguïté K1; ajout des règles candidates L1–L8 et des cas limites restant à spécifier.
- `CHANGELOG.md` : ajout de cette passe documentaire.
- `docs/ETAPE_2_REVUE_DOCUMENTAIRE.md` : création du présent rapport.

Aucun autre fichier n'a été modifié. Aucune source originale n'a été supprimée, renommée ou déplacée. Aucun code applicatif n'a été touché.

## Choix, approbations et points en attente

- **D21 option B :** choisie par l'utilisateur; `SELECTED_FOR_REVIEW`, pas d'approbation définitive. La cohérence de K1–K3 reste à résoudre.
- **D22 / D16 :** séparation acceptée; `SELECTED_FOR_REVIEW`. D16 n'est pas approuvée.
- **D16 :** ouverte; approbation juridique, contractuelle et de protection des données encore requise concernant rétention, entraînement, sous-traitants et traitement/transfert.
- **L1–L8 option A :** base de travail retenue; `SELECTED_FOR_REVIEW`; revue technique et formalisation des priorités/cas limites requises.
- **F1/F2 :** aucun choix; seuils 70 et 45 candidats inactifs, non adoptés.
- **P1 :** non démarrée.

## P0 — preuves disponibles et limites

Cette passe n'a exécuté aucun contrôle P0 ni test. Les seules preuves de contrôles présentes dans les fichiers examinés sont celles que le rapport local attribue au porteur du projet; elles n'ont pas été réexécutées pour cette revue.

| Catégorie | Éléments constatés |
|---|---|
| Résultats communiqués dans `docs/P0-validation-report.md` | Ruff `All checks passed!`; mypy `Success: no issues found in 4 source files`; pytest `1 passed, 1 warning`; Gitleaks `no leaks found`. Le rapport les qualifie explicitement de résultats communiqués, pas d'exécutions de son rédacteur. |
| Avertissement rapporté | Avertissement Starlette/httpx à examiner; aucune correction ni sortie détaillée n'est fournie dans le rapport. |
| Contrôles non exécutés selon le rapport | T-L1 (canari de fuite); T-H1 à T-H10 (barrières Hermes); T-P1 (stockage Hermes); T-D21 (approbation D16/D21); tests fonctionnels P1. |
| Élément décrit, sans preuve de fonctionnement produit | `GET /health` est documenté comme présent dans le squelette; cela ne démontre pas le fonctionnement produit. |
| Exécution de cette revue | Aucun test, Ruff, mypy ou Gitleaks lancé. Aucune preuve de CI, stockage, auth, quotas, CORS ou exposition réseau collectée ici. |

**Statut P0 : non clos.** Les résultats communiqués sont encourageants mais non reproduits dans cette passe, l'avertissement reste à traiter et les tests de sécurité listés sont non exécutés. Les documents examinés ne permettent pas de déclarer les barrières prouvées.

## Prérequis précis avant P1

1. Rendre disponibles dans le dépôt les versions de référence PRD, Agent Spec et Orchestrateur, puis synchroniser avec elles les choix consignés ici sans écraser les originaux.
2. Résoudre la portée de D21 option B avec K1–K3 et documenter l'état d'activation permis pour chaque environnement; ne pas assimiler ce choix à une approbation de D16.
3. Faire examiner et approuver D16 séparément : fournisseur et contrat, rétention, entraînement, sous-traitants, traitement/transfert et exigences juridiques/protection des données. Garder tout envoi de contenu réel bloqué jusque-là.
4. Faire une revue technique L1–L8 qui définit l'applicabilité, les priorités entre cas qui se chevauchent et le traitement des contrôles désactivés, `UNKNOWN` et `ERROR`; formaliser ensuite les tests avant d'annoncer une implémentation.
5. Garder F1/F2 inactifs jusqu'à essais synthétiques documentés et décision explicite sur les seuils.
6. Reproduire et archiver les contrôles P0 annoncés (Ruff, mypy, pytest, Gitleaks), examiner l'avertissement Starlette/httpx et exécuter T-L1, T-H1–T-H10, T-P1 et T-D21. Ne déclarer les tests réussis qu'avec des sorties conservées.
7. Vérifier CI, configuration, authentification, quotas, CORS et persistance avant toute exposition réseau; consigner les preuves et les limites.

Aucune donnée réelle n'a été envoyée à un LLM, aucun fournisseur/service externe n'a été activé, P1 n'a pas été lancée et aucun commit/push n'a été effectué pendant cette passe.
