# DECISIONS

Ce registre conserve les choix exprimés sans les transformer en approbations définitives. Les décisions en attente restent soumises à revue et validation explicite.

## D21 — Activation par défaut de Hermes

- Choix utilisateur : option B — Hermes peut être activé par défaut après configuration technique.
- Statut : `SELECTED_FOR_REVIEW`.
- Ce choix n'est pas une approbation définitive de l'activation en production ni des modalités K1–K3.
- K1 (`HERMES_ENABLED=false` sur une installation neuve) reste compatible avec une éventuelle activation après configuration technique; cette interprétation et les modalités K2/K3 restent à valider avant toute décision finale. L'activation/configuration technique ne permet pas de transmettre du contenu réel.
- D16 demeure un préalable indépendant à tout envoi de contenu réel à un LLM.

## D22 / D16 — Séparation des approbations

- Choix utilisateur : D22 ne vaut jamais approbation automatique de D16; D16 doit être approuvée explicitement et séparément.
- Statut : `SELECTED_FOR_REVIEW`.
- D16 reste ouverte jusqu'à l'examen et l'approbation des conditions juridiques, contractuelles, de rétention, d'entraînement, de sous-traitance et de protection des données.
- Aucune donnée réelle ne peut être transmise à un LLM tant que D16 n'est pas approuvée.

## Fiabilité L1–L8 — Base proposée

- Choix utilisateur : option A — retenir les règles proposées comme base de travail à intégrer après revue technique.
- Statut : `SELECTED_FOR_REVIEW`.
- Les règles ne sont ni implémentées ni testées sur la base des preuves disponibles.
- Les cas de chevauchement, l'ordre d'application et la définition des contrôles applicables restent à préciser en revue technique. Voir `docs/CONTRAT_HERMES_FASTAPI_consolide.md`.

## F1 / F2 — Seuils de score

- Aucun choix utilisateur consigné.
- Les seuils 70 (F1) et 45 (F2) restent des propositions/candidats inactifs à évaluer; ils ne sont pas adoptés.
