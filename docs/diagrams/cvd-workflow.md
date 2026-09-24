# Diagramme — Workflow v2 (SPEC-eVDP-2026-V2)

Onze étapes principales, un bouton et un seul propriétaire par étape. Les
sorties d'exception sont des actions secondaires, jamais des boutons de
validation. Source : `apps/coordination/workflow.py` (`VDP_TRANSITIONS`).

```mermaid
stateDiagram-v2
    [*] --> SUBMITTED : Déclarant — Soumettre le rapport (≥ 1 PJ)

    SUBMITTED --> ACKNOWLEDGED : Triage — Accuser réception (SLA 72 h)
    ACKNOWLEDGED --> IN_ANALYSIS : Triage — Déclarer recevable
    IN_ANALYSIS --> VALIDATION_PENDING : Analyste — Soumettre la qualification (SLA 5 j avec l'étape 2)
    VALIDATION_PENDING --> VALIDATED : Coordinateur / analyste senior — Valider (4 yeux, SLA 2 j)
    VALIDATED --> VENDOR_NOTIFIED : Analyste — Transmettre à l'organisation
    VENDOR_NOTIFIED --> REMEDIATION_IN_PROGRESS : DSI — Plan de remédiation (SLA 5 j)
    REMEDIATION_IN_PROGRESS --> FIX_AVAILABLE : DSI — Correctif disponible (30/60/90 j)
    FIX_AVAILABLE --> FIX_VERIFIED : Analyste — Confirmer le correctif (SLA 5 j)
    FIX_VERIFIED --> ADVISORY_REVIEW : Analyste — Soumettre l'advisory (assaini)
    ADVISORY_REVIEW --> CLOSED : Coordinateur — Publier et clôturer (4 yeux, prime réglée)
    CLOSED --> [*]

    state "Exceptions (actions secondaires, commentaire obligatoire)" as exc {
        NEEDS_INFORMATION
        REJECTION_PENDING
    }
    SUBMITTED --> NEEDS_INFORMATION : Demander des compléments
    ACKNOWLEDGED --> NEEDS_INFORMATION
    IN_ANALYSIS --> NEEDS_INFORMATION
    NEEDS_INFORMATION --> IN_ANALYSIS : Déclarant — Envoyer les compléments (retour à l'étape d'origine)
    NEEDS_INFORMATION --> REJECTION_PENDING : 30 j sans réponse (automatique)

    SUBMITTED --> REJECTION_PENDING : Proposer le rejet / doublon
    ACKNOWLEDGED --> REJECTION_PENDING
    IN_ANALYSIS --> REJECTION_PENDING
    REJECTION_PENDING --> REJECTED : Coordinateur — Confirmer (4 yeux)
    REJECTION_PENDING --> DUPLICATE : Coordinateur — Confirmer (motif doublon)
    REJECTION_PENDING --> IN_ANALYSIS : Coordinateur — Renvoyer à l'étape d'origine

    VALIDATION_PENDING --> IN_ANALYSIS : Renvoyer à l'analyste
    ADVISORY_REVIEW --> FIX_VERIFIED : Renvoyer à l'analyste
    FIX_AVAILABLE --> REMEDIATION_IN_PROGRESS : Correctif insuffisant

    REJECTED --> [*]
    DUPLICATE --> [*]
```

L'escalade (automatique sur SLA dépassé, ou manuelle par le Coordinateur aux
étapes 6 et 7) ne change pas le statut : elle lève une alerte rouge et
notifie la coordination nationale.

## Branche Bug Bounty (champ `Case.bounty_status`)

```mermaid
stateDiagram-v2
    [*] --> UNDETERMINED
    UNDETERMINED --> BOUNTY_ELIGIBLE : validation (programme Bug Bounty)
    UNDETERMINED --> NOT_ELIGIBLE : validation (VDP)
    BOUNTY_ELIGIBLE --> BOUNTY_PROPOSED : Analyste — Proposer la prime (B1)
    BOUNTY_PROPOSED --> BOUNTY_CREDITED : Coordinateur — Approuver et créditer le Wallet (B2, 4 yeux)
    BOUNTY_PROPOSED --> BOUNTY_ELIGIBLE : Coordinateur — Renvoyer
    BOUNTY_PROPOSED --> NOT_ELIGIBLE : Coordinateur — Rejeter
    BOUNTY_ELIGIBLE --> NOT_ELIGIBLE : Coordinateur — Déclarer non éligible
```

« Publier et clôturer » reste grisé tant que la prime n'est ni
`BOUNTY_CREDITED` ni `NOT_ELIGIBLE`.

## Contrôles serveur (`check_transition`)

1. La transition existe pour le statut courant.
2. Le dossier est dans le périmètre de l'utilisateur (sinon 404).
3. L'utilisateur possède la capacité de la transition.
4. Les pré-requis de l'étape sont remplis (liste explicite en cas d'échec).
5. Quatre yeux : l'acteur diffère de l'auteur de l'étape précédente.
6. Commentaire obligatoire (étapes 4, 10, B2 et toutes les exceptions).

Le refus est audité hors transaction ; l'application est atomique et auditée.

## Colonnes Kanban

| Colonne | États regroupés |
|---------|-----------------|
| Réception | `SUBMITTED`, `ACKNOWLEDGED` |
| Analyse | `IN_ANALYSIS`, `NEEDS_INFORMATION`, `VALIDATION_PENDING`, `REJECTION_PENDING` |
| Validé | `VALIDATED`, `VENDOR_NOTIFIED` |
| Remédiation | `REMEDIATION_IN_PROGRESS`, `FIX_AVAILABLE` |
| Publication | `FIX_VERIFIED`, `ADVISORY_REVIEW` |
| Clos | `CLOSED`, `REJECTED`, `DUPLICATE` |

Chaque carte porte un badge d'échéance : vert, orange à 75 % du délai,
rouge à échéance.

## Migration depuis les 24 statuts v1

Voir `apps/coordination/migrations/0008_workflow_v2_data.py` pour le mapping
complet (ex. `RECEIVED` → `SUBMITTED`, `TRIAGE` → `IN_ANALYSIS`,
`VENDOR_CONTACTED`/`VENDOR_ACKNOWLEDGED` → `VENDOR_NOTIFIED`, `PUBLISHED` →
`CLOSED`, `OUT_OF_SCOPE`/`NOT_APPLICABLE`/`INFORMATIVE` → `REJECTED`).
