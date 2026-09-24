# Diagramme — Workflow v2 (chemin principal et exceptions)

Référence : « Workflow v2 & Matrice RBAC » et `apps/coordination/workflow.py`.
Chaque flèche du chemin principal est **un bouton porté par un seul rôle**.

```mermaid
stateDiagram-v2
    [*] --> SUBMITTED : Déclarant — Soumettre le rapport (≥ 1 PJ)

    state "Réception et qualification" as reception {
        SUBMITTED --> ACKNOWLEDGED : Triage — Accuser réception (72 h)
        ACKNOWLEDGED --> IN_ANALYSIS : Triage — Déclarer recevable (checklist)
        IN_ANALYSIS --> VALIDATION_PENDING : Analyste — Soumettre la qualification (CVSS, CWE)
        VALIDATION_PENDING --> VALIDATED : Coordinateur / analyste senior — Valider (4 yeux, 2 j)
    }

    VALIDATED --> VENDOR_NOTIFIED : Analyste — Transmettre à l'organisation

    state "Remédiation et publication" as remediation {
        VENDOR_NOTIFIED --> REMEDIATION_IN_PROGRESS : DSI — Plan de remédiation (5 j)
        REMEDIATION_IN_PROGRESS --> FIX_AVAILABLE : DSI — Correctif disponible (30/60/90 j)
        FIX_AVAILABLE --> FIX_VERIFIED : Analyste — Confirmer le correctif (5 j)
        FIX_VERIFIED --> ADVISORY_REVIEW : Analyste — Soumettre l'advisory (assaini)
        ADVISORY_REVIEW --> CLOSED : Coordinateur — Publier et clôturer (4 yeux)
    }

    CLOSED --> [*]
```

## Sorties d'exception (actions secondaires, commentaire obligatoire)

```mermaid
stateDiagram-v2
    state "SUBMITTED à IN_ANALYSIS" as early
    early --> NEEDS_INFORMATION : Triage/Analyste — Demander des compléments (SLA suspendu)
    NEEDS_INFORMATION --> early : Déclarant — Envoyer les compléments
    NEEDS_INFORMATION --> REJECTION_PENDING : 30 j sans réponse (automatique)
    early --> REJECTION_PENDING : Triage/Analyste — Proposer rejet ou doublon
    REJECTION_PENDING --> early : Coordinateur — Renvoyer
    REJECTION_PENDING --> REJECTED : Coordinateur — Confirmer (4 yeux)
    REJECTION_PENDING --> DUPLICATE : Coordinateur — Confirmer le doublon
    VALIDATION_PENDING --> IN_ANALYSIS : Coordinateur — Renvoyer à l'auteur
    ADVISORY_REVIEW --> FIX_VERIFIED : Coordinateur — Renvoyer à l'auteur
    FIX_AVAILABLE --> REMEDIATION_IN_PROGRESS : Analyste — Correctif insuffisant
    REJECTED --> [*]
    DUPLICATE --> [*]
```

**Escalade** (étapes 6 et 7) : automatique sur SLA dépassé ou décidée par le
Coordinateur ; le statut ne change pas (alerte rouge, Coordinateur notifié).
Après 90 jours depuis la notification de l'organisation, le Coordinateur peut
décider une **divulgation à échéance** : « Soumettre l'advisory » devient
possible depuis `VENDOR_NOTIFIED` ou `REMEDIATION_IN_PROGRESS`.

## Capacités RBAC exigées

| Action | Capacité | Rôle(s) |
|--------|----------|---------|
| Accuser réception, Déclarer recevable | `TRIAGE_CASE` | `TRIAGER` |
| Soumettre la qualification (et saisir le CVSS) | `SET_SEVERITY` | `CSIRT_ANALYST` |
| Valider la qualification | `VALIDATE_SEVERITY` | `NATIONAL_COORDINATOR`, analyste senior |
| Transmettre, Confirmer le correctif, Correctif insuffisant | `COORDINATE_VENDOR` | `CSIRT_ANALYST` |
| Plan de remédiation, Correctif disponible | `MANAGE_REMEDIATION` | `DSI_ADMIN`, `ORGANIZATION_MANAGER` |
| Soumettre l'advisory | `DRAFT_ADVISORY` | `CSIRT_ANALYST` |
| Publier et clôturer | `PUBLISH_ADVISORY` | `NATIONAL_COORDINATOR` |
| Demander des compléments | `REQUEST_INFORMATION` | `TRIAGER`, `CSIRT_ANALYST` |
| Proposer rejet / doublon | `PROPOSE_REJECTION` | `TRIAGER`, `CSIRT_ANALYST` |
| Confirmer rejet, renvoyer, escalader, divulgation à échéance | `ARBITRATE_CASE` | `NATIONAL_COORDINATOR` |
| Envoyer les compléments | déclarant du dossier | chercheur |

## Colonnes Kanban

| Colonne | États regroupés |
|---------|-----------------|
| Réception | `SUBMITTED`, `ACKNOWLEDGED`, `NEEDS_INFORMATION` |
| Analyse | `IN_ANALYSIS`, `VALIDATION_PENDING`, `REJECTION_PENDING` |
| Validé | `VALIDATED` |
| Remédiation | `VENDOR_NOTIFIED`, `REMEDIATION_IN_PROGRESS`, `FIX_AVAILABLE` |
| Publication | `FIX_VERIFIED`, `ADVISORY_REVIEW` |
| Clos | `CLOSED`, `REJECTED`, `DUPLICATE` |

Chaque carte porte un badge d'échéance : vert, orange à 75 % du SLA de l'étape
en cours, rouge à échéance.
