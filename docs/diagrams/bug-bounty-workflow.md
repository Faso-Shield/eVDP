# Diagramme — Workflow Bug Bounty

```mermaid
stateDiagram-v2
    [*] --> SUBMITTED : soumission sur un programme Bug Bounty

    SUBMITTED --> RECEIVED
    SUBMITTED --> TRIAGE
    RECEIVED --> ACKNOWLEDGED
    ACKNOWLEDGED --> TRIAGE

    TRIAGE --> NEEDS_INFORMATION
    TRIAGE --> VALIDATED
    TRIAGE --> DUPLICATE
    TRIAGE --> OUT_OF_SCOPE
    TRIAGE --> NOT_APPLICABLE
    TRIAGE --> INFORMATIVE
    TRIAGE --> REJECTED

    NEEDS_INFORMATION --> TRIAGE

    VALIDATED --> SEVERITY_ASSIGNED : capacité SET_SEVERITY
    SEVERITY_ASSIGNED --> BOUNTY_REVIEW : capacité PROPOSE_BOUNTY
    SEVERITY_ASSIGNED --> REMEDIATION
    BOUNTY_REVIEW --> REWARD_APPROVED : capacité APPROVE_BOUNTY
    BOUNTY_REVIEW --> REMEDIATION
    REWARD_APPROVED --> REMEDIATION

    REMEDIATION --> FIX_AVAILABLE
    REMEDIATION --> VERIFICATION
    FIX_AVAILABLE --> VERIFICATION
    VERIFICATION --> FIX_VERIFIED
    VERIFICATION --> REMEDIATION

    FIX_VERIFIED --> DISCLOSURE_SCHEDULED
    FIX_VERIFIED --> CLOSED
    DISCLOSURE_SCHEDULED --> PUBLISHED
    PUBLISHED --> CLOSED
    INFORMATIVE --> CLOSED

    DUPLICATE --> [*]
    OUT_OF_SCOPE --> [*]
    NOT_APPLICABLE --> [*]
    REJECTED --> [*]
    CLOSED --> [*]
```

## Cycle de vie de la récompense

```mermaid
stateDiagram-v2
    [*] --> PENDING : proposition (PROPOSE_BOUNTY)
    PENDING --> UNDER_REVIEW : avis de pairs
    PENDING --> APPROVED : décision directe
    PENDING --> REJECTED
    PENDING --> CANCELLED
    UNDER_REVIEW --> APPROVED : APPROVE_BOUNTY
    UNDER_REVIEW --> REJECTED : APPROVE_BOUNTY
    UNDER_REVIEW --> CANCELLED
    APPROVED --> PAID : RECORD_PAYMENT
    APPROVED --> CANCELLED
    REJECTED --> [*]
    CANCELLED --> [*]
    PAID --> [*]
```

**Séparation des responsabilités :** proposer, approuver et enregistrer un
versement relèvent de trois capacités distinctes. Un analyste qui propose une
récompense ne peut pas l'approuver.

**Aucun paiement réel** n'est déclenché par la plateforme : `PAID` enregistre
une trace comptable rapprochée d'un versement effectué hors ligne.
