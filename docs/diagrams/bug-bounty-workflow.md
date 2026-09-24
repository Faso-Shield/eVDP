# Diagramme — Workflow Bug Bounty

Workflow v2 : le dossier suit le chemin principal commun (voir
`docs/diagrams/cvd-workflow.md`) ; la prime avance sur une branche
parallèle, portée par `Case.bounty_status`.

```mermaid
stateDiagram-v2
    [*] --> UNDETERMINED : soumission
    UNDETERMINED --> BOUNTY_ELIGIBLE : étape 4 validée (programme Bug Bounty)
    UNDETERMINED --> NOT_ELIGIBLE : étape 4 validée (VDP)
    BOUNTY_ELIGIBLE --> BOUNTY_PROPOSED : B1 Analyste — Proposer la prime
    BOUNTY_PROPOSED --> BOUNTY_CREDITED : B2 Coordinateur — Approuver et créditer le Wallet (4 yeux)
    BOUNTY_PROPOSED --> BOUNTY_ELIGIBLE : Renvoyer (commentaire)
    BOUNTY_PROPOSED --> NOT_ELIGIBLE : Rejeter
    BOUNTY_ELIGIBLE --> NOT_ELIGIBLE : Déclarer non éligible
    BOUNTY_CREDITED --> [*]
    NOT_ELIGIBLE --> [*]
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
