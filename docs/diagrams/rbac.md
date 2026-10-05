# Diagramme — RBAC (workflow v2)

Chaque étape du workflow a une seule capacité propriétaire. Le super admin
administre la plateforme mais ne voit **aucun** dossier (ISO/IEC 27001 A.5.3).

```mermaid
graph LR
    subgraph national["Rôles nationaux"]
        SA["SUPER_ADMIN<br/>(aucun dossier)"]
        NC["NATIONAL_COORDINATOR"]
        CA["CSIRT_ANALYST<br/>(+ senior : VALIDATE_SEVERITY)"]
        TR["TRIAGER"]
        AU["AUDITOR<br/>(lecture seule)"]
    end

    subgraph orga["Rôles organisation — dès l'étape 5"]
        DSI["DSI_ADMIN"]
        OM["ORGANIZATION_MANAGER"]
    end

    subgraph chercheurs["Chercheurs — leurs rapports uniquement"]
        SR["SECURITY_RESEARCHER"]
        BR["BUG_BOUNTY_RESEARCHER"]
        PU["PUBLIC_USER"]
    end

    subgraph caps["Capacités de workflow"]
        C1["TRIAGE_CASE<br/>étapes 1-2"]
        C2["SET_SEVERITY<br/>CVSS, étape 3"]
        C3["VALIDATE_SEVERITY<br/>étape 4"]
        C4["COORDINATE_VENDOR<br/>étapes 5, 8"]
        C5["MANAGE_REMEDIATION<br/>étapes 6, 7"]
        C6["DRAFT_ADVISORY<br/>étape 9"]
        C7["PUBLISH_ADVISORY<br/>étape 10"]
        C8["PROPOSE_BOUNTY<br/>B1"]
        C9["APPROVE_BOUNTY<br/>B2"]
        C10["REQUEST_INFORMATION<br/>PROPOSE_REJECTION"]
        C11["ARBITRATE_CASE<br/>rejet, renvoi, escalade"]
        C12["SUBMIT_REPORT"]
    end

    subgraph admin["Capacités d'administration"]
        A1["MANAGE_USERS"]
        A2["MANAGE_ALL_ORGANIZATIONS"]
        A3["MANAGE_PROGRAM"]
        A4["VIEW_AUDIT_LOG"]
    end

    SA --> A1 & A2 & A3
    NC --> C3 & C7 & C9 & C11 & A1 & A2 & A3 & A4
    CA --> C2 & C4 & C6 & C8 & C10 & A3
    TR --> C1 & C10
    AU --> A4
    DSI --> C5 & A3
    OM --> C5 & A3
    SR --> C12
    BR --> C12
    PU --> C12

    classDef nat fill:#0b2a4a,stroke:#071c33,color:#fff
    classDef org fill:#123f6d,stroke:#071c33,color:#fff
    classDef res fill:#0d7a5f,stroke:#08553f,color:#fff
    class SA,NC,CA,TR,AU nat
    class DSI,OM org
    class SR,BR,PU res
```

La matrice de visibilité des données (qui lit quoi) est détaillée dans
`docs/cvd-workflow.md`, section 7, et implémentée dans
`apps/coordination/visibility.py`.

## Trois barrières d'autorisation

```mermaid
flowchart TD
    REQ["Requête HTTP"] --> AUTH{"Authentifié ?"}
    AUTH -->|non| LOGIN["Redirection connexion / 401"]
    AUTH -->|oui| QS["1. Queryset<br/>Case.objects.visible_to(user)"]
    QS --> OBJ{"2. Objet<br/>case.is_visible_to(user)"}
    OBJ -->|non| NF["404 + audit DENIED<br/>(jamais 403 : ne pas confirmer l'existence)"]
    OBJ -->|oui| CAP{"3. Capacité<br/>user.has_capability(...)"}
    CAP -->|non| FORBID["403 + audit DENIED"]
    CAP -->|oui| WF{"4. Pré-requis et quatre yeux<br/>check_transition()"}
    WF -->|non| REF["Refus listant ce qui manque + audit DENIED"]
    WF -->|oui| SVC["Service métier<br/>workflow + audit + notification"]
    SVC --> OK["Réponse"]
```
