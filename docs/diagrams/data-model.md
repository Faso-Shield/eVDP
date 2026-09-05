# Diagramme — Modèle de données

```mermaid
erDiagram
    USER ||--o{ ORGANIZATION_MEMBER : "appartient à"
    ORGANIZATION ||--o{ ORGANIZATION_MEMBER : "compte"
    ORGANIZATION ||--o{ SECURITY_CONTACT : "publie"
    USER ||--o| RESEARCHER_PROFILE : "possède"
    RESEARCHER_PROFILE ||--o{ REPUTATION_EVENT : "accumule"

    ORGANIZATION ||--o{ PROGRAM : "porte"
    PROGRAM ||--o{ PROGRAM_SCOPE : "délimite"
    PROGRAM ||--o{ PROGRAM_RULE : "encadre"
    PROGRAM ||--o| REWARD_POLICY : "récompense selon"
    REWARD_POLICY ||--o{ REWARD_TIER : "détaille"
    PROGRAM }o--o| SLA_POLICY : "applique"

    USER ||--o{ VULNERABILITY_REPORT : "déclare"
    ORGANIZATION ||--o{ VULNERABILITY_REPORT : "est affectée par"
    PROGRAM ||--o{ VULNERABILITY_REPORT : "reçoit"

    VULNERABILITY_REPORT ||--|| CASE : "ouvre"
    CASE ||--o{ CASE_STATUS_HISTORY : "trace"
    CASE ||--o{ CASE_ASSIGNMENT : "assigne"
    CASE ||--o{ CASE_PARTICIPANT : "autorise"
    CASE ||--o{ CASE_MESSAGE : "porte"
    CASE ||--o{ CASE_TIMELINE_EVENT : "chronologie"
    CASE ||--o{ SLA_EVENT : "échéances"
    CASE ||--o{ ATTACHMENT : "pièces jointes"
    CASE_MESSAGE ||--o{ ATTACHMENT : "joint"
    CASE ||--o| CASE : "doublon de"
    CASE }o--o| CWE : "classée"
    CASE }o--o| CVE : "référencée"

    CASE ||--o| BOUNTY : "récompense"
    BOUNTY ||--o{ BOUNTY_REVIEW : "revue par"
    BOUNTY ||--o{ BOUNTY_PAYMENT : "versement"
    USER ||--o{ BOUNTY : "bénéficie"

    CASE ||--o{ ADVISORY : "publication"
    ADVISORY ||--o{ ADVISORY_TIMELINE_ENTRY : "chronologie publique"
    ADVISORY ||--o{ ADVISORY_REFERENCE : "références"
    ADVISORY }o--o| CVE : "identifie"
    ADVISORY }o--o| CWE : "classe"

    USER ||--o{ NOTIFICATION : "reçoit"
    USER ||--o{ AUDIT_LOG : "génère"
    USER ||--o{ API_KEY : "détient"
    SLA_POLICY ||--o{ SLA_EVENT : "définit"

    USER {
        uuid id PK
        string email UK
        string role "10 rôles RBAC"
        bool email_verified
        text pgp_public_key "clé publique uniquement"
    }

    VULNERABILITY_REPORT {
        uuid id PK
        string title
        text description "Markdown"
        text proof_of_concept "sensible"
        text pgp_payload "bloc chiffré"
        bool is_anonymous
        string submitter_ip_hash "IP jamais en clair"
    }

    CASE {
        uuid id PK
        string case_id UK "EVDP-2026-000001"
        string workflow "VDP | BUG_BOUNTY"
        string status "24 états"
        string severity
        decimal cvss_score
        int priority_score
        date disclosure_date
    }

    ADVISORY {
        uuid id PK
        string advisory_id UK "EVDP-ADV-2026-000001"
        text summary "public, assaini"
        string status "DRAFT→PUBLISHED"
        string credit "selon choix du chercheur"
    }

    ATTACHMENT {
        uuid id PK
        string original_filename "métadonnée d'affichage"
        string storage_name "UUID opaque"
        string sha256
        string scan_status
    }

    AUDIT_LOG {
        uuid id PK
        datetime timestamp
        string action "40 types"
        string result "SUCCESS|FAILURE|DENIED"
        json metadata "secrets caviardés"
    }
```

## Séparation Rapport / Case

```mermaid
flowchart LR
    subgraph prive["Domaine privé"]
        R["VulnerabilityReport<br/>déclaration brute, non réécrite"]
        C["Case<br/>workflow, sévérité retenue,<br/>assignation, SLA"]
        M["CaseMessage<br/>3 niveaux de confidentialité"]
        A["Attachment<br/>preuves de concept"]
    end

    subgraph public["Domaine public"]
        AD["Advisory<br/>représentation assainie"]
    end

    R -->|1:1 à la soumission| C
    C --> M
    C --> A
    C -.->|"rédaction humaine<br/>champs non sensibles uniquement"| AD

    classDef p fill:#8b1a13,stroke:#5c110d,color:#fff
    classDef pub fill:#0d7a5f,stroke:#08553f,color:#fff
    class R,C,M,A p
    class AD pub
```

Le trait pointillé est le **seul** chemin du privé vers le public, et il exige
une action humaine habilitée. Aucun champ sensible (preuve de concept, étapes
de reproduction, URL cible, identifiant de dossier) ne le traverse.
