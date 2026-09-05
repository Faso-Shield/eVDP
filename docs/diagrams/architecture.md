# Diagramme — Architecture de déploiement

```mermaid
graph TB
    subgraph internet["Internet"]
        R["Chercheur / Citoyen"]
        O["Organisation / DSI"]
        A["Analyste CSIRT"]
        API["Intégration machine"]
    end

    subgraph frontend["Réseau evdp-frontend"]
        NGINX["evdp-nginx<br/>TLS · en-têtes · rate limiting"]
    end

    subgraph backend["Réseau evdp-backend (interne, non exposé)"]
        WEB["evdp-web<br/>Django 5.2 + DRF<br/>Gunicorn"]
        DB[("evdp-db<br/>PostgreSQL 16")]
        REDIS[("evdp-redis<br/>cache + broker")]
        WORKER["evdp-worker<br/>Celery"]
        BEAT["evdp-beat<br/>planificateur"]
        MINIO[("evdp-minio<br/>pièces jointes<br/>bucket privé")]
        MAIL["evdp-mailpit<br/>emails"]
        CLAM["evdp-clamav<br/>(optionnel)"]
    end

    R -->|HTTPS| NGINX
    O -->|HTTPS| NGINX
    A -->|HTTPS| NGINX
    API -->|HTTPS + clé d'API| NGINX

    NGINX --> WEB
    WEB --> DB
    WEB --> REDIS
    WEB --> MINIO
    WEB --> MAIL

    REDIS --> WORKER
    REDIS --> BEAT
    BEAT --> REDIS
    WORKER --> DB
    WORKER --> MINIO
    WORKER --> MAIL
    WORKER -.->|analyse antivirus| CLAM

    classDef exposed fill:#0d7a5f,stroke:#08553f,color:#fff
    classDef internal fill:#0b2a4a,stroke:#071c33,color:#fff
    classDef store fill:#123f6d,stroke:#071c33,color:#fff
    class NGINX exposed
    class WEB,WORKER,BEAT,MAIL,CLAM internal
    class DB,REDIS,MINIO store
```

**Points clés**

- Seul `evdp-nginx` publie un port vers l'extérieur.
- PostgreSQL, Redis et MinIO ne sont joignables que depuis le réseau interne.
- Les pièces jointes ne sont jamais servies par Nginx : `/media/` retourne 404.
- ClamAV est optionnel ; en son absence l'analyse est marquée `SKIPPED`.
