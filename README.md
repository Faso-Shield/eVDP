# eVDP

**Plateforme nationale de divulgation coordonnée de vulnérabilités et de
gestion de programmes Bug Bounty**
Projet **CYBER-DEF 2** — ANSSI-BF / CSIRT National

---

eVDP offre aux chercheurs en sécurité, aux citoyens et aux professionnels un
canal **officiel, sécurisé et juridiquement encadré** pour signaler une
vulnérabilité affectant un service public ou une infrastructure numérique
burkinabè — puis aux équipes CSIRT, DSI et organisations un espace commun pour
la trier, la coordonner, la corriger et la publier de manière responsable.

```
Signaler  →  Analyser  →  Coordonner  →  Corriger  →  Publier
```

---

## Sommaire

- [Fonctionnalités](#fonctionnalités)
- [Démarrage rapide](#démarrage-rapide)
- [Comptes de démonstration](#comptes-de-démonstration)
- [Architecture](#architecture)
- [Sécurité](#sécurité)
- [Développement](#développement)
- [Tests](#tests)
- [API](#api)
- [Documentation](#documentation)

---

## Fonctionnalités

### Divulgation coordonnée (CVD)

- Formulaire public de signalement, avec ou sans compte, avec option **anonyme**
- Chiffrement **PGP** optionnel du contenu sensible
- Création automatique d'un dossier `EVDP-2026-000001`
- Machine à états de 24 statuts, transitions strictement contrôlées
- Messagerie sécurisée à 3 niveaux de confidentialité, avec hash d'intégrité
- Pièces jointes validées, stockées sous nom opaque, jamais servies directement
- Échéances **SLA** configurables surveillées par Celery Beat
- Gestion des doublons **sans fuite** vers le déclarant
- Chronologie graphique de chaque dossier

### Bug Bounty

- Programmes avec périmètre structuré (in/out of scope, priorités P1–P4)
- **Matrice de récompenses configurable** — aucun montant codé en dur
- Cycle proposition → revue → approbation → versement
- Séparation stricte des rôles : proposer ≠ approuver ≠ payer
- Aucun flux financier réel n'est déclenché par la plateforme (MVP)

### Publication

- Advisories `EVDP-ADV-2026-000001` — représentation **assainie** du dossier privé
- Aucun PoC, aucune étape de reproduction, aucune URL sensible n'est publiée
- Chronologie publique recopiée uniquement depuis les jalons marqués publics
- Crédit du chercheur respectant son choix d'identité
- CVSS v3.1 calculé hors ligne, CWE et CVE associés

### Pilotage

- Tableaux de bord chercheur, organisation/DSI, CSIRT et **posture nationale**
- Recherche globale sur le périmètre autorisé
- Exports CSV, Excel et PDF soumis aux permissions et audités
- Journal d'audit **immuable** couvrant 40 types d'actions

---

## Démarrage rapide

### Prérequis

- Docker ≥ 24 et Docker Compose v2
- 4 Go de RAM disponibles

### Installation

```bash
git clone <url-du-depot> evdp
cd evdp

# 1. Configuration
cp .env.example .env

# 2. Générer une clé secrète et renseigner les mots de passe
python -c "import secrets; print(secrets.token_urlsafe(64))"
#   → reporter la valeur dans SECRET_KEY
#   → définir POSTGRES_PASSWORD et MINIO_ROOT_PASSWORD

# 3. Démarrer la plateforme
docker compose up -d

# 4. Charger les données de démonstration (optionnel)
docker compose run --rm evdp-web seed

# 5. Créer un compte administrateur
docker compose exec evdp-web python manage.py createsuperuser
```

La plateforme est disponible sur **http://localhost/**.

| Service | URL | Accès |
|---------|-----|-------|
| Plateforme | http://localhost/ | Public |
| Administration Django | http://localhost/admin/ | Superutilisateur |
| Documentation API | http://localhost/api/docs/ | Authentifié |
| Sonde de vivacité | http://localhost/health/ | Public |
| Sonde de disponibilité | http://localhost/ready/ | Public |

### Mode développement

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d
```

Expose en plus, **uniquement sur 127.0.0.1** : Mailpit (`:8025`), console MinIO
(`:9001`), PostgreSQL (`:5432`), Redis (`:6379`), Django (`:8000`).

### Vérification

```bash
docker compose ps                      # tous les services en "healthy"
curl -fsS http://localhost/health/     # {"status": "ok", ...}
curl -fsS http://localhost/ready/      # base et cache disponibles
```

---

## Comptes de démonstration

Créés par `docker compose run --rm evdp-web seed`.
Mot de passe commun : **`EvdpDemo2026!`**

| Rôle | Email | Peut faire |
|------|-------|-----------|
| Administrateur | `admin@evdp.bf` | Tout |
| Coordinateur national | `coordinateur@anssi.bf` | Publier, approuver les récompenses, auditer |
| Analyste CSIRT | `analyste@csirt.bf` | Trier, qualifier, rédiger des advisories |
| Agent de triage | `triage@csirt.bf` | Trier, définir la sévérité |
| DSI ministère | `dsi@sante.gov.bf` | Voir **uniquement** les vulnérabilités de son ministère |
| Responsable organisation | `responsable@education.gov.bf` | Gérer son organisation et ses programmes |
| Chercheur | `researcher@demo.bf` | Soumettre, suivre ses rapports |
| Chercheur Bug Bounty | `bugbounty@demo.bf` | Soumettre, suivre ses récompenses |
| Auditeur | `auditeur@evdp.bf` | Lecture seule + journal d'audit |

> ⚠️ Ces identifiants servent **exclusivement** à la démonstration.
> Ne jamais charger `seed_demo` sur une instance de production.

Le jeu de démonstration contient 4 organisations, 2 programmes (VDP et Bug
Bounty), 3 dossiers à des stades différents, 1 récompense approuvée et
1 advisory publié.

---

## Architecture

```
INTERNET → Nginx → Django/DRF ─┬─ PostgreSQL
                               ├─ Redis ─┬─ Celery worker
                               │         └─ Celery beat
                               ├─ MinIO (pièces jointes, privé)
                               └─ Mailpit (emails)
```

Seul Nginx publie un port. PostgreSQL, Redis et MinIO restent sur le réseau
interne `evdp-backend`.

**Pile technique :** Python 3.12 · Django 5.2 · Django REST Framework ·
PostgreSQL 16 · Redis 7 · Celery 5 · MinIO · Nginx · Django Templates + HTMX

Voir **[ARCHITECTURE.md](ARCHITECTURE.md)** pour les décisions structurantes.

---

## Sécurité

La plateforme traite des vulnérabilités non corrigées : sa compromission
équivaudrait à une compromission nationale. Les principes suivants sont
appliqués sans exception.

| Principe | Mise en œuvre |
|----------|---------------|
| **Privé par défaut** | Aucun rapport n'est publié automatiquement ; seul un advisory assaini est publiable |
| **Moindre privilège** | 10 rôles, 23 capacités, isolation appliquée au niveau du queryset |
| **Tout est auditable** | Journal append-only ; les refus sont journalisés durablement |
| **Ne jamais exposer les données internes** | La vue publique est un objet distinct du dossier privé |
| **Aucune clé privée côté serveur** | Seules les clés publiques PGP sont stockées ; tout bloc privé est refusé |

Mesures principales : Argon2, CSP, HSTS, CSRF, cookies durcis, rate limiting
applicatif **et** bordure, validation des uploads (extension + MIME +
signature binaire), Markdown assaini contre le XSS stocké, réponse **404 au
lieu de 403** pour ne pas confirmer l'existence d'un dossier hors périmètre.

Voir **[docs/security.md](docs/security.md)** pour la correspondance OWASP
ASVS / Top 10 et le modèle de menaces.

**Signaler une vulnérabilité sur eVDP lui-même :** utilisez le canal décrit
dans `/.well-known/security.txt`.

---

## Développement

### Sans Docker

```bash
python -m venv .venv
source .venv/bin/activate          # Windows : .venv\Scripts\activate
pip install -r requirements/dev.txt

export DB_ENGINE=sqlite            # PostgreSQL reste la cible de production
export SECRET_KEY=dev-only-key
export EMAIL_BACKEND=django.core.mail.backends.console.EmailBackend

python manage.py migrate
python manage.py seed_demo
python manage.py runserver
```

### Qualité

```bash
ruff check .          # lint
black --check .       # formatage
bandit -r apps config # analyse statique de sécurité
pip-audit             # vulnérabilités des dépendances
```

---

## Tests

```bash
# Suite complète (SQLite, rapide)
pytest

# Sur PostgreSQL, comme en production
docker compose run --rm -e DB_ENGINE=postgres evdp-web \
    python -m pytest tests/ -q

# Avec couverture
pytest --cov=apps --cov-report=term-missing
```

**205 tests** couvrant l'authentification, le RBAC, le workflow CVD et Bug
Bounty, les doublons, les pièces jointes, les récompenses, les advisories,
l'API, le journal d'audit, le calculateur CVSS et la sécurité applicative
(XSS, CSRF, IDOR, élévation de privilèges, mass assignment, upload).

Tests d'isolation notables :

- un chercheur A ne peut pas accéder au rapport du chercheur B ;
- une organisation A ne peut pas accéder aux vulnérabilités de l'organisation B ;
- un utilisateur DSI ne peut pas accéder aux fonctions nationales ;
- un utilisateur sans permission ne peut pas télécharger une pièce jointe.

---

## API

API REST versionnée sous `/api/v1/`, documentée par OpenAPI.

```bash
# Soumettre un rapport
curl -X POST http://localhost/api/v1/reports/ \
  -H "X-eVDP-Api-Key: evdp_..." \
  -H "Content-Type: application/json" \
  -d '{
        "title": "Injection SQL sur le portail",
        "vulnerability_type": "SQLI",
        "description": "Description technique détaillée de la vulnérabilité.",
        "affected_organization_name": "Ministère X"
      }'
```

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| `POST` | `/api/v1/reports/` | Soumettre un rapport |
| `GET` | `/api/v1/reports/` | Lister ses dossiers |
| `GET` | `/api/v1/reports/{case_id}/` | Détail d'un dossier |
| `PATCH` | `/api/v1/reports/{case_id}/` | Qualifier (analystes) |
| `POST` | `/api/v1/reports/{case_id}/transition/` | Changer de statut |
| `GET/POST` | `/api/v1/reports/{case_id}/messages/` | Messagerie |
| `GET/POST` | `/api/v1/reports/{case_id}/attachments/` | Pièces jointes |
| `GET/POST` | `/api/v1/programs/` | Programmes |
| `GET` | `/api/v1/advisories/` | Advisories publiés |
| `GET` | `/api/v1/organizations/` | Organisations |
| `GET` | `/api/v1/researchers/` | Chercheurs publics |
| `POST` | `/api/v1/import/csaf/` | Import CSAF 2.0 |
| `GET` | `/api/v1/export/csaf/{advisory_id}/` | Export CSAF 2.0 d'un advisory publié |

Voir **[docs/api.md](docs/api.md)**.

---

## Documentation

| Document | Contenu |
|----------|---------|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Décisions d'architecture, modèle de données |
| [PLAN.md](PLAN.md) | État d'avancement, critères d'acceptation |
| [docs/installation.md](docs/installation.md) | Installation détaillée |
| [docs/deployment.md](docs/deployment.md) | Déploiement en production, TLS |
| [docs/security.md](docs/security.md) | Modèle de menaces, OWASP, durcissement |
| [docs/api.md](docs/api.md) | Référence API |
| [docs/cvd-workflow.md](docs/cvd-workflow.md) | Processus de divulgation coordonnée |
| [docs/bug-bounty.md](docs/bug-bounty.md) | Programmes et récompenses |
| [docs/administration.md](docs/administration.md) | Exploitation quotidienne |
| [docs/backup.md](docs/backup.md) | Sauvegarde et restauration |
| [docs/diagrams/](docs/diagrams/) | Diagrammes Mermaid |

---

## Licence et contexte

Développé dans le cadre du projet **CYBER-DEF 2** pour l'écosystème national de
cybersécurité du Burkina Faso.

Cette plateforme s'inspire **conceptuellement** des processus de coordination
publiés par le CERT/CC (VINCE) — cas de vulnérabilité, coordination
multipartite, publication contrôlée. Aucun code source tiers n'a été repris :
l'ensemble de l'implémentation est original et adapté au contexte burkinabè.
