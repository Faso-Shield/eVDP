# Installation — eVDP

---

## 1. Prérequis

| Composant | Version minimale | Remarque |
|-----------|------------------|----------|
| Docker Engine | 24.0 | 29.x testé |
| Docker Compose | v2.20 | Plugin `docker compose` |
| RAM | 4 Go | 8 Go recommandés en production |
| Disque | 20 Go | Croît avec les pièces jointes |
| Système | Linux (Debian 12 / Ubuntu 22.04+) | Windows/macOS pour le développement |

Pour un développement sans Docker : Python 3.12+ et PostgreSQL 16 (ou SQLite
pour les tests).

---

## 2. Installation avec Docker (recommandé)

### 2.1 Récupération

```bash
git clone https://github.com/wendiouedraogo8-art/evdp.git
cd evdp
```

### 2.2 Configuration

```bash
cp .env.example .env
```

Générez les deux clés (bibliothèque standard Python uniquement) :

```bash
# SECRET_KEY (≥ 50 caractères)
python -c "import secrets; print(secrets.token_urlsafe(64))"

# FIELD_ENCRYPTION_KEY : clé Fernet, 44 caractères terminés par « = »
python -c "import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())"
```

Renseignez au minimum dans `.env` :

| Variable | Rôle |
|----------|------|
| `SECRET_KEY` | Clé de signature Django — **obligatoire**, ≥ 50 caractères |
| `FIELD_ENCRYPTION_KEY` | Clé Fernet des données de versement chiffrées — **obligatoire**, à ne jamais changer une fois des données enregistrées |
| `POSTGRES_PASSWORD` | Mot de passe PostgreSQL — **obligatoire** |
| `SITE_BASE_URL` | Adresse réelle de l'instance (ex. `https://vdp.exemple.bf`) |
| `ALLOWED_HOSTS` | Domaines servis (ex. `vdp.exemple.bf`) |
| `CSRF_TRUSTED_ORIGINS` | Origines complètes (ex. `https://vdp.exemple.bf`) |

> `docker compose` **refuse de démarrer** si `SECRET_KEY`, `FIELD_ENCRYPTION_KEY`
> ou `POSTGRES_PASSWORD` sont absents : c'est
> volontaire, aucune valeur par défaut de production n'existe.
>
> En revanche, il **ne détecte pas** une valeur d'exemple laissée en place :
> vérifiez qu'il n'en reste aucune (la commande ne doit rien afficher) :
>
> ```bash
> grep -n "CHANGEZ-MOI" .env
> ```

### 2.3 Démarrage

```bash
docker compose up -d
docker compose ps          # attendre que tous les services soient "healthy"
docker compose logs -f evdp-web
```

Le conteneur `evdp-web` applique les migrations et collecte les fichiers
statiques au démarrage : aucune commande manuelle n'est nécessaire.

### 2.4 Vérification

```bash
curl -fsS http://localhost/health/    # {"status": "ok", "service": "evdp-web"}
curl -fsS http://localhost/ready/     # database + cache "ok"
```

Ouvrez ensuite **http://localhost/**.

### 2.5 Premier compte administrateur

```bash
docker compose exec evdp-web python manage.py createsuperuser
```

### 2.6 Données de référence (recommandé pour une vraie instance)

```bash
docker compose exec evdp-web python manage.py seed_reference
```

Charge uniquement des données réelles et réutilisables, sans aucun compte
ni mot de passe de démonstration : le référentiel CWE, la politique SLA
nationale par défaut, les textes de la plateforme (politique de
divulgation, à propos), l'ANSSI-BF, le CSIRT National, et les 15
principaux ministères du Burkina Faso (organisation_type `MINISTRY`,
domaine `.gov.bf` indicatif).

Option `--with-programs` : ajoute un programme VDP national (ANSSI-BF) et
deux programmes Bug Bounty réalistes (CSIRT National ; Ministère de la
Santé), avec périmètre technique, règles de test et matrice de
récompenses en XOF — toujours sans faux compte ni faux dossier.

Idempotente : peut être relancée sans dupliquer. Les coordonnées de
contact de chaque organisation (email officiel, responsable DSI) sont
volontairement laissées vides — à compléter depuis l'interface (fiche de
l'organisation) ou en invitant le vrai responsable
(**Organisations → *nom* → Ajouter un membre**).

### 2.7 Données de démonstration (optionnel, tests uniquement)

```bash
docker compose run --rm evdp-web seed
```

Crée 4 organisations, 9 comptes, 2 programmes, 4 dossiers (dont un
signalement anonyme, sans compte), 1 récompense approuvée et 1 advisory
publié — tous fictifs, avec un mot de passe commun et documenté.

> ⚠️ **Jamais en production.** Ces comptes utilisent un mot de passe connu.
> Si vous avez déjà chargé `seed_reference`, `seed_demo` s'ajoute par-dessus
> sans conflit (organisations différentes).

---

## 3. Mode développement

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d
```

Différences : `DEBUG=True`, code monté en volume (rechargement à chaud), logs
lisibles, et exposition **sur 127.0.0.1 uniquement** de :

| Service | Port local |
|---------|-----------|
| Django (direct) | 8000 |
| Mailpit (emails) | 8025 |
| PostgreSQL | 5432 |
| Redis | 6379 |

---

## 4. Installation sans Docker

```bash
python -m venv .venv
source .venv/bin/activate            # Windows : .venv\Scripts\activate
pip install -r requirements/dev.txt
```

### PostgreSQL

```bash
createdb evdp
createuser evdp --pwprompt
psql -d evdp -c "CREATE EXTENSION IF NOT EXISTS pg_trgm;"
psql -d evdp -c "CREATE EXTENSION IF NOT EXISTS unaccent;"
```

```bash
export DJANGO_SETTINGS_MODULE=config.settings.dev
export SECRET_KEY=dev-only-key
export POSTGRES_HOST=localhost
export POSTGRES_PASSWORD=...
export REDIS_URL=redis://localhost:6379/0
export EMAIL_BACKEND=django.core.mail.backends.console.EmailBackend

python manage.py migrate
python manage.py seed_demo
python manage.py runserver
```

### SQLite (tests rapides uniquement)

```bash
export DB_ENGINE=sqlite
python manage.py migrate && python manage.py runserver
```

> SQLite ne convient qu'au développement. La production cible PostgreSQL.

### Celery en local

```bash
celery -A config worker -l info
celery -A config beat -l info --scheduler django_celery_beat.schedulers:DatabaseScheduler
```

---

## 5. Commandes utiles

```bash
docker compose exec evdp-web python manage.py migrate
docker compose exec evdp-web python manage.py createsuperuser
docker compose exec evdp-web python manage.py shell
docker compose exec evdp-web python manage.py collectstatic --no-input
docker compose run --rm evdp-web seed          # données de démonstration
docker compose run --rm evdp-web migrate       # migrations seules

docker compose logs -f evdp-web evdp-worker
docker compose restart evdp-web
docker compose down                            # arrêt (volumes conservés)
docker compose down -v                         # ⚠️ supprime les données
```

---

## 6. Dépannage

| Symptôme | Cause probable | Résolution |
|----------|----------------|------------|
| `SECRET_KEY est obligatoire` | `.env` absent ou incomplet | `cp .env.example .env` et renseigner les valeurs |
| `evdp-web` et `evdp-worker` redémarrent en boucle, `docker logs evdp-web` affiche `FIELD_ENCRYPTION_KEY invalide` (`Fernet key must be 32 url-safe base64-encoded bytes`) | Valeur d'exemple `CHANGEZ-MOI-cle-fernet` laissée dans `.env` | Générer une clé (§2.2), la reporter dans `.env`, puis `docker compose up -d` |
| `evdp-web` redémarre en boucle | Base non prête | `docker compose logs evdp-db` ; l'entrypoint attend jusqu'à 120 s |
| `/ready/` renvoie 503 | Redis ou PostgreSQL injoignable | `docker compose ps`, vérifier les healthchecks |
| CSS absent | `collectstatic` non exécuté | `docker compose restart evdp-web` |
| Erreur CSRF | Origine absente | Ajouter l'URL complète à `CSRF_TRUSTED_ORIGINS` |
| Pièce jointe refusée | Extension ou signature interdite | Voir `docs/security.md` §5 |
| Emails invisibles | Mailpit non exposé | Utiliser la surcouche `docker-compose.dev.yml` |
| Pas de SLA sur un dossier | Aucune politique SLA | La migration `coordination.0003` en crée une ; vérifier dans l'admin |

Diagnostic complet :

```bash
docker compose ps
docker compose logs --tail=100 evdp-web
docker compose exec evdp-web python manage.py check --deploy
```
