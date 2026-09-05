# Déploiement en production — eVDP

---

## 1. Cible

Serveur Linux (Debian 12 / Ubuntu 22.04 LTS ou supérieur), 4 vCPU, 8 Go de
RAM, 100 Go de disque, Docker Engine ≥ 24 et Compose v2.

---

## 2. Préparation du serveur

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y ca-certificates curl gnupg ufw fail2ban

# Docker (dépôt officiel)
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker "$USER"
```

### Pare-feu

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp        # restreindre à l'IP d'administration
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

Aucun autre port n'a besoin d'être ouvert : PostgreSQL, Redis et MinIO restent
sur le réseau Docker interne.

### Utilisateur applicatif

```bash
sudo useradd --create-home --shell /bin/bash evdp
sudo usermod -aG docker evdp
sudo -iu evdp
```

---

## 3. Installation

```bash
git clone <url-du-depot> /home/evdp/evdp
cd /home/evdp/evdp
cp .env.example .env
chmod 600 .env
```

### Configuration de production

```dotenv
DJANGO_SETTINGS_MODULE=config.settings.prod
SECRET_KEY=<64 caractères générés aléatoirement>
DEBUG=False
ALLOWED_HOSTS=vdp.exemple.bf
CSRF_TRUSTED_ORIGINS=https://vdp.exemple.bf

SECURE_SSL_REDIRECT=True
SECURE_HSTS_SECONDS=31536000

POSTGRES_PASSWORD=<mot de passe fort>
MINIO_ROOT_PASSWORD=<mot de passe fort>
MINIO_SECRET_KEY=<identique>

EMAIL_HOST=smtp.exemple.bf
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_USER=evdp@exemple.bf
EMAIL_PASSWORD=<mot de passe>
DEFAULT_FROM_EMAIL=eVDP <no-reply@exemple.bf>

EVDP_NATIONAL_TEAM=ANSSI-BF / CSIRT National
EVDP_CONTACT_EMAIL=vdp@anssi.bf

CLAMAV_HOST=evdp-clamav        # fortement recommandé
LOG_LEVEL=INFO
LOG_FORMAT=json
```

Génération de la clé :

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(64))"
```

> Mailpit est un outil de développement. **Remplacez-le par un vrai relais
> SMTP** en production et retirez le service du fichier compose.

---

## 4. TLS

### Certificat Let's Encrypt

```bash
sudo apt install -y certbot
sudo certbot certonly --standalone -d vdp.exemple.bf
sudo mkdir -p /home/evdp/evdp/docker/nginx/certs
sudo cp /etc/letsencrypt/live/vdp.exemple.bf/fullchain.pem \
        /home/evdp/evdp/docker/nginx/certs/evdp.crt
sudo cp /etc/letsencrypt/live/vdp.exemple.bf/privkey.pem \
        /home/evdp/evdp/docker/nginx/certs/evdp.key
sudo chown -R evdp:evdp /home/evdp/evdp/docker/nginx/certs
sudo chmod 600 /home/evdp/evdp/docker/nginx/certs/evdp.key
```

### Activation

1. Décommentez le bloc `server { listen 443 ssl; … }` dans
   `docker/nginx/conf.d/evdp.conf` et reprenez-y les blocs `location`.
2. Remplacez le contenu du serveur port 80 par une redirection :

```nginx
server {
    listen 80;
    server_name vdp.exemple.bf;
    location /.well-known/acme-challenge/ { root /var/www/certbot; }
    location / { return 301 https://$host$request_uri; }
}
```

3. Montez le répertoire de certificats dans le service `evdp-nginx` :

```yaml
    volumes:
      - ./docker/nginx/certs:/etc/nginx/certs:ro
```

4. Publiez le port 443 et passez `SECURE_SSL_REDIRECT=True`,
   `SECURE_HSTS_SECONDS=31536000`.

### Renouvellement

```bash
sudo crontab -e
0 3 * * 1 certbot renew --quiet --deploy-hook \
  "cp /etc/letsencrypt/live/vdp.exemple.bf/fullchain.pem /home/evdp/evdp/docker/nginx/certs/evdp.crt && \
   cp /etc/letsencrypt/live/vdp.exemple.bf/privkey.pem /home/evdp/evdp/docker/nginx/certs/evdp.key && \
   cd /home/evdp/evdp && docker compose restart evdp-nginx"
```

---

## 5. Démarrage

```bash
docker compose build
docker compose up -d
docker compose ps
docker compose exec evdp-web python manage.py createsuperuser
docker compose exec evdp-web python manage.py check --deploy
```

`check --deploy` doit être exempt d'avertissement.

> **N'exécutez jamais `seed_demo` en production** : il crée des comptes dont
> le mot de passe est publié dans la documentation.

---

## 6. Antivirus (recommandé)

Ajoutez à `docker-compose.yml` :

```yaml
  evdp-clamav:
    image: clamav/clamav:1.4
    container_name: evdp-clamav
    restart: unless-stopped
    volumes:
      - evdp-clamav-data:/var/lib/clamav
    networks:
      - evdp-backend
    healthcheck:
      test: ["CMD", "clamdscan", "--ping", "1"]
      interval: 60s
      timeout: 10s
      retries: 3
      start_period: 300s
    deploy:
      resources:
        limits:
          memory: 2g
```

Puis `CLAMAV_HOST=evdp-clamav` dans `.env`.

Sans ce service, les pièces jointes sont marquées `SKIPPED` : l'absence
d'analyse est tracée, mais le fichier reste téléchargeable.

---

## 7. Démarrage automatique

`restart: unless-stopped` couvre les redémarrages de conteneur. Pour le
démarrage au boot :

```ini
# /etc/systemd/system/evdp.service
[Unit]
Description=Plateforme eVDP
Requires=docker.service
After=docker.service network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
User=evdp
WorkingDirectory=/home/evdp/evdp
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now evdp
```

---

## 8. Sauvegardes

```bash
chmod +x scripts/*.sh
sudo crontab -u evdp -e
```

```cron
0 2 * * * /home/evdp/evdp/scripts/backup_db.sh    >> /var/log/evdp-backup.log 2>&1
0 3 * * * /home/evdp/evdp/scripts/backup_minio.sh >> /var/log/evdp-backup.log 2>&1
```

Les sauvegardes contiennent des **vulnérabilités non corrigées** : chiffrez-les
et stockez-les hors du serveur. Voir `docs/backup.md`.

---

## 9. Mise à jour

```bash
cd /home/evdp/evdp
./scripts/backup_db.sh                 # toujours sauvegarder avant
git pull
docker compose build
docker compose run --rm evdp-web migrate
docker compose up -d
docker compose ps
curl -fsS https://vdp.exemple.bf/ready/
```

Retour arrière :

```bash
git checkout <commit-precedent>
docker compose build && docker compose up -d
./scripts/restore_db.sh backups/evdp-db-<horodatage>.sql.gz
```

---

## 10. Supervision

| À surveiller | Seuil |
|--------------|-------|
| `GET /ready/` | ≠ 200 pendant 2 min |
| `evdp_cases_sla_breached` | Hausse anormale |
| Logger `evdp.security` : `cache_unavailable` | **Toute occurrence** |
| Logger `evdp.security` : `throttle_backend_unavailable` | **Toute occurrence** |
| `AuditAction.PERMISSION_DENIED` | Pic soudain |
| `AuditAction.LOGIN_FAILED` | Pic soudain |
| Disque | > 80 % |
| Certificat TLS | Expiration < 21 jours |

Les journaux sont émis en JSON sur `stdout` : branchez `docker compose logs`
sur Loki, Elastic ou votre SIEM.

Prometheus peut scruter `/metrics/` depuis le réseau interne :

```yaml
scrape_configs:
  - job_name: evdp
    metrics_path: /metrics/
    static_configs:
      - targets: ['evdp-nginx:80']
```

---

## 11. Checklist de mise en production

- [ ] `SECRET_KEY` unique, généré aléatoirement, jamais commité
- [ ] `DEBUG=False`
- [ ] `ALLOWED_HOSTS` limité aux domaines réels
- [ ] `CSRF_TRUSTED_ORIGINS` en `https://`
- [ ] TLS actif, `SECURE_SSL_REDIRECT=True`, HSTS activé
- [ ] Mots de passe PostgreSQL et MinIO forts et uniques
- [ ] Relais SMTP réel configuré, Mailpit retiré
- [ ] ClamAV activé
- [ ] `seed_demo` **non exécuté**
- [ ] Superutilisateur créé, comptes de démonstration absents
- [ ] `manage.py check --deploy` sans avertissement
- [ ] Sauvegardes planifiées, chiffrées, **restauration testée**
- [ ] Pare-feu actif, SSH restreint
- [ ] Supervision et alertes en place
- [ ] Clé publique PGP nationale publiée (`PGP_PUBLIC_KEY`)
- [ ] Politique de divulgation relue et adaptée dans l'administration
