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

Aucun autre port n'a besoin d'être ouvert : PostgreSQL et Redis restent
sur le réseau Docker interne. En sortie, le serveur doit pouvoir joindre le
serveur SMTP de la structure (emails) ; pour restreindre cette sortie, voir
§3, Messagerie, point 6.

### Utilisateur applicatif

```bash
sudo useradd --create-home --shell /bin/bash evdp
sudo usermod -aG docker evdp
sudo -iu evdp
```

---

## 3. Installation

```bash
git clone --branch v1.0.0 https://github.com/Faso-Shield/eVDP.git /home/evdp/evdp
cd /home/evdp/evdp
cp .env.example .env
chmod 600 .env
```

Remplacez `v1.0.0` par la version livrée : les fichiers de configuration
(compose, Nginx) correspondent alors exactement à l'image.

### Image de l'application : construite ou publiée

Deux façons d'obtenir l'image de l'application, au choix :

| | Construite sur le serveur (par défaut) | Publiée par la CI (recommandé) |
|---|---|---|
| Réglage dans `.env` | rien | `EVDP_IMAGE=ghcr.io/faso-shield/evdp-app:1.0.0` |
| Obtenir l'image | `docker compose build` (≈ 25 min, accès Internet) | `docker compose pull evdp-web evdp-worker evdp-beat` (quelques minutes) |
| Démarrer | `docker compose up -d` | `docker compose up -d --no-build` |
| Image identique à celle testée par la CI | non garanti | oui : construite, testée et scannée une seule fois |

Avec l'image publiée, si le registre est privé, connectez-vous d'abord avec
un jeton d'accès en lecture (`read:packages`) fourni par l'équipe :

```bash
docker login ghcr.io -u <compte-github>
```

Pour vérifier qu'une image correspond au code d'une version (audit) :

```bash
docker inspect ghcr.io/faso-shield/evdp-app:1.0.0 \
  -f '{{ index .Config.Labels "org.opencontainers.image.revision" }}'
```

La valeur affichée est le commit Git dont l'image est issue.

### Configuration de production

```dotenv
DJANGO_SETTINGS_MODULE=config.settings.prod
SECRET_KEY=<64 caractères générés aléatoirement>
FIELD_ENCRYPTION_KEY=<clé Fernet, voir .env.example ; à sauvegarder hors de la base>
DEBUG=False
ALLOWED_HOSTS=vdp.exemple.bf
CSRF_TRUSTED_ORIGINS=https://vdp.exemple.bf

SECURE_SSL_REDIRECT=True
SECURE_HSTS_SECONDS=31536000

POSTGRES_PASSWORD=<mot de passe fort>

EMAIL_HOST=smtp.exemple.bf
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_USE_SSL=False
EMAIL_USER=evdp@exemple.bf
EMAIL_PASSWORD=<mot de passe>
DEFAULT_FROM_EMAIL=eVDP <no-reply@exemple.bf>
SITE_BASE_URL=https://vdp.exemple.bf

EVDP_NATIONAL_TEAM=ANSSI-BF / CSIRT National
EVDP_CONTACT_EMAIL=vdp@anssi.bf

MESSAGE_INTEGRITY_KEY=<64 caractères, voir ci-dessous>
METRICS_TOKEN=<64 caractères, voir ci-dessous>

CLAMAV_HOST=evdp-clamav        # fortement recommandé
LOG_LEVEL=INFO
LOG_FORMAT=json
```

Génération des clés :

```bash
# SECRET_KEY (≥ 50 caractères)
python3 -c "import secrets; print(secrets.token_urlsafe(64))"

# MESSAGE_INTEGRITY_KEY (HMAC-SHA256 des messages)
python3 -c "import secrets; print(secrets.token_urlsafe(48))"

# METRICS_TOKEN (jeton Bearer pour /metrics/, à reporter dans Prometheus)
python3 -c "import secrets; print(secrets.token_urlsafe(48))"
```

### Messagerie

> Guide complet, pas à pas, avec exemples de `.env`, message type pour le
> service informatique et FAQ : **[messagerie.md](messagerie.md)**. Cette
> section en est le résumé pour l'installation.

La plateforme n'envoie pas elle-même ses emails sur Internet : elle les
remet à un **serveur SMTP**, qui les distribue. Ces emails ne sont pas
accessoires : vérification d'adresse à l'inscription, réinitialisation de
mot de passe, notifications de dossier, alertes de SLA. Sans messagerie
fonctionnelle, un chercheur ne peut pas activer son compte.

Par défaut, la plateforme écrit à **Mailpit**, un faux serveur de
développement qui garde les emails sans les envoyer. **En production,
remplacez-le par le serveur SMTP de la structure** (points 1 à 5), puis
désactivez Mailpit (point 8).

**1. Informations à demander au service informatique de la structure**

| Information | Variable | Exemple |
|---|---|---|
| Adresse du serveur SMTP | `EMAIL_HOST` | `smtp.ministere.gov.bf` |
| Port | `EMAIL_PORT` | `587`, `465` ou `25` |
| Mode de chiffrement | `EMAIL_USE_TLS` / `EMAIL_USE_SSL` | voir le tableau suivant |
| Compte d'envoi et mot de passe | `EMAIL_USER` / `EMAIL_PASSWORD` | `no-reply@ministere.gov.bf` |
| Adresse d'expédition | `DEFAULT_FROM_EMAIL` | `eVDP <no-reply@ministere.gov.bf>` |
| Certificat du serveur émis par une autorité interne ? | voir le point 7 | oui / non |

Un compte dédié à la plateforme (`no-reply@…`) est préférable à la boîte
d'une personne : il survit aux départs et se révoque sans gêner personne.

**L'adresse d'expédition doit en général être celle du compte d'envoi.** La
plupart des serveurs refusent d'envoyer au nom d'une autre adresse que
celle authentifiée (`EMAIL_USER`) : si `DEFAULT_FROM_EMAIL` est
`no-reply@…`, le compte doit être `no-reply@…`, ou le service informatique
doit autoriser ce compte à envoyer en son nom.

**2. Port et chiffrement**

| Le serveur accepte… | `EMAIL_PORT` | `EMAIL_USE_TLS` | `EMAIL_USE_SSL` |
|---|---|---|---|
| STARTTLS (le plus courant) | `587` | `True` | `False` |
| TLS dès la connexion (SMTPS) | `465` | `False` | `True` |
| Relais interne, sans compte ni chiffrement | `25` | `False` | `False` |

Le relais interne (port 25) est fréquent dans les administrations : le
serveur accepte la plateforme d'après son adresse IP, sans mot de passe.
Laissez alors `EMAIL_USER` et `EMAIL_PASSWORD` vides, et demandez au
service informatique d'autoriser l'adresse IP du serveur eVDP. Les emails
circulent en clair jusqu'au relais : réservez ce mode à un relais situé
sur le même réseau de confiance.

Ne mettez **jamais `EMAIL_USE_TLS` et `EMAIL_USE_SSL` à `True` ensemble** :
la plateforme refuse de démarrer. Un mauvais couple (par exemple `465` avec
`EMAIL_USE_TLS=True`) bloque la connexion jusqu'au délai `EMAIL_TIMEOUT`
(30 s par défaut), puis l'envoi échoue. Certains emails partent pendant la
requête de l'utilisateur (inscription, réinitialisation) : avec un réglage
faux, sa page peut donc attendre jusqu'à 30 s avant de s'afficher.

**3. Liens contenus dans les emails**

`SITE_BASE_URL` doit contenir l'adresse publique réelle de l'instance
(`https://vdp.exemple.bf`). C'est elle qui construit les liens de
vérification, de réinitialisation et d'accès aux dossiers : laissée vide ou
fausse, les emails partent mais leurs liens ne mènent nulle part.

**4. Délivrabilité : SPF, DKIM, DMARC**

Le domaine de `DEFAULT_FROM_EMAIL` doit autoriser le serveur SMTP à envoyer
en son nom. C'est le travail de l'**administrateur du domaine** (zone DNS),
pas de la plateforme, mais sans cela les emails arrivent en spam ou sont
rejetés :

- **SPF** : enregistrement TXT listant les serveurs autorisés à envoyer ;
- **DKIM** : signature des emails par le serveur SMTP, clé publique en DNS ;
- **DMARC** : politique appliquée par les destinataires si SPF ou DKIM échoue.

**5. Test d'envoi**

Après le démarrage (§5), envoyez un email d'essai à une adresse que vous
consultez :

```bash
docker compose exec evdp-web python manage.py sendtestemail adresse@exemple.bf
```

Vérifiez qu'il arrive **en boîte de réception** (pas en spam) et que
l'expéditeur affiché est le bon. En cas d'échec, `sendtestemail` affiche
directement l'erreur.

**Après la mise en service**, un email non remis n'interrompt pas la
plateforme et n'est **pas renvoyé** : il est perdu, et une ligne
`email_delivery_failed` est écrite au journal. Elle indique l'usage
(`purpose` : `notification` ou `activation`), le domaine du destinataire, et
la cause : `error` (type d'erreur), puis `smtp_code` et `smtp_reply` (réponse
du serveur) ou `detail` (réseau, TLS, délai). Ni le contenu de l'email ni
l'adresse complète du destinataire n'y figurent. Pour surveiller :

```bash
docker compose logs evdp-web evdp-worker | grep email_delivery_failed
```

Les échecs de l'email de réinitialisation de mot de passe sont journalisés
par Django lui-même (`Failed to send password reset email`).

| Erreur (`sendtestemail`, ou `error` / `smtp_code` au journal) | Cause probable |
|---|---|
| `timed out`, `TimeoutError` (après 30 s) | mauvais couple port / chiffrement, ou port sortant bloqué par le pare-feu |
| `Connection refused`, `ConnectionRefusedError` | `EMAIL_HOST` ou `EMAIL_PORT` erroné |
| `SMTPAuthenticationError`, code `535` | `EMAIL_USER` ou `EMAIL_PASSWORD` erroné |
| `SMTPSenderRefused`, code `550` ou `553` | `DEFAULT_FROM_EMAIL` différent du compte d'envoi (point 1) |
| `SMTPRecipientsRefused`, code `550` | adresse du destinataire inconnue, ou relais refusant l'IP du serveur (port 25) |
| `SSL: WRONG_VERSION_NUMBER` | `EMAIL_USE_SSL=True` sur un port STARTTLS (587) |
| `CERTIFICATE_VERIFY_FAILED` | certificat du serveur émis par une autorité interne (point 7) |
| `Temporary failure in name resolution` / `Name or service not known` | le conteneur ne peut pas sortir : réseau `evdp-smtp` absent du service, ou DNS bloqué par le pare-feu (point 6) |
| Email reçu en spam | SPF, DKIM ou DMARC absents pour le domaine d'expédition (point 4) |
| Liens des emails incorrects | `SITE_BASE_URL` vide ou erronée (point 3) |
| Inscription ou réinitialisation très lente | envoi qui attend le délai de 30 s : voir les lignes ci-dessus |

**6. Sortie réseau des conteneurs**

La base de données et Redis sont sur un réseau Docker **interne**
(`evdp-backend`), coupé d'Internet. Les deux conteneurs qui envoient des
emails, `evdp-web` (vérification d'adresse, réinitialisation) et
`evdp-worker` (notifications), sont **en plus** reliés au réseau `evdp-smtp`,
leur seule sortie vers le serveur SMTP. C'est une sortie uniquement : rien
n'entre par ce réseau, la plateforme reste servie par Nginx seul.

Par défaut, cette sortie n'est pas restreinte. **Recommandé en production :
la limiter au seul serveur SMTP** avec le pare-feu de l'hôte. Docker applique
la chaîne `DOCKER-USER` d'iptables au trafic de ses conteneurs. Exemple à
adapter, puis à valider par le test d'envoi (point 5) :

```bash
# Nom exact du réseau : préfixé par le nom du dossier du projet
docker network ls | grep evdp-smtp
SUBNET=$(docker network inspect evdp_evdp-smtp -f '{{(index .IPAM.Config 0).Subnet}}')
SMTP_IP=10.20.0.25          # adresse du serveur SMTP de la structure
DNS_IP=10.20.0.53           # résolveur DNS utilisé par l'hôte

# -I insère en tête : la dernière règle saisie est évaluée la première.
sudo iptables -I DOCKER-USER -s "$SUBNET" -j DROP
sudo iptables -I DOCKER-USER -s "$SUBNET" -p tcp -d "$SMTP_IP" --dport 587 -j ACCEPT
sudo iptables -I DOCKER-USER -s "$SUBNET" -p udp -d "$DNS_IP" --dport 53 -j ACCEPT
sudo iptables -I DOCKER-USER -s "$SUBNET" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
```

Remplacez `587` par `465` ou `25` selon le point 2, et rendez les règles
persistantes (`iptables-persistent` sur Debian/Ubuntu). L'antivirus a son
propre réseau de sortie (`evdp-external`) : ces règles ne coupent pas ses
mises à jour.

**7. Certificat émis par une autorité interne**

Les messageries d'État utilisent souvent un certificat signé par une
autorité de certification (AC) interne, que la plateforme ne connaît pas :
l'envoi échoue avec `CERTIFICATE_VERIFY_FAILED`. Ne désactivez pas la
vérification : ajoutez l'AC interne aux autorités reconnues par les deux
conteneurs qui envoient des emails.

Demandez au service informatique le certificat de l'AC (fichier `.pem` ou
`.crt`, format PEM), puis construisez un fichier qui contient **les
autorités publiques de l'image et l'AC interne** (la variable
`SSL_CERT_FILE` remplace la liste par défaut, elle ne la complète pas) :

```bash
mkdir -p docker/certs
docker compose exec evdp-web cat /etc/ssl/certs/ca-certificates.crt > docker/certs/smtp-ca-bundle.pem
cat ac-interne.pem >> docker/certs/smtp-ca-bundle.pem
```

Déclarez-le dans `docker-compose.override.yml` (point 8), puis
`docker compose up -d` et refaites le test d'envoi :

```yaml
services:
  evdp-web:
    volumes:
      - ./docker/certs/smtp-ca-bundle.pem:/etc/evdp/smtp-ca-bundle.pem:ro
    environment:
      SSL_CERT_FILE: /etc/evdp/smtp-ca-bundle.pem
  evdp-worker:
    volumes:
      - ./docker/certs/smtp-ca-bundle.pem:/etc/evdp/smtp-ca-bundle.pem:ro
    environment:
      SSL_CERT_FILE: /etc/evdp/smtp-ca-bundle.pem
```

Après une mise à jour de l'image, reconstruisez ce fichier : les autorités
publiques qu'il contient datent de sa création.

**8. Désactiver Mailpit**

Ne modifiez pas `docker-compose.yml` : il serait en conflit avec chaque mise
à jour du projet. Créez à côté un fichier `docker-compose.override.yml`,
propre à ce serveur (Docker Compose le lit automatiquement, et il est exclu
du dépôt par `.gitignore`) :

```yaml
services:
  evdp-mailpit:
    profiles: ["mailpit"]
```

Mailpit n'est alors plus démarré par `docker compose up -d`. Arrêtez
l'instance déjà lancée :

```bash
docker compose rm -sf evdp-mailpit
```

Les réglages du point 7, si besoin, vont dans ce même fichier.

---

## 4. TLS

### Certificat Let's Encrypt

Le challenge ACME utilise la methode `--webroot` : Nginx sert le defi HTTP
sur le port 80 (volume `certbot-www`), il n'est pas necessaire de l'arreter.

```bash
sudo apt install -y certbot

# Premiere obtention (Nginx doit etre demarre sur le port 80)
sudo certbot certonly --webroot -w /var/www/certbot -d vdp.exemple.bf
```

### Copie des certificats

Trois fichiers sont requis par `tls.conf` (`evdp.crt`, `evdp.key`,
`chain.pem` pour OCSP stapling) :

```bash
DOMAIN=vdp.exemple.bf
CERTS_DIR=/home/evdp/evdp/docker/nginx/certs
sudo mkdir -p "$CERTS_DIR"
sudo cp /etc/letsencrypt/live/$DOMAIN/fullchain.pem "$CERTS_DIR/evdp.crt"
sudo cp /etc/letsencrypt/live/$DOMAIN/privkey.pem   "$CERTS_DIR/evdp.key"
sudo cp /etc/letsencrypt/live/$DOMAIN/chain.pem     "$CERTS_DIR/chain.pem"
sudo chown -R evdp:evdp "$CERTS_DIR"
sudo chmod 600 "$CERTS_DIR/evdp.key"
```

### Activation

1. Renommez la configuration HTTP seule et activez le bloc TLS :

```bash
cd /home/evdp/evdp
mv docker/nginx/conf.d/evdp.conf docker/nginx/conf.d/evdp.conf.http-only
mv docker/nginx/conf.d/tls.conf.template docker/nginx/conf.d/tls.conf
```

2. Dans `docker-compose.yml`, decommentez le port 443 et les volumes :

```yaml
    ports:
      - "0.0.0.0:${HTTP_PORT:-80}:80"
      - "0.0.0.0:${HTTPS_PORT:-443}:443"
    volumes:
      - ./docker/nginx/conf.d:/etc/nginx/conf.d:ro
      - ./docker/nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./docker/nginx/certs:/etc/nginx/certs:ro
      - certbot-www:/var/www/certbot:ro
```

3. Dans `.env`, activez le HTTPS :

```dotenv
SECURE_SSL_REDIRECT=True
SECURE_HSTS_SECONDS=31536000
CSRF_TRUSTED_ORIGINS=https://vdp.exemple.bf
SITE_BASE_URL=https://vdp.exemple.bf
```

4. Redemarrez :

```bash
docker compose up -d
curl -sk -o /dev/null -w "%{http_code}" https://vdp.exemple.bf/login/
# Attendu : 200
```

### Renouvellement

```bash
sudo crontab -e
0 3 * * 1 certbot renew --webroot -w /var/www/certbot --deploy-hook \
  "CERTS=/home/evdp/evdp/docker/nginx/certs && \
   DOMAIN=vdp.exemple.bf && \
   cp /etc/letsencrypt/live/\$DOMAIN/fullchain.pem \$CERTS/evdp.crt && \
   cp /etc/letsencrypt/live/\$DOMAIN/privkey.pem   \$CERTS/evdp.key && \
   cp /etc/letsencrypt/live/\$DOMAIN/chain.pem     \$CERTS/chain.pem && \
   cd /home/evdp/evdp && docker compose exec evdp-nginx nginx -s reload"
```

---

## 5. Démarrage

```bash
docker compose build
docker compose up -d
docker compose ps
docker compose exec evdp-web python manage.py createsuperuser
docker compose exec evdp-web python manage.py seed_reference
docker compose exec evdp-web python manage.py check --deploy
```

Avec une image publiée (`EVDP_IMAGE`, §3), remplacez les deux premières
lignes par `docker compose pull evdp-web evdp-worker evdp-beat` puis
`docker compose up -d --no-build`.

Une fois HTTPS activé (§4), `check --deploy` doit être exempt
d'avertissement. Tant que la plateforme est servie en HTTP, quatre
avertissements sont attendus : `security.W004`, `W008`, `W012` et `W016`
(HSTS, redirection HTTPS, cookies `Secure`).

`seed_reference` charge le référentiel CWE, la politique SLA par défaut,
les textes de la plateforme et les organisations réelles (ANSSI-BF, CSIRT
National, ministères) — sans aucun compte ni mot de passe fictif. Ajoutez
`--with-programs` pour créer aussi un programme VDP national et deux
programmes Bug Bounty réalistes (toujours sans faux compte ni faux dossier).
Idempotente, sans risque de la relancer.

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
0 3 * * * /home/evdp/evdp/scripts/backup_media.sh >> /var/log/evdp-backup.log 2>&1
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
docker compose run --rm evdp-web python manage.py migrate
docker compose run --rm evdp-web python manage.py rechiffrer_champs
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

### Avec une image publiée

```bash
cd /home/evdp/evdp
./scripts/backup_db.sh                 # toujours sauvegarder avant
git fetch --tags && git checkout v1.0.1
# dans .env : EVDP_IMAGE=ghcr.io/faso-shield/evdp-app:1.0.1
docker compose pull evdp-web evdp-worker evdp-beat
docker compose run --rm evdp-web python manage.py migrate
docker compose up -d --no-build
curl -fsS https://vdp.exemple.bf/ready/
```

Retour arrière : revenir à l'étiquette et à `EVDP_IMAGE` précédentes, puis
restaurer la base comme ci-dessus.

### Publier une nouvelle version (équipe de développement)

La CI publie l'image dans le registre GitHub (`ghcr.io/faso-shield/evdp-app`)
quand une **étiquette de version** est poussée, et seulement si tous les
contrôles sont verts (tests, analyse de sécurité, scan de l'image,
migrations) :

```bash
git checkout main && git pull
git tag -a v1.0.1 -m "eVDP 1.0.1"
git push origin v1.0.1
```

| Étiquette | Images publiées |
|---|---|
| `v1.0.1` | `evdp-app:1.0.1` et `evdp-app:1.0` |
| `v1.1.0-rc1` (pré-version, pour essai) | `evdp-app:1.1.0-rc1` seulement |

L'image publiée est celle-là même que la CI vient de construire et de
scanner : elle n'est pas reconstruite. Le récapitulatif du job
« Publication de l'image » sur GitHub donne les noms publiés.

---

## 10. Rotation de la clé PGP nationale

`PGP_PUBLIC_KEY` et `PGP_FINGERPRINT` (`.env`) ne sont **volontairement pas**
modifiables depuis l'interface web, contrairement à la politique de
divulgation ou au texte « À propos ». Un changement exige un accès serveur
et un redémarrage — c'est un choix de sécurité assumé : si ce champ était
modifiable depuis un simple formulaire admin, un seul compte Coordinateur
compromis (hameçonnage, etc.) suffirait à substituer discrètement la clé
nationale et à intercepter tous les signalements chiffrés suivants. Exiger
un accès infrastructure ajoute une barrière supplémentaire, indépendante
d'un compte applicatif compromis.

### Quand tourner la clé

- À l'approche de sa date d'expiration (fixée à la génération — 2 à 3 ans
  est une durée raisonnable)
- Immédiatement en cas de compromission suspectée ou confirmée de la clé
  privée (poste volé, phrase secrète potentiellement exposée)
- Selon une cadence régulière décidée par l'équipe (ex. tous les 2 ans),
  même sans incident, par hygiène de sécurité

### Procédure recommandée

1. **Générer la nouvelle paire de clés** (Kleopatra ou `gpg --full-generate-key`)
   suffisamment à l'avance — jamais dans l'urgence, sauf compromission avérée.
2. **Limite technique à connaître** : eVDP ne publie qu'**une seule** clé à la
   fois (`PGP_PUBLIC_KEY`) — le code ne prévoit pas d'afficher simultanément
   une ancienne et une nouvelle clé « en transition ». La période de
   recouvrement doit donc se gérer **par la communication**, pas par la
   plateforme :
   - Annoncer la date de bascule à l'avance, par un canal indépendant
     d'eVDP (communiqué officiel, réseaux sociaux institutionnels ANSSI-BF).
   - À la date prévue, publier la nouvelle clé sur eVDP (étape 3) — à partir
     de ce moment, tout signalement chiffré avec l'ancienne clé reste
     déchiffrable (la clé privée correspondante est conservée), mais
     l'ancienne clé n'est plus proposée aux nouveaux déclarants.
3. **Appliquer le changement** :
   ```bash
   cd ~/evdp
   nano .env    # remplacer PGP_PUBLIC_KEY et PGP_FINGERPRINT
   docker compose up -d
   curl -fsS https://vdp.exemple.bf/pgp-key.asc   # verifier la nouvelle cle publiee
   ```
4. **Publier l'empreinte de la nouvelle clé sur un canal indépendant** de la
   plateforme elle-même (communiqué, document officiel) — un chercheur
   sérieux doit pouvoir vérifier que la clé affichée sur eVDP correspond
   bien à l'empreinte annoncée ailleurs, sans devoir faire confiance
   uniquement au serveur qui la sert.
5. **Consigner la rotation** : date, motif, empreintes de l'ancienne et de
   la nouvelle clé — dans un registre interne à l'équipe (`.env` n'étant pas
   versionné, cette trace doit vivre ailleurs que dans Git).
6. **Conserver l'ancienne clé privée** en lieu sûr tant que d'anciens
   signalements chiffrés avec elle pourraient nécessiter un déchiffrement —
   ne jamais la détruire immédiatement après la bascule.

## 11. Supervision

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

Prometheus peut scruter `/metrics/` depuis le réseau interne. L'accès
nécessite un jeton Bearer (`METRICS_TOKEN`) :

```yaml
scrape_configs:
  - job_name: evdp
    metrics_path: /metrics/
    authorization:
      credentials: '<valeur de METRICS_TOKEN>'
    static_configs:
      - targets: ['evdp-nginx:80']
```

---

## 12. Checklist de mise en production

- [ ] `SECRET_KEY` unique, généré aléatoirement, jamais commité
- [ ] `FIELD_ENCRYPTION_KEY` générée et sauvegardée hors de la base
- [ ] `MESSAGE_INTEGRITY_KEY` générée (HMAC-SHA256 des messages)
- [ ] `METRICS_TOKEN` généré et reporté dans le job Prometheus
- [ ] `DEBUG=False`
- [ ] `ALLOWED_HOSTS` limité aux domaines réels
- [ ] `CSRF_TRUSTED_ORIGINS` en `https://`
- [ ] TLS actif, `SECURE_SSL_REDIRECT=True`, HSTS activé (y compris sur `/static/`)
- [ ] `chain.pem` copié dans `docker/nginx/certs/` (OCSP stapling)
- [ ] IP réelle des clients configurée (`set_real_ip_from` dans `nginx.conf`, ou `userland-proxy: false` dans Docker)
- [ ] Mot de passe PostgreSQL fort et unique
- [ ] Volume `evdp-media` sur un disque chiffré, sauvegardé (`backup_media.sh`)
- [ ] Relais SMTP réel configuré, Mailpit désactivé par `docker-compose.override.yml` (§3, Messagerie, point 8)
- [ ] `sendtestemail` reçu en boîte de réception (§3, Messagerie)
- [ ] SPF, DKIM et DMARC configurés pour le domaine d'expédition
- [ ] `SITE_BASE_URL` égale à l'adresse publique réelle
- [ ] Sortie des conteneurs `evdp-web` / `evdp-worker` limitée au serveur SMTP (§3, Messagerie, point 6)
- [ ] ClamAV activé
- [ ] `seed_demo` **non exécuté**
- [ ] Superutilisateur créé, comptes de démonstration absents
- [ ] `manage.py check --deploy` sans avertissement
- [ ] Sauvegardes planifiées, chiffrées, **restauration testée**
- [ ] Pare-feu actif, SSH restreint
- [ ] Supervision et alertes en place
- [ ] Clé publique PGP nationale publiée (`PGP_PUBLIC_KEY`)
- [ ] Date d'expiration de la clé PGP suivie, prochaine rotation planifiée (§10)
- [ ] Politique de divulgation relue et adaptée dans l'administration
