# Installation pas à pas — eVDP

Ce guide installe eVDP sur un serveur, à partir du **paquet de livraison**
(`eVDP-<version>/`). Il ne demande ni accès Internet, ni compte GitHub, ni
connaissance du code.

Suivez les étapes dans l'ordre. Chacune se termine par **« Vous devez
voir »** : si ce n'est pas le cas, ne passez pas à la suite, consultez le
[dépannage](#depannage) en fin de guide.

Dans les commandes, `1.0.2` est la version livrée : remplacez-la par celle de
votre paquet. Les commandes se tapent sur le serveur, dans un terminal (SSH).

---

## Avant de commencer

### Le serveur

| Élément | Minimum |
|---|---|
| Système | Ubuntu 22.04 LTS ou 24.04 LTS, ou Debian 12 |
| Processeur et mémoire | 4 vCPU, 8 Go de RAM (l'antivirus en utilise 2) |
| Disque | 100 Go |
| Réseau entrant | ports 80 et 443 ouverts vers les utilisateurs, port 22 (SSH) réservé à l'administration |
| Compte | un utilisateur avec les droits `sudo` |

### Ce qu'il faut demander à l'avance

| À qui | Quoi | Utilisé à l'étape |
|---|---|---|
| Équipe réseau | L'adresse du serveur : un nom (`vdp.anssi.bf`) ou une IP (`10.20.0.10`) | 6 |
| Équipe système | Une source de temps (NTP) joignable par le serveur | 2 |
| Service informatique | Les paramètres du serveur d'email : hôte, port, chiffrement, compte, mot de passe | 10 |
| Autorité de certification (interne ou commerciale) | Un certificat pour l'adresse du serveur, sa clé privée et la chaîne de l'autorité | 11 |
| Chaque administrateur | Une application d'authentification sur téléphone (FreeOTP, Google Authenticator, Microsoft Authenticator…) | 9 |

Les étapes 1 à 9 suffisent pour une plateforme qui fonctionne. Les étapes 10
à 13 la mettent en production.

---

## Étape 1 — Installer Docker

Vérifiez d'abord s'il est déjà présent :

```bash
docker version
docker compose version
```

S'il l'est, passez à l'étape 2.

**Serveur relié à Internet :**

```bash
curl -fsSL https://get.docker.com | sudo sh
```

**Serveur sans Internet :** sur un poste connecté, téléchargez les cinq
paquets correspondant au système du serveur depuis
`https://download.docker.com/linux/ubuntu/dists/<nom-de-version>/pool/stable/amd64/`
(remplacez `ubuntu` par `debian` si besoin ; le nom de version s'obtient sur
le serveur avec `lsb_release -cs`) :

- `containerd.io`
- `docker-ce`
- `docker-ce-cli`
- `docker-buildx-plugin`
- `docker-compose-plugin`

Copiez-les sur le serveur, dans un dossier vide, puis :

```bash
sudo dpkg -i ./*.deb
sudo systemctl enable --now docker
```

Si `dpkg` signale une dépendance manquante, l'équipe système l'installe
depuis le miroir interne de la distribution, puis relance la commande.

**Dans les deux cas**, autorisez votre utilisateur à utiliser Docker, puis
**déconnectez-vous et reconnectez-vous** :

```bash
sudo usermod -aG docker "$USER"
```

**Vous devez voir**, après reconnexion :

```bash
docker compose version
```

```
Docker Compose version v2.x.x
```

---

## Étape 2 — Vérifier l'heure du serveur

Les administrateurs se connectent avec un code à 6 chiffres qui change toutes
les 30 secondes. Si l'heure du serveur dérive de plus d'une minute, **tous
les codes sont refusés**.

```bash
timedatectl
```

**Vous devez voir :**

```
System clock synchronized: yes
```

Si la valeur est `no`, l'équipe système configure une source de temps
(NTP), par exemple dans `/etc/systemd/timesyncd.conf`, puis :

```bash
sudo systemctl restart systemd-timesyncd
```

---

## Étape 3 — Copier et vérifier le paquet

Copiez le dossier `eVDP-1.0.2` sur le serveur (clé USB, disque, `scp`), par
exemple dans votre dossier personnel, puis :

```bash
cd ~/eVDP-1.0.2
sha256sum -c SHA256SUMS.txt
```

**Vous devez voir** une ligne par fichier, chacune terminée par `OK` (ou
`Réussi`), et aucune ligne `FAILED`.

Comparez aussi l'empreinte de l'image avec celle transmise par l'équipe de
livraison par un autre canal (téléphone, courrier) :

```bash
grep evdp-app SHA256SUMS.txt
```

**Si un fichier est `FAILED`**, ne l'installez pas : demandez un nouveau
paquet.

---

## Étape 4 — Charger les images

```bash
docker load -i 2-images-docker/evdp-app-1.0.2.tar.gz
docker load -i 2-images-docker/images-tierces-1.0.2.tar.gz
```

Chaque commande prend une à deux minutes.

**Vous devez voir** six lignes `Loaded image:` au total :

```
Loaded image: ghcr.io/faso-shield/evdp-app:1.0.2
Loaded image: postgres:16.4-alpine
Loaded image: redis:7.4-alpine
Loaded image: nginx:1.27-alpine
Loaded image: clamav/clamav:1.4.6
Loaded image: axllent/mailpit:v1.21
```

---

## Étape 5 — Extraire le code

Le code va dans un dossier dédié, ici `/opt/evdp` :

```bash
sudo mkdir -p /opt/evdp
sudo chown "$USER": /opt/evdp
unzip -q 1-code-source/eVDP-1.0.2-source.zip -d /opt/evdp
cd /opt/evdp/eVDP-1.0.2
```

Si `unzip` n'est pas installé, cette commande fait la même chose :

```bash
python3 -m zipfile -e 1-code-source/eVDP-1.0.2-source.zip /opt/evdp
```

**Vous devez voir**, avec `ls` dans `/opt/evdp/eVDP-1.0.2`, entre autres :
`docker-compose.yml`, `.env.example` (fichier caché : `ls -a`), `scripts`,
`docs`.

**Toutes les commandes suivantes se tapent dans ce dossier.**

---

## Étape 6 — Préparer la configuration (`.env`)

Un script crée le fichier de configuration et y place tous les secrets,
générés pour cette installation. Il ne demande que l'adresse du serveur :

```bash
bash scripts/preparer_env.sh --adresse vdp.anssi.bf
```

Remplacez `vdp.anssi.bf` par l'adresse obtenue de l'équipe réseau (un nom ou
une IP, sans `http://`).

**Vous devez voir :**

```
[evdp] Image de l'application : ghcr.io/faso-shield/evdp-app:1.0.2
[evdp] .env cree pour http://vdp.anssi.bf (droits 600).
```

**Sauvegardez `.env` maintenant**, sur un support chiffré, hors du serveur. Il
contient les clés de chiffrement : sans elles, les données chiffrées de la
plateforme sont **définitivement perdues** en cas de panne du serveur. Ne
l'envoyez jamais par email.

---

## Étape 7 — Démarrer la plateforme

```bash
docker compose up -d --no-build
```

Le premier démarrage prend **3 à 5 minutes** : création de la base de
données, chargement des signatures antivirus. Suivez l'avancement :

```bash
docker compose ps
```

Relancez la commande toutes les 30 secondes.

**Vous devez voir** huit services, tous avec l'état `(healthy)` :
`evdp-beat`, `evdp-clamav`, `evdp-db`, `evdp-mailpit`, `evdp-nginx`,
`evdp-redis`, `evdp-web`, `evdp-worker`.

Un état `(health: starting)` est normal pendant les premières minutes.
`(unhealthy)` ou `Restarting` après 5 minutes : voir le dépannage.

---

## Étape 8 — Initialiser

Chargez les données de référence (vulnérabilités CWE, délais de traitement,
organisations nationales) :

```bash
docker compose exec evdp-web python manage.py seed_reference
```

**Vous devez voir :** `Donnees de reference chargees.`

Créez le premier compte administrateur :

```bash
docker compose exec evdp-web python manage.py createsuperuser
```

La commande demande une adresse email puis un mot de passe, deux fois. Le mot
de passe doit compter au moins 12 caractères et ne pas être trop courant.

**Vous devez voir :** `Superuser created successfully.`

> **N'exécutez jamais `seed_demo`** : cette commande crée des comptes de
> démonstration dont le mot de passe est publié dans la documentation.

---

## Étape 9 — Première connexion

Depuis un poste du réseau, ouvrez un navigateur à l'adresse :

```text
http://vdp.anssi.bf/login/
```

Connectez-vous avec l'email et le mot de passe de l'étape 8.

**À la première connexion, la plateforme impose la double
authentification** à tout compte administrateur :

1. Elle affiche un QR code.
2. Scannez-le avec l'application d'authentification du téléphone.
3. Saisissez le code à 6 chiffres affiché par l'application.
4. La plateforme affiche des **codes de secours** : notez-les et rangez-les en
   lieu sûr. Ils servent si le téléphone est perdu.

**Vous devez voir** la plateforme, avec à gauche un menu **Administration**
(Organisations, Comptes, Clé PGP nationale).

Ce compte est un **administrateur système** : il gère les comptes, les
organisations et la clé PGP, mais **ne voit aucun signalement** (séparation
des rôles). Créez ensuite, depuis **Administration → Comptes**, les comptes
métier : coordinateur national, analystes CSIRT, etc. Les rôles sont décrits
dans le guide `eVDP_Guide_Comptes_Roles.docx`. Chaque nouveau compte métier
enrôlera à son tour son propre authentificateur.

**Votre plateforme fonctionne.** Les étapes suivantes la préparent pour la
production.

---

## Étape 10 — Brancher le vrai serveur d'email

Par défaut, les emails (vérification d'adresse, mot de passe oublié,
notifications) sont retenus par **Mailpit**, un faux serveur d'essai : ils
n'arrivent chez personne. Pour les consulter pendant les essais, depuis votre
poste :

```bash
ssh -L 8025:127.0.0.1:8025 <utilisateur>@vdp.anssi.bf
```

puis ouvrez `http://127.0.0.1:8025` dans le navigateur.

Pour envoyer de vrais emails, suivez **`messagerie.md`** (guide dédié, avec le
message type à adresser au service informatique). En résumé : renseigner six
variables `EMAIL_*` dans `.env`, relancer, puis tester :

```bash
docker compose up -d --no-build
docker compose exec evdp-web python manage.py sendtestemail votre.adresse@anssi.bf
```

**Vous devez voir** l'email arriver dans votre boîte de réception.

Désactivez ensuite Mailpit (`messagerie.md`, point 8).

---

## Étape 11 — Activer HTTPS

Sans HTTPS, les mots de passe circulent en clair sur le réseau. Cette étape
est **obligatoire** avant l'ouverture aux utilisateurs.

**1. Déposez les trois fichiers du certificat** dans `docker/nginx/certs/`,
sous ces noms exacts :

| Nom à donner | Contenu |
|---|---|
| `evdp.crt` | le certificat du serveur, **suivi** des certificats intermédiaires (chaîne complète) |
| `evdp.key` | la clé privée du certificat |
| `chain.pem` | les certificats de l'autorité (intermédiaires et racine) |

Les fichiers doivent être au format PEM (texte commençant par
`-----BEGIN`). Avec Let's Encrypt (serveur public), voir `deployment.md` §4.

```bash
chmod 644 docker/nginx/certs/evdp.crt docker/nginx/certs/chain.pem
chmod 640 docker/nginx/certs/evdp.key
```

**2. Basculez la configuration Nginx en HTTPS :**

```bash
mv docker/nginx/conf.d/evdp.conf docker/nginx/conf.d/evdp.conf.http-only
cp docker/nginx/conf.d/tls.conf.template docker/nginx/conf.d/tls.conf
```

**3. Ouvrez le port 443 et donnez les certificats à Nginx.** Créez le fichier
`docker-compose.override.yml`, à côté de `docker-compose.yml` :

```yaml
services:
  evdp-nginx:
    ports:
      - "0.0.0.0:${HTTPS_PORT:-443}:443"
    volumes:
      - ./docker/nginx/certs:/etc/nginx/certs:ro
```

Si ce fichier existe déjà (désactivation de Mailpit, étape 10), ajoutez le
bloc `evdp-nginx` sous la ligne `services:` existante.

**4. Passez la configuration en HTTPS, puis relancez :**

```bash
bash scripts/preparer_env.sh --https
docker compose up -d --no-build
```

**Vous devez voir**, au bout d'une minute, tous les services `(healthy)`
(`docker compose ps`), puis :

```bash
curl -sI http://vdp.anssi.bf/ | head -n 1
```

```
HTTP/1.1 301 Moved Permanently
```

Dans le navigateur, `https://vdp.anssi.bf/login/` s'ouvre avec un cadenas.
Si le navigateur signale un certificat non reconnu, l'autorité interne n'est
pas encore installée sur ce poste : c'est à régler par le service
informatique sur les postes, pas sur la plateforme.

Enfin, le contrôle de configuration ne doit plus afficher d'avertissement :

```bash
docker compose exec evdp-web python manage.py check --deploy
```

**Vous devez voir :** `System check identified no issues (1 silenced).`

---

## Étape 12 — Sauvegardes et redémarrage automatique

**Sauvegardes** : la base de données et les pièces jointes, chaque nuit.

```bash
chmod +x scripts/*.sh
crontab -e
```

Ajoutez ces deux lignes :

```text
0 2 * * * /opt/evdp/eVDP-1.0.2/scripts/backup_db.sh >> /var/log/evdp-backup.log 2>&1
0 3 * * * /opt/evdp/eVDP-1.0.2/scripts/backup_media.sh >> /var/log/evdp-backup.log 2>&1
```

Les archives contiennent des vulnérabilités non corrigées : chiffrez-les et
copiez-les hors du serveur (`backup.md`). **Testez une restauration** au
moins une fois avant la mise en production.

**Redémarrage du serveur** : les conteneurs redémarrent seuls avec Docker.
Pour un démarrage garanti au boot, voir `deployment.md` §7.

---

## Étape 13 — Dernières vérifications

Parcourez la checklist de mise en production (`deployment.md` §12). Les
points les plus souvent oubliés :

- `.env` sauvegardé hors du serveur (étape 6) ;
- codes de secours de l'administrateur rangés (étape 9) ;
- email de test reçu (étape 10) ;
- HTTPS actif, `check --deploy` sans avertissement (étape 11) ;
- une restauration de sauvegarde testée (étape 12) ;
- Mailpit désactivé ;
- sur réseau isolé : mise à jour des signatures antivirus prévue
  (`deployment.md` §6).

---

## Dépannage

| Ce que vous voyez | Cause probable | Que faire |
|---|---|---|
| `permission denied ... docker.sock` | Utilisateur pas encore dans le groupe `docker` | Déconnectez-vous et reconnectez-vous (étape 1) |
| `sha256sum` affiche `FAILED` | Fichier abîmé ou modifié pendant la copie | Recopiez le fichier ; s'il échoue encore, demandez un nouveau paquet |
| `preparer_env.sh` : `.env existe deja` | Le script a déjà été lancé | Gardez le `.env` existant. `--force` seulement pour une installation neuve, jamais sur une plateforme en service |
| `preparer_env.sh` : `aucune image ... chargee` | Étape 4 non faite | Chargez les images, puis relancez |
| `pull access denied` ou `repository does not exist` au démarrage | `--no-build` oublié, ou images non chargées | `docker compose up -d --no-build` ; vérifiez `docker images` |
| `port is already allocated` | Un autre logiciel occupe le port 80 ou 443 | `sudo ss -ltnp` montre lequel ; arrêtez-le, ou changez `HTTP_PORT` dans `.env` |
| `evdp-clamav` reste `starting` 5 minutes | Chargement des signatures, normal | Attendez ; si ça dure plus de 10 minutes, vérifiez la mémoire libre (`free -h`) |
| `evdp-web` `unhealthy` | Erreur de configuration | `docker compose logs evdp-web \| tail -n 50` |
| Le navigateur affiche `Bad Request (400)` | Adresse utilisée différente de celle de l'étape 6 | Utilisez l'adresse exacte, ou relancez l'étape 6 sur une installation neuve |
| Connexion refusée avec `CSRF` | Adresse en `http` au lieu de `https` (ou l'inverse) | Après l'étape 11, utilisez toujours `https://` |
| Code à 6 chiffres toujours refusé | Heure du serveur décalée | Étape 2 |
| Téléphone de l'administrateur perdu | — | Code de secours ; à défaut, sur le serveur : `docker compose exec evdp-web python manage.py reset_mfa <email>` |
| Aucun email ne part | Mailpit encore actif, ou paramètres SMTP | `messagerie.md`, tableau des erreurs |
| `evdp-nginx` s'arrête après l'étape 11 | Fichier de certificat manquant ou mal nommé | `docker compose logs evdp-nginx \| tail -n 20` ; vérifiez les trois noms de fichiers |

Pour un diagnostic, les journaux de tous les services :

```bash
docker compose logs --tail 50
```
