# Guide de configuration de la messagerie eVDP

Ce guide explique, étape par étape, comment faire envoyer de vrais emails à
la plateforme eVDP : ce qu'il faut demander, où l'écrire, comment le tester
et comment réparer une panne. Il s'adresse à la personne qui installe ou
administre la plateforme ; aucune connaissance préalable des serveurs mail
n'est nécessaire.

**En bref**

- Pour un essai ou une démonstration, **il n'y a rien à faire** : les emails
  sont gardés dans Mailpit, consultable sur http://127.0.0.1:8025 (§2).
- En production, il faut le **serveur mail de la structure** : 6 valeurs à
  écrire dans `.env`, puis un test d'envoi (§3).
- **Aucune reconstruction de l'image** n'est nécessaire : `.env` modifié,
  `docker compose up -d` suffit.

**Sommaire**

1. [Comprendre comment eVDP envoie ses emails](#1-comprendre-comment-evdp-envoie-ses-emails)
2. [Mode essai : Mailpit](#2-mode-essai--mailpit)
3. [Mise en production, étape par étape](#3-mise-en-production-étape-par-étape)
4. [Cas particuliers](#4-cas-particuliers)
5. [Sécurité réseau](#5-sécurité-réseau)
6. [Surveillance et dépannage](#6-surveillance-et-dépannage)
7. [Référence des variables](#7-référence-des-variables)
8. [Checklist finale](#8-checklist-finale)
9. [Questions fréquentes](#9-questions-fréquentes)

---

## 1. Comprendre comment eVDP envoie ses emails

### 1.1 Le principe

La plateforme n'envoie pas elle-même ses emails sur Internet. Elle les
**remet à un serveur mail** (serveur « SMTP »), exactement comme on dépose
une lettre à la poste : c'est ce serveur qui les distribue aux destinataires.

```
  Plateforme eVDP  ──────►  Serveur SMTP  ──────►  Boîte du destinataire
  (evdp-web,                (celui de la            (chercheur, DSI,
   evdp-worker)              structure)              analyste...)
```

Configurer la messagerie, c'est donc **dire à eVDP quel serveur SMTP
utiliser et comment s'y connecter**. Rien d'autre.

### 1.2 Les emails envoyés par la plateforme

Ces emails ne sont pas accessoires : sans eux, un chercheur ne peut même
pas activer son compte.

| Email | Destinataire | Envoyé par |
|---|---|---|
| Activation du compte (lien valable 24 h) | personne qui s'inscrit | `evdp-web` |
| Réinitialisation du mot de passe | utilisateur qui l'a demandée | `evdp-web` |
| Accusé de réception, lien de suivi | déclarant, y compris sans compte | `evdp-web` |
| Nouveau rapport, nouveau message, nouvelle pièce jointe, demande d'informations | acteurs du dossier | `evdp-web` |
| Changement de statut, validation, rejet, doublon, escalade | acteurs du dossier | `evdp-web` |
| Échéance SLA proche ou dépassée, rappels de prise en charge, divulgation imminente | CSIRT, organisations | `evdp-worker` (tâches planifiées) |
| Récompense proposée, approuvée, rejetée, payée | chercheur concerné | `evdp-web` |

**Confidentialité** : ces emails ne contiennent **jamais** de détail
technique, de preuve de concept ni le titre de la vulnérabilité. Ils
annoncent seulement qu'une action est disponible, avec une référence
(`EVDP-2026-000123`) et un lien vers l'espace sécurisé. Les textes sont
modifiables par un administrateur dans l'administration Django, rubrique
**Modèles d'email**.

### 1.3 Deux modes

| Mode | Serveur utilisé | Les emails partent-ils vraiment ? |
|---|---|---|
| **Essai / démonstration** (par défaut) | Mailpit, fourni avec la plateforme | **Non** : ils sont gardés et consultables dans Mailpit |
| **Production** | serveur SMTP de la structure | Oui |

---

## 2. Mode essai : Mailpit

**Mailpit** est un faux serveur mail livré avec la plateforme. Il accepte
tous les emails et les garde, sans jamais les envoyer. C'est le mode par
défaut : un `docker compose up -d` sur un projet fraîchement cloné l'active
sans aucune configuration.

**Consulter les emails** : ouvrez **http://127.0.0.1:8025** dans un
navigateur, sur la machine qui fait tourner Docker.

À savoir :

- Mailpit n'est joignable **que depuis cette machine** (127.0.0.1), jamais
  depuis le réseau : c'est voulu.
- Il **perd ses messages** à chaque redémarrage de son conteneur.
- Si le port 8025 est déjà utilisé sur la machine, choisissez-en un autre
  dans `.env` (`MAILPIT_PORT=8026`), puis `docker compose up -d evdp-mailpit`.
- Pour vérifier que la plateforme écrit bien à Mailpit :

  ```bash
  docker compose exec evdp-web python manage.py sendtestemail test@exemple.bf
  ```

  L'email apparaît aussitôt sur http://127.0.0.1:8025.

> **Attention** : en mode essai, un chercheur qui s'inscrit ne reçoit
> **jamais** son lien d'activation dans sa vraie boîte. Pour une plateforme
> ouverte au public, passez au §3.

---

## 3. Mise en production, étape par étape

### Étape 1 : rassembler les informations

Tout vient du **service informatique de la structure** (ou de
l'administrateur de sa messagerie). Il vous faut :

| Information | Exemple |
|---|---|
| Adresse du serveur SMTP | `smtp.ministere.gov.bf` |
| Port | `587`, `465` ou `25` |
| Mode de chiffrement | STARTTLS, SSL/TLS, ou aucun (relais interne) |
| Compte d'envoi et son mot de passe | `no-reply@ministere.gov.bf` |
| Adresse d'expédition affichée | `eVDP <no-reply@ministere.gov.bf>` |
| Le certificat du serveur est-il émis par une autorité interne ? | oui / non |

Demandez de préférence un **compte dédié** à la plateforme
(`no-reply@…`) plutôt que la boîte d'une personne : il survit aux départs,
et on peut le révoquer sans gêner personne.

**Message type à envoyer au service informatique :**

> Bonjour,
>
> Nous mettons en service la plateforme eVDP, qui doit envoyer des emails
> automatiques (activation de compte, notifications de dossiers). Pourriez-vous
> nous fournir :
>
> 1. un compte d'envoi dédié, par exemple `no-reply@<domaine>`, et son mot de passe ;
> 2. l'adresse du serveur SMTP, le port et le mode de chiffrement (STARTTLS sur 587, ou SSL/TLS sur 465) ;
> 3. si le certificat du serveur SMTP est émis par une autorité de certification interne, le certificat de cette autorité (format PEM) ;
> 4. la confirmation que les enregistrements SPF, DKIM et DMARC du domaine autorisent ce serveur à envoyer pour cette adresse.
>
> Le serveur eVDP enverra depuis l'adresse IP : `<IP du serveur>`.
>
> Merci.

### Étape 2 : comprendre le port et le chiffrement

Il existe deux façons de chiffrer la connexion entre eVDP et le serveur
mail, plus un cas sans chiffrement :

- **STARTTLS (port 587)** : la connexion commence en clair, puis les deux
  côtés passent au chiffrement. C'est le cas le plus courant.
- **SSL/TLS direct (port 465)** : la connexion est chiffrée dès le premier
  instant.
- **Relais interne (port 25)** : pas de chiffrement ni de mot de passe ; le
  serveur accepte eVDP d'après son adresse IP (voir §4.1).

| Le serveur accepte… | `EMAIL_PORT` | `EMAIL_USE_TLS` | `EMAIL_USE_SSL` |
|---|---|---|---|
| STARTTLS | `587` | `True` | `False` |
| SSL/TLS direct | `465` | `False` | `True` |
| Relais interne | `25` | `False` | `False` |

> **Jamais `EMAIL_USE_TLS=True` et `EMAIL_USE_SSL=True` ensemble** : la
> plateforme refuse alors de démarrer, avec un message qui l'explique.
>
> Un mauvais couple (par exemple le port 465 avec `EMAIL_USE_TLS=True`) ne
> provoque pas d'erreur immédiate : la connexion attend jusqu'au délai
> `EMAIL_TIMEOUT` (30 secondes), puis l'envoi échoue. D'où l'importance du
> test de l'étape 6.

### Étape 3 : remplir le fichier `.env`

Ouvrez le fichier `.env` à la racine du projet et remplacez la section
**Messagerie**. Trois exemples complets, selon votre cas :

**Cas A : STARTTLS sur le port 587 (le plus courant)**

```dotenv
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=smtp.ministere.gov.bf
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_USE_SSL=False
EMAIL_USER=no-reply@ministere.gov.bf
EMAIL_PASSWORD=le-mot-de-passe-fourni
EMAIL_TIMEOUT=30
DEFAULT_FROM_EMAIL=eVDP <no-reply@ministere.gov.bf>
```

**Cas B : SSL/TLS sur le port 465**

```dotenv
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=smtp.ministere.gov.bf
EMAIL_PORT=465
EMAIL_USE_TLS=False
EMAIL_USE_SSL=True
EMAIL_USER=no-reply@ministere.gov.bf
EMAIL_PASSWORD=le-mot-de-passe-fourni
EMAIL_TIMEOUT=30
DEFAULT_FROM_EMAIL=eVDP <no-reply@ministere.gov.bf>
```

**Cas C : relais interne sur le port 25**

```dotenv
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=relais.ministere.gov.bf
EMAIL_PORT=25
EMAIL_USE_TLS=False
EMAIL_USE_SSL=False
EMAIL_USER=
EMAIL_PASSWORD=
EMAIL_TIMEOUT=30
DEFAULT_FROM_EMAIL=eVDP <no-reply@ministere.gov.bf>
```

Trois règles :

- **Aucune espace** autour du signe `=`, et pas de guillemets.
- **`DEFAULT_FROM_EMAIL` doit être l'adresse du compte d'envoi** (ou une
  adresse que ce compte a le droit d'utiliser). La plupart des serveurs
  refusent d'envoyer au nom d'une autre adresse (erreur `550` ou `553`).
- Le fichier `.env` contient un mot de passe : il ne doit **jamais** être
  partagé ni envoyé sur Git (il est déjà exclu par `.gitignore`). Protégez-le
  sur le serveur : `chmod 600 .env`.

### Étape 4 : vérifier l'adresse publique de la plateforme

Les emails contiennent des liens (activation, réinitialisation, accès à un
dossier). Ils sont construits à partir de `SITE_BASE_URL`, dans le même
fichier `.env` :

```dotenv
SITE_BASE_URL=https://vdp.ministere.gov.bf
```

C'est l'adresse **exacte** que les utilisateurs tapent dans leur navigateur,
avec `https://` et sans `/` final. Laissée vide ou fausse, les emails partent
bien, mais leurs liens ne mènent nulle part.

### Étape 5 : appliquer la configuration

```bash
docker compose up -d
```

Docker recrée les conteneurs dont la configuration a changé. Pas besoin de
reconstruire l'image (`--build`) : seuls les réglages ont changé, pas le code.

Si `EMAIL_USE_TLS` et `EMAIL_USE_SSL` sont tous deux à `True`, `evdp-web` ne
démarre pas : `docker compose logs evdp-web` affiche
`EMAIL_USE_TLS et EMAIL_USE_SSL sont exclusifs`. Corrigez `.env` et relancez.

### Étape 6 : tester l'envoi

Envoyez un email d'essai à une adresse **que vous consultez réellement** :

```bash
docker compose exec evdp-web python manage.py sendtestemail votre.adresse@exemple.bf
```

- **Aucun message affiché** : l'email a été accepté par le serveur SMTP.
- **Une erreur s'affiche** : cherchez-la dans le tableau du §6.3.

Ensuite, vérifiez dans votre boîte :

1. l'email est arrivé **en boîte de réception**, pas en spam (sinon : étape 7) ;
2. l'expéditeur affiché est le bon (`DEFAULT_FROM_EMAIL`).

Enfin, testez un **vrai parcours** : créez un compte chercheur avec une
adresse que vous consultez, et vérifiez que le lien d'activation arrive et
**fonctionne** (il confirme `SITE_BASE_URL`).

### Étape 7 : éviter le spam (SPF, DKIM, DMARC)

Les messageries des destinataires (Gmail, Outlook…) vérifient que le serveur
qui envoie a bien le droit d'utiliser le domaine de l'expéditeur. Sans ces
trois réglages, les emails d'eVDP arrivent en spam, ou sont refusés.

Ces réglages se font dans la **zone DNS du domaine**, par son
administrateur, pas dans eVDP :

| Réglage | Rôle | Exemple d'enregistrement DNS (TXT) |
|---|---|---|
| **SPF** | liste les serveurs autorisés à envoyer pour le domaine | `v=spf1 ip4:203.0.113.25 -all` sur `ministere.gov.bf` |
| **DKIM** | le serveur SMTP signe chaque email ; la clé publique est publiée en DNS | fournie par le serveur SMTP, publiée sur `<sélecteur>._domainkey.ministere.gov.bf` |
| **DMARC** | indique aux destinataires quoi faire si SPF ou DKIM échoue | `v=DMARC1; p=quarantine; rua=mailto:dmarc@ministere.gov.bf` sur `_dmarc.ministere.gov.bf` |

Ces exemples sont indicatifs : les valeurs réelles dépendent du serveur
mail de la structure. Si la messagerie existe déjà et envoie correctement
pour ce domaine, ces enregistrements sont généralement déjà en place : il
suffit d'utiliser ce même serveur.

**Vérification** : dans l'email de test reçu, affichez l'original (« Afficher
l'original » dans Gmail, « Afficher la source » ailleurs) et cherchez la
ligne `Authentication-Results` : elle doit indiquer `spf=pass`, `dkim=pass`
et `dmarc=pass`.

### Étape 8 : désactiver Mailpit

En production, Mailpit ne sert plus. Pour qu'il ne démarre plus, **ne
modifiez pas `docker-compose.yml`** : il entrerait en conflit avec chaque
mise à jour du projet. Créez plutôt, à côté, un fichier
`docker-compose.override.yml`. Docker Compose le lit automatiquement, et il
est exclu du dépôt : il reste propre à ce serveur.

```yaml
services:
  evdp-mailpit:
    profiles: ["mailpit"]
```

Puis arrêtez l'instance déjà lancée :

```bash
docker compose rm -sf evdp-mailpit
```

Pour le relancer un jour (diagnostic) :
`docker compose --profile mailpit up -d evdp-mailpit`.

---

## 4. Cas particuliers

### 4.1 Relais interne sans mot de passe (port 25)

Fréquent dans les administrations : le serveur mail accepte eVDP parce
qu'il reconnaît son **adresse IP**, sans compte ni mot de passe.

- Utilisez le **cas C** de l'étape 3 (`EMAIL_USER` et `EMAIL_PASSWORD` vides).
- Le service informatique doit **autoriser l'adresse IP du serveur eVDP**
  sur le relais. Sinon : erreur `SMTPRecipientsRefused` (code `550`,
  « relay access denied »).
- Les emails circulent **en clair** jusqu'au relais : réservez ce mode à un
  relais situé sur le même réseau de confiance que le serveur eVDP.

### 4.2 Certificat émis par une autorité interne

Les messageries d'État utilisent souvent un certificat signé par une
**autorité de certification (AC) interne**, que la plateforme ne connaît
pas. L'envoi échoue alors avec `CERTIFICATE_VERIFY_FAILED`.

**Ne désactivez pas la vérification du certificat** : elle protège les mots
de passe et les emails contre l'interception. Ajoutez plutôt l'AC interne
aux autorités reconnues par les deux conteneurs qui envoient des emails.

1. Obtenez du service informatique le certificat de l'AC, au format PEM
   (fichier texte commençant par `-----BEGIN CERTIFICATE-----`). Appelons-le
   `ac-interne.pem`.

2. Construisez un fichier qui contient **les autorités publiques de l'image
   et l'AC interne**. Les deux sont nécessaires : la variable
   `SSL_CERT_FILE` (point 3 ci-dessous) **remplace** la liste par défaut,
   elle ne la complète pas.

   ```bash
   mkdir -p docker/certs
   docker compose exec evdp-web cat /etc/ssl/certs/ca-certificates.crt > docker/certs/smtp-ca-bundle.pem
   cat ac-interne.pem >> docker/certs/smtp-ca-bundle.pem
   ```

3. Déclarez-le dans `docker-compose.override.yml` (le même fichier qu'à
   l'étape 8 du §3) :

   ```yaml
   services:
     evdp-mailpit:
       profiles: ["mailpit"]
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

4. Appliquez et retestez :

   ```bash
   docker compose up -d
   docker compose exec evdp-web python manage.py sendtestemail votre.adresse@exemple.bf
   ```

Après chaque **mise à jour de l'image**, reconstruisez ce fichier (étape 2) :
les autorités publiques qu'il contient datent du jour de sa création. Les
fichiers `.pem` sont exclus de Git par `.gitignore`.

### 4.3 Messagerie hébergée (Gmail, Microsoft 365…)

Possible, mais à réserver aux essais ou aux petites structures : une
plateforme nationale doit de préférence s'appuyer sur une messagerie
maîtrisée par l'État.

- **Gmail / Google Workspace** : `smtp.gmail.com`, port 587 (STARTTLS) ou
  465 (SSL). Le mot de passe habituel est refusé : il faut un **mot de
  passe d'application**, qui suppose la validation en deux étapes activée
  sur le compte. Les quotas d'envoi quotidiens sont limités.
- **Microsoft 365** : `smtp.office365.com`, port 587 (STARTTLS).
  L'authentification SMTP doit être **autorisée pour la boîte d'envoi** par
  l'administrateur du tenant, et Microsoft restreint progressivement
  l'authentification par mot de passe : vérifiez la politique en vigueur
  avec lui.

Dans tous les cas, `DEFAULT_FROM_EMAIL` doit être l'adresse du compte.

---

## 5. Sécurité réseau

### 5.1 Comment les conteneurs accèdent au serveur mail

La plateforme est découpée en conteneurs Docker reliés par des réseaux
séparés :

```
                     Internet / réseau de la structure
                                  ▲
                                  │  sortie vers le serveur SMTP
                     ┌────────────┴────────────┐
                     │  réseau evdp-smtp       │
                     │  evdp-web   evdp-worker │
                     └────────────┬────────────┘
   ┌──────────────── réseau interne evdp-backend (coupé d'Internet) ──────┐
   │  evdp-web   evdp-worker   evdp-beat   evdp-db   evdp-redis   Mailpit │
   └──────────────────────────────────────────────────────────────────────┘
```

- La **base de données** et **Redis** sont sur un réseau interne, sans
  aucun accès à Internet.
- Seuls les deux conteneurs qui envoient des emails, `evdp-web` et
  `evdp-worker`, ont **en plus** une sortie (`evdp-smtp`) vers le serveur
  mail.
- C'est une **sortie uniquement** : rien n'entre par ce réseau. La
  plateforme reste accessible seulement par Nginx (ports 80/443).

### 5.2 Restreindre la sortie au seul serveur mail (recommandé)

Par défaut, `evdp-web` et `evdp-worker` peuvent joindre n'importe quelle
adresse. En production, limitez cette sortie au seul serveur SMTP avec le
pare-feu de l'hôte (Linux). Docker applique la chaîne `DOCKER-USER`
d'iptables au trafic de ses conteneurs.

```bash
# 1. Nom exact du réseau : il est préfixé par le nom du dossier du projet
docker network ls | grep evdp-smtp

# 2. Paramètres (à adapter)
SUBNET=$(docker network inspect evdp_evdp-smtp -f '{{(index .IPAM.Config 0).Subnet}}')
SMTP_IP=10.20.0.25          # adresse IP du serveur SMTP de la structure
DNS_IP=10.20.0.53           # résolveur DNS utilisé par l'hôte
SMTP_PORT=587               # 587, 465 ou 25 selon l'étape 2

# 3. Règles (-I insère en tête : la dernière saisie est évaluée la première)
sudo iptables -I DOCKER-USER -s "$SUBNET" -j DROP
sudo iptables -I DOCKER-USER -s "$SUBNET" -p tcp -d "$SMTP_IP" --dport "$SMTP_PORT" -j ACCEPT
sudo iptables -I DOCKER-USER -s "$SUBNET" -p udp -d "$DNS_IP" --dport 53 -j ACCEPT
sudo iptables -I DOCKER-USER -s "$SUBNET" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
```

Puis :

1. refaites le **test d'envoi** (étape 6) : il doit toujours fonctionner ;
2. rendez les règles **persistantes** (paquet `iptables-persistent` sur
   Debian/Ubuntu), sinon elles disparaissent au redémarrage.

Cet exemple est à adapter à la politique de pare-feu du serveur. Il ne
touche pas l'antivirus, qui a son propre réseau de sortie (`evdp-external`)
pour ses mises à jour.

---

## 6. Surveillance et dépannage

### 6.1 Ce qui se passe quand un email échoue

- La plateforme **continue de fonctionner** : un échec d'envoi ne bloque ni
  l'inscription, ni le traitement d'un dossier.
- L'email **n'est pas renvoyé** : il est perdu. Une notification reste
  toutefois visible dans l'espace de l'utilisateur (cloche des
  notifications), et un compte non activé peut redemander son lien.
- Une ligne **`email_delivery_failed`** est écrite au journal, avec la
  cause.

### 6.2 Lire le journal

```bash
docker compose logs evdp-web evdp-worker | grep email_delivery_failed
```

Exemple de ligne :

```json
{"level": "WARNING", "logger": "evdp.notifications",
 "message": "email_delivery_failed", "purpose": "notification",
 "recipient_domain": "exemple.bf", "error": "SMTPAuthenticationError",
 "smtp_code": 535, "smtp_reply": "5.7.8 Username and Password not accepted"}
```

| Champ | Signification |
|---|---|
| `purpose` | `notification` (dossiers, comptes) ou `activation` (lien d'activation) |
| `recipient_domain` | domaine du destinataire (jamais l'adresse complète) |
| `error` | type d'erreur : c'est la colonne de gauche du tableau §6.3 |
| `smtp_code`, `smtp_reply` | code et réponse du serveur mail, s'il a répondu |
| `detail` | cause réseau, TLS ou délai, si le serveur n'a pas répondu |

Ni le contenu de l'email ni l'adresse complète du destinataire ne figurent
au journal.

Les échecs de l'email de **réinitialisation du mot de passe** sont
journalisés par Django lui-même :

```bash
docker compose logs evdp-web | grep "Failed to send password reset"
```

Dans l'administration Django, rubrique **Notifications**, la colonne
**Emailed at** reste vide pour une notification dont l'email n'est pas
parti.

### 6.3 Tableau des erreurs

| Erreur (`sendtestemail`, ou champ `error` / `smtp_code`) | Cause probable | Que faire |
|---|---|---|
| `timed out`, `TimeoutError` (après 30 s) | mauvais couple port / chiffrement, ou port bloqué par un pare-feu | revoir l'étape 2 ; vérifier le pare-feu (§5.2) |
| `Connection refused`, `ConnectionRefusedError` | adresse ou port du serveur erroné | vérifier `EMAIL_HOST` et `EMAIL_PORT` |
| `Temporary failure in name resolution`, `Name or service not known` | le conteneur ne trouve pas le serveur : nom erroné, ou sortie réseau bloquée | vérifier `EMAIL_HOST` ; vérifier le DNS dans le pare-feu (§5.2) |
| `SMTPAuthenticationError`, code `535` | identifiant ou mot de passe refusé | vérifier `EMAIL_USER` et `EMAIL_PASSWORD` ; mot de passe d'application (§4.3) |
| `SMTPSenderRefused`, code `550` ou `553` | adresse d'expédition non autorisée pour ce compte | `DEFAULT_FROM_EMAIL` = adresse du compte (étape 3) |
| `SMTPRecipientsRefused`, code `550` | destinataire inconnu, ou relais qui refuse l'IP du serveur | vérifier l'adresse ; faire autoriser l'IP (§4.1) |
| `SSL: WRONG_VERSION_NUMBER` | `EMAIL_USE_SSL=True` sur un port STARTTLS | port 587 : `EMAIL_USE_TLS=True`, `EMAIL_USE_SSL=False` |
| `CERTIFICATE_VERIFY_FAILED` | certificat émis par une autorité interne | §4.2 |
| `SMTPNotSupportedError` (STARTTLS) | `EMAIL_USE_TLS=True` sur un serveur qui ne le propose pas | vérifier le mode de chiffrement avec le service informatique |
| `EMAIL_USE_TLS et EMAIL_USE_SSL sont exclusifs` (au démarrage) | les deux à `True` | un seul à `True` (étape 2) |
| Email reçu en spam | SPF, DKIM ou DMARC absents | étape 7 |
| Liens des emails incorrects | `SITE_BASE_URL` vide ou erronée | étape 4 |
| Inscription ou réinitialisation très lente | l'envoi attend le délai de 30 s | voir les lignes « timed out » ci-dessus |
| Emails visibles dans Mailpit mais pas dans les vraies boîtes | la plateforme écrit encore à Mailpit | `EMAIL_HOST` est resté `evdp-mailpit` (étape 3), puis `docker compose up -d` |

---

## 7. Référence des variables

Toutes se règlent dans `.env`.

| Variable | Valeur par défaut | Rôle |
|---|---|---|
| `EMAIL_BACKEND` | `django.core.mail.backends.smtp.EmailBackend` | mode d'envoi ; ne pas changer en production |
| `EMAIL_HOST` | `evdp-mailpit` | adresse du serveur SMTP |
| `EMAIL_PORT` | `1025` (Mailpit) | port du serveur SMTP |
| `EMAIL_USE_TLS` | `False` | `True` pour STARTTLS (port 587) |
| `EMAIL_USE_SSL` | `False` | `True` pour SSL/TLS direct (port 465) |
| `EMAIL_USER` | vide | compte d'envoi ; vide pour un relais interne |
| `EMAIL_PASSWORD` | vide | mot de passe du compte d'envoi |
| `EMAIL_TIMEOUT` | `30` | délai maximal d'une connexion, en secondes |
| `DEFAULT_FROM_EMAIL` | `eVDP <no-reply@evdp.bf>` | expéditeur affiché ; doit correspondre au compte |
| `SITE_BASE_URL` | vide | adresse publique, utilisée dans les liens des emails |
| `MAILPIT_PORT` | `8025` | port local de l'interface Mailpit |
| `EVDP_CONTACT_EMAIL` | `vdp@anssi.bf` | adresse de contact affichée sur le site (pas un réglage d'envoi) |

---

## 8. Checklist finale

- [ ] Informations SMTP obtenues du service informatique (étape 1)
- [ ] Port et chiffrement cohérents : un seul de `EMAIL_USE_TLS` / `EMAIL_USE_SSL` à `True`, ou aucun pour le port 25 (étape 2)
- [ ] `.env` rempli, `DEFAULT_FROM_EMAIL` = adresse du compte, `chmod 600 .env` (étape 3)
- [ ] `SITE_BASE_URL` = adresse publique réelle, en `https://` (étape 4)
- [ ] `docker compose up -d` exécuté (étape 5)
- [ ] `sendtestemail` reçu **en boîte de réception**, bon expéditeur (étape 6)
- [ ] Inscription de test : lien d'activation reçu et fonctionnel (étape 6)
- [ ] `spf=pass`, `dkim=pass`, `dmarc=pass` dans l'email reçu (étape 7)
- [ ] Mailpit désactivé par `docker-compose.override.yml` (étape 8)
- [ ] Certificat d'AC interne installé, si nécessaire (§4.2)
- [ ] Sortie réseau limitée au serveur SMTP, règles persistantes (§5.2)
- [ ] Surveillance de `email_delivery_failed` en place (§6.2)

---

## 9. Questions fréquentes

**Faut-il reconstruire l'image Docker après avoir changé la messagerie ?**
Non. Les réglages sont lus au démarrage depuis `.env` : `docker compose up -d`
suffit.

**Les emails contiennent-ils des informations sensibles ?**
Non. Ils ne donnent qu'une référence de dossier et un lien vers l'espace
sécurisé ; le contenu reste dans la plateforme, derrière l'authentification
(§1.2).

**Que se passe-t-il si le serveur mail tombe en panne ?**
La plateforme continue de fonctionner. Les emails envoyés pendant la panne
sont perdus (pas de nouvel essai automatique), mais les notifications
restent visibles dans l'espace des utilisateurs. Surveillez
`email_delivery_failed` (§6.2).

**Peut-on modifier le texte des emails ?**
Oui, sans toucher au code : administration Django, rubrique **Modèles
d'email**. Respectez la règle de confidentialité : aucun détail technique.

**Peut-on garder Mailpit en production pour « voir » les emails ?**
Non : Mailpit ne distribue rien. Une fois le vrai serveur configuré, les
emails ne passent plus par Mailpit ; désactivez-le (étape 8).

**Le test `sendtestemail` passe, mais un utilisateur ne reçoit rien.**
Vérifiez ses spams, puis le journal (`email_delivery_failed`, §6.2) : un
refus propre à son adresse (`SMTPRecipientsRefused`) ou un problème de
délivrabilité (étape 7) sont les causes les plus fréquentes.

**Où trouver le reste du déploiement (HTTPS, sauvegardes…) ?**
Dans [deployment.md](deployment.md).
