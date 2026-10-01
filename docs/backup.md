# Sauvegarde et restauration — eVDP

> Les sauvegardes eVDP contiennent des **vulnérabilités non corrigées** et des
> preuves de concept. Elles doivent être chiffrées, stockées hors du serveur
> et leur accès restreint au même niveau que la plateforme elle-même.

---

## 1. Périmètre

| Élément | Contenu | Criticité |
|---------|---------|-----------|
| PostgreSQL | Dossiers, rapports, messages, audit, comptes | **Critique** |
| Volume `evdp-media` | Pièces jointes, preuves de concept | **Critique** |
| `.env` | Secrets | **Critique** — hors sauvegarde automatique |
| `FIELD_ENCRYPTION_KEY` | Clé des données de versement chiffrées en base | **Critique** — sans elle, un dump restauré est illisible |
| Volumes Redis | Cache et file d'attente | Non critique (reconstructible) |

---

## 2. Scripts fournis

| Script | Rôle |
|--------|------|
| `scripts/backup_db.sh` | Dump PostgreSQL compressé, rotation |
| `scripts/backup_media.sh` | Archive du volume des pièces jointes, rotation |
| `scripts/restore_db.sh` | Restauration avec confirmation explicite |

```bash
chmod +x scripts/*.sh
```

---

## 3. Sauvegarde de la base

```bash
./scripts/backup_db.sh
# → backups/evdp-db-20260905-020000.sql.gz
```

Variables : `BACKUP_DIR` (défaut `./backups`), `RETENTION_DAYS` (défaut 30).

Le script utilise `pg_dump` dans le conteneur, compresse en gzip, vérifie
l'intégrité de l'archive et purge les sauvegardes expirées.

---

## 4. Sauvegarde des pièces jointes

```bash
./scripts/backup_media.sh
# → backups/evdp-media-20260905-030000.tar.gz
```

Le script archive le dossier `/app/media` du conteneur `evdp-web` (volume
`evdp-media`), vérifie l'archive et purge les sauvegardes expirées.

### Ancienne installation avec MinIO

Les images MinIO ne sont plus distribuées publiquement : les pièces jointes
sont désormais stockées sur disque. Une instance qui en conserve dans MinIO
les copie une fois vers le disque, tant que l'image MinIO est encore présente
sur la machine (le volume `evdp-minio-data` n'est pas supprimé) :

```bash
# 1. Relancer l'ancien MinIO, seul, sur le reseau interne
docker run -d --name evdp-minio --network evdp_evdp-backend \
  -v evdp_evdp-minio-data:/data \
  -e MINIO_ROOT_USER=evdp-minio -e MINIO_ROOT_PASSWORD=<ancien mot de passe> \
  minio/minio:RELEASE.2024-10-13T13-34-11Z server /data

# 2. Compter, puis copier (les variables MINIO_* de .env designent la source)
docker compose run --rm evdp-web python manage.py copier_fichiers_s3_vers_disque --dry-run
docker compose run --rm evdp-web python manage.py copier_fichiers_s3_vers_disque

# 3. Arreter l'ancien MinIO
docker rm -f evdp-minio
```

La commande garde le nom de chaque fichier (aucune ligne de la base n'est
modifiée), ne recopie pas un fichier déjà présent et contrôle l'empreinte
SHA-256 de chaque pièce jointe copiée. Le préfixe `evdp_` des volumes et du
réseau est le nom du projet Compose (`docker volume ls`).

---

## 5. Restauration

```bash
./scripts/restore_db.sh backups/evdp-db-20260905-020000.sql.gz
```

Le script exige une confirmation explicite (`RESTAURER`), arrête les services
applicatifs, restaure, puis les redémarre.

### Pièces jointes

```bash
docker compose exec -T evdp-web tar -C /app -xzf - < backups/evdp-media-20260905-030000.tar.gz
```

---

## 6. Chiffrement

```bash
gpg --encrypt --recipient sauvegarde@anssi.bf \
    backups/evdp-db-20260905-020000.sql.gz

shred -u backups/evdp-db-20260905-020000.sql.gz   # supprimer le clair
```

Les données de versement des chercheurs (identité, IBAN, mobile money,
crypto, PayPal) sont en outre chiffrées dans la base elle-même avec
`FIELD_ENCRYPTION_KEY`. Conservez cette clé à part, dans le coffre des
secrets : un dump restauré sans elle garde ces champs illisibles. Pour
changer de clé, placez la nouvelle en tête (`nouvelle,ancienne`), lancez
`python manage.py rechiffrer_champs`, puis retirez l'ancienne.

Déchiffrement :

```bash
gpg --decrypt backups/evdp-db-20260905-020000.sql.gz.gpg \
    > backups/evdp-db-20260905-020000.sql.gz
```

---

## 7. Externalisation

```bash
# Copie chiffrée vers un site distant
rsync -avz --delete backups/*.gpg sauvegarde@site-distant:/backups/evdp/

# Ou vers un stockage objet
mc mirror backups/ distant/evdp-backups/
```

Règle **3-2-1** : 3 copies, 2 supports différents, 1 hors site.

---

## 8. Planification

```cron
# crontab -u evdp -e
0 2 * * * /home/evdp/evdp/scripts/backup_db.sh    >> /var/log/evdp-backup.log 2>&1
0 3 * * * /home/evdp/evdp/scripts/backup_media.sh >> /var/log/evdp-backup.log 2>&1
0 4 * * 0 find /home/evdp/evdp/backups -name '*.gpg' -mtime +90 -delete
```

---

## 9. Politique de rétention

| Fréquence | Rétention | Support |
|-----------|-----------|---------|
| Quotidienne | 30 jours | Disque local chiffré |
| Hebdomadaire | 12 semaines | Site distant |
| Mensuelle | 12 mois | Archivage froid |
| Annuelle | 5 ans | Archivage froid |

Objectifs cibles : **RPO 24 h**, **RTO 4 h**.

---

## 10. Test de restauration

Une sauvegarde non testée n'est pas une sauvegarde. **Trimestriellement :**

1. Monter une instance de test isolée.
2. Restaurer la dernière sauvegarde quotidienne.
3. Vérifier : nombre de dossiers, dernier advisory publié, connexion,
   téléchargement d'une pièce jointe, intégrité du journal d'audit.
4. Consigner la durée réelle de restauration.
5. Détruire l'instance de test **et ses données**.

```bash
docker compose exec evdp-web python manage.py shell -c "
from apps.coordination.models import Case
from apps.disclosures.models import Advisory
from apps.audit.models import AuditLog
print('Dossiers  :', Case.objects.count())
print('Advisories:', Advisory.objects.count())
print('Audit     :', AuditLog.objects.count())
"
```

---

## 11. Reprise après sinistre

1. Provisionner un serveur conforme à `docs/deployment.md`.
2. Restaurer `.env` depuis le coffre à secrets (jamais depuis les sauvegardes).
3. `git clone` du dépôt à la version en production.
4. `docker compose up -d evdp-db evdp-redis evdp-web`
5. `./scripts/restore_db.sh <sauvegarde>`
6. Restaurer les pièces jointes (`backup_media.sh`, section 5).
7. `docker compose up -d`
8. Vérifier `/ready/` et le contrôle post-restauration ci-dessus.
9. Faire tourner les secrets si le sinistre est d'origine malveillante.
