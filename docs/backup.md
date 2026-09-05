# Sauvegarde et restauration — eVDP

> Les sauvegardes eVDP contiennent des **vulnérabilités non corrigées** et des
> preuves de concept. Elles doivent être chiffrées, stockées hors du serveur
> et leur accès restreint au même niveau que la plateforme elle-même.

---

## 1. Périmètre

| Élément | Contenu | Criticité |
|---------|---------|-----------|
| PostgreSQL | Dossiers, rapports, messages, audit, comptes | **Critique** |
| MinIO | Pièces jointes, preuves de concept | **Critique** |
| `.env` | Secrets | **Critique** — hors sauvegarde automatique |
| Volumes Redis | Cache et file d'attente | Non critique (reconstructible) |

---

## 2. Scripts fournis

| Script | Rôle |
|--------|------|
| `scripts/backup_db.sh` | Dump PostgreSQL compressé, rotation |
| `scripts/backup_minio.sh` | Miroir du bucket, archive compressée, rotation |
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
./scripts/backup_minio.sh
# → backups/evdp-minio-20260905-030000.tar.gz
```

Le script effectue un miroir du bucket avec le client `mc` puis archive le
résultat.

---

## 5. Restauration

```bash
./scripts/restore_db.sh backups/evdp-db-20260905-020000.sql.gz
```

Le script exige une confirmation explicite (`RESTAURER`), arrête les services
applicatifs, restaure, puis les redémarre.

### Pièces jointes

```bash
tar xzf backups/evdp-minio-20260905-030000.tar.gz -C /tmp/restore
docker compose run --rm --entrypoint sh evdp-minio-init -c '
  mc alias set evdp "$MINIO_ENDPOINT" "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" &&
  mc mirror /restore/evdp-attachments "evdp/$MINIO_BUCKET"
'
```

---

## 6. Chiffrement

```bash
gpg --encrypt --recipient sauvegarde@anssi.bf \
    backups/evdp-db-20260905-020000.sql.gz

shred -u backups/evdp-db-20260905-020000.sql.gz   # supprimer le clair
```

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
0 3 * * * /home/evdp/evdp/scripts/backup_minio.sh >> /var/log/evdp-backup.log 2>&1
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
4. `docker compose up -d evdp-db evdp-redis evdp-minio`
5. `./scripts/restore_db.sh <sauvegarde>`
6. Restaurer les pièces jointes MinIO.
7. `docker compose up -d`
8. Vérifier `/ready/` et le contrôle post-restauration ci-dessus.
9. Faire tourner les secrets si le sinistre est d'origine malveillante.
