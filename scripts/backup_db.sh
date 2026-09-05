#!/usr/bin/env bash
# =============================================================================
# eVDP - sauvegarde de la base PostgreSQL
#
#   ./scripts/backup_db.sh
#
# Variables : BACKUP_DIR (defaut ./backups), RETENTION_DAYS (defaut 30)
#
# ATTENTION : l'archive produite contient des vulnerabilites NON CORRIGEES.
# Chiffrez-la et stockez-la hors du serveur (voir docs/backup.md).
# =============================================================================
set -Eeuo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKUP_DIR="${BACKUP_DIR:-${PROJECT_DIR}/backups}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
ARCHIVE="${BACKUP_DIR}/evdp-db-${TIMESTAMP}.sql.gz"

log() { printf '[evdp-backup] %s\n' "$*"; }
fail() { printf '[evdp-backup] ERREUR: %s\n' "$*" >&2; exit 1; }

cd "${PROJECT_DIR}"

command -v docker >/dev/null 2>&1 || fail "docker est introuvable."
docker compose ps evdp-db --format '{{.State}}' 2>/dev/null | grep -q running \
    || fail "Le service evdp-db n'est pas demarre."

mkdir -p "${BACKUP_DIR}"
chmod 700 "${BACKUP_DIR}"

POSTGRES_USER="${POSTGRES_USER:-evdp}"
POSTGRES_DB="${POSTGRES_DB:-evdp}"
if [ -f "${PROJECT_DIR}/.env" ]; then
    POSTGRES_USER="$(grep -E '^POSTGRES_USER=' "${PROJECT_DIR}/.env" | cut -d= -f2- || echo "${POSTGRES_USER}")"
    POSTGRES_DB="$(grep -E '^POSTGRES_DB=' "${PROJECT_DIR}/.env" | cut -d= -f2- || echo "${POSTGRES_DB}")"
fi

log "Sauvegarde de ${POSTGRES_DB} vers ${ARCHIVE}…"
docker compose exec -T evdp-db \
    pg_dump --username="${POSTGRES_USER}" --dbname="${POSTGRES_DB}" \
            --clean --if-exists --no-owner --no-privileges \
    | gzip -9 > "${ARCHIVE}"

# Une archive tronquee est pire qu'aucune archive : on verifie avant de purger.
gzip -t "${ARCHIVE}" || fail "Archive corrompue : ${ARCHIVE}"

chmod 600 "${ARCHIVE}"
SIZE="$(du -h "${ARCHIVE}" | cut -f1)"
log "Sauvegarde terminee (${SIZE})."

log "Purge des sauvegardes de plus de ${RETENTION_DAYS} jours…"
find "${BACKUP_DIR}" -name 'evdp-db-*.sql.gz' -type f -mtime "+${RETENTION_DAYS}" -print -delete

log "Sauvegardes disponibles :"
ls -lh "${BACKUP_DIR}"/evdp-db-*.sql.gz 2>/dev/null | tail -5 || true

cat <<'REMINDER'

[evdp-backup] RAPPEL SECURITE
  Cette archive contient des vulnerabilites non corrigees.
    gpg --encrypt --recipient sauvegarde@anssi.bf <archive>
    rsync -avz backups/*.gpg sauvegarde@site-distant:/backups/evdp/
REMINDER
