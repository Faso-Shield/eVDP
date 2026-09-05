#!/usr/bin/env bash
# =============================================================================
# eVDP - sauvegarde des pieces jointes (MinIO)
#
#   ./scripts/backup_minio.sh
#
# Variables : BACKUP_DIR (defaut ./backups), RETENTION_DAYS (defaut 30)
#
# ATTENTION : ces fichiers sont des PREUVES DE CONCEPT de vulnerabilites non
# corrigees. Chiffrez l'archive et stockez-la hors du serveur.
# =============================================================================
set -Eeuo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKUP_DIR="${BACKUP_DIR:-${PROJECT_DIR}/backups}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
STAGING="${BACKUP_DIR}/.minio-${TIMESTAMP}"
ARCHIVE="${BACKUP_DIR}/evdp-minio-${TIMESTAMP}.tar.gz"

log() { printf '[evdp-backup] %s\n' "$*"; }
fail() { printf '[evdp-backup] ERREUR: %s\n' "$*" >&2; exit 1; }
cleanup() { rm -rf "${STAGING}"; }
trap cleanup EXIT

cd "${PROJECT_DIR}"

docker compose ps evdp-minio --format '{{.State}}' 2>/dev/null | grep -q running \
    || fail "Le service evdp-minio n'est pas demarre."

mkdir -p "${STAGING}"
chmod 700 "${BACKUP_DIR}" "${STAGING}"

BUCKET="${MINIO_BUCKET:-evdp-attachments}"
if [ -f "${PROJECT_DIR}/.env" ]; then
    BUCKET="$(grep -E '^MINIO_BUCKET=' "${PROJECT_DIR}/.env" | cut -d= -f2- || echo "${BUCKET}")"
fi

log "Miroir du bucket ${BUCKET}…"
docker compose run --rm --no-deps \
    -v "${STAGING}:/backup" \
    --entrypoint sh evdp-minio-init -c '
        set -e
        mc alias set evdp "$MINIO_ENDPOINT" "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" >/dev/null
        mc mirror --overwrite --remove "evdp/$MINIO_BUCKET" "/backup/$MINIO_BUCKET"
    ' || fail "Echec du miroir MinIO."

log "Compression…"
tar -czf "${ARCHIVE}" -C "${STAGING}" .
chmod 600 "${ARCHIVE}"

tar -tzf "${ARCHIVE}" >/dev/null || fail "Archive corrompue : ${ARCHIVE}"

FILES="$(tar -tzf "${ARCHIVE}" | wc -l)"
SIZE="$(du -h "${ARCHIVE}" | cut -f1)"
log "Sauvegarde terminee : ${FILES} entrees, ${SIZE}."

log "Purge des sauvegardes de plus de ${RETENTION_DAYS} jours…"
find "${BACKUP_DIR}" -name 'evdp-minio-*.tar.gz' -type f -mtime "+${RETENTION_DAYS}" -print -delete

cat <<'REMINDER'

[evdp-backup] RAPPEL SECURITE
  Cette archive contient des preuves de concept exploitables.
    gpg --encrypt --recipient sauvegarde@anssi.bf <archive>
REMINDER
