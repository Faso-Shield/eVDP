#!/usr/bin/env bash
# =============================================================================
# eVDP - sauvegarde des pieces jointes (volume evdp-media)
#
#   ./scripts/backup_media.sh
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
ARCHIVE="${BACKUP_DIR}/evdp-media-${TIMESTAMP}.tar.gz"

log() { printf '[evdp-backup] %s\n' "$*"; }
fail() { printf '[evdp-backup] ERREUR: %s\n' "$*" >&2; exit 1; }

cd "${PROJECT_DIR}"

command -v docker >/dev/null 2>&1 || fail "docker est introuvable."
docker compose ps evdp-web --format '{{.State}}' 2>/dev/null | grep -q running \
    || fail "Le service evdp-web n'est pas demarre."

mkdir -p "${BACKUP_DIR}"
chmod 700 "${BACKUP_DIR}"
umask 077

log "Archivage de /app/media vers ${ARCHIVE}…"
docker compose exec -T evdp-web tar -C /app -czf - media > "${ARCHIVE}" \
    || fail "Echec de l'archivage."
chmod 600 "${ARCHIVE}"

tar -tzf "${ARCHIVE}" >/dev/null || fail "Archive corrompue : ${ARCHIVE}"

FILES="$(tar -tzf "${ARCHIVE}" | wc -l)"
SIZE="$(du -h "${ARCHIVE}" | cut -f1)"
log "Sauvegarde terminee : ${FILES} entrees, ${SIZE}."

log "Purge des sauvegardes de plus de ${RETENTION_DAYS} jours…"
find "${BACKUP_DIR}" -name 'evdp-media-*.tar.gz' -type f -mtime "+${RETENTION_DAYS}" -print -delete

cat <<'REMINDER'

[evdp-backup] RAPPEL SECURITE
  Cette archive contient des preuves de concept exploitables.
    gpg --encrypt --recipient sauvegarde@anssi.bf <archive>
REMINDER
