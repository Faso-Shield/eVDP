#!/usr/bin/env bash
# =============================================================================
# eVDP - restauration de la base PostgreSQL
#
#   ./scripts/restore_db.sh backups/evdp-db-20260905-020000.sql.gz
#
# OPERATION DESTRUCTIVE : la base courante est ecrasee.
# Une confirmation explicite est exigee.
# =============================================================================
set -Eeuo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARCHIVE="${1:-}"

log() { printf '[evdp-restore] %s\n' "$*"; }
fail() { printf '[evdp-restore] ERREUR: %s\n' "$*" >&2; exit 1; }

cd "${PROJECT_DIR}"

[ -n "${ARCHIVE}" ] || fail "Usage: $0 <archive.sql.gz>"
[ -f "${ARCHIVE}" ] || fail "Archive introuvable : ${ARCHIVE}"
gzip -t "${ARCHIVE}" || fail "Archive corrompue : ${ARCHIVE}"

POSTGRES_USER="${POSTGRES_USER:-evdp}"
POSTGRES_DB="${POSTGRES_DB:-evdp}"
if [ -f "${PROJECT_DIR}/.env" ]; then
    POSTGRES_USER="$(grep -E '^POSTGRES_USER=' "${PROJECT_DIR}/.env" | cut -d= -f2- || echo "${POSTGRES_USER}")"
    POSTGRES_DB="$(grep -E '^POSTGRES_DB=' "${PROJECT_DIR}/.env" | cut -d= -f2- || echo "${POSTGRES_DB}")"
fi

cat <<EOF

  ============================================================
   RESTAURATION DE LA BASE eVDP
  ============================================================
   Archive     : ${ARCHIVE}
   Base cible  : ${POSTGRES_DB}
   Taille      : $(du -h "${ARCHIVE}" | cut -f1)

   TOUTES LES DONNEES ACTUELLES SERONT DEFINITIVEMENT PERDUES,
   y compris les dossiers et le journal d'audit.
  ============================================================

EOF

printf 'Tapez exactement RESTAURER pour confirmer : '
read -r CONFIRMATION
[ "${CONFIRMATION}" = "RESTAURER" ] || fail "Restauration annulee."

log "Arret des services applicatifs…"
docker compose stop evdp-web evdp-worker evdp-beat || true

log "Demarrage de la base…"
docker compose up -d evdp-db
sleep 5

log "Restauration en cours…"
gunzip -c "${ARCHIVE}" | docker compose exec -T evdp-db \
    psql --username="${POSTGRES_USER}" --dbname="${POSTGRES_DB}" --quiet

log "Application des migrations eventuellement plus recentes…"
docker compose run --rm evdp-web migrate

log "Redemarrage des services…"
docker compose up -d

log "Verification…"
sleep 10
docker compose exec -T evdp-web python manage.py shell -c "
from apps.audit.models import AuditLog
from apps.coordination.models import Case
from apps.disclosures.models import Advisory
print('Dossiers   :', Case.objects.count())
print('Advisories :', Advisory.objects.count())
print('Audit      :', AuditLog.objects.count())
" || log "Verification impossible : consultez 'docker compose logs evdp-web'."

log "Restauration terminee."
