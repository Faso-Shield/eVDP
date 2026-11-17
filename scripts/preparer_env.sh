#!/usr/bin/env bash
# =============================================================================
# eVDP - preparation du fichier .env d'une nouvelle installation
#
#   bash scripts/preparer_env.sh                      (questions posees)
#   bash scripts/preparer_env.sh --adresse vdp.anssi.bf
#   bash scripts/preparer_env.sh --https              (passage en HTTPS)
#
# Premiere utilisation : cree .env a partir de .env.example et y place
#   - tous les secrets, generes aleatoirement pour CETTE installation ;
#   - le meme mot de passe Redis aux quatre endroits qui l'utilisent ;
#   - l'adresse du serveur (ALLOWED_HOSTS, CSRF_TRUSTED_ORIGINS, SITE_BASE_URL) ;
#   - l'image de l'application deja chargee (EVDP_IMAGE).
# Les secrets sont produits par l'image eVDP elle-meme : le serveur n'a besoin
# ni de Python ni d'acces Internet. Aucun secret n'est affiche a l'ecran.
#
# --https : sur un .env existant, active HTTPS (redirection, HSTS, adresses en
# https://) sans toucher aux secrets. A lancer une fois le certificat installe.
#
# Options :
#   --adresse NOM   nom DNS ou adresse IP par laquelle on joint la plateforme
#   --image IMAGE   image de l'application (defaut : la plus recente chargee)
#   --force         remplace un .env existant (l'ancien est conserve a cote)
# =============================================================================
set -Eeuo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${PROJECT_DIR}/.env"
EXAMPLE_FILE="${PROJECT_DIR}/.env.example"
IMAGE_REPO="ghcr.io/faso-shield/evdp-app"

log() { printf '[evdp] %s\n' "$*"; }
fail() { printf '[evdp] ERREUR : %s\n' "$*" >&2; exit 1; }

ADRESSE=""
IMAGE=""
FORCE=0
MODE="creation"

while [ $# -gt 0 ]; do
    case "$1" in
        --adresse) ADRESSE="${2:-}"; shift 2 ;;
        --image) IMAGE="${2:-}"; shift 2 ;;
        --force) FORCE=1; shift ;;
        --https) MODE="https"; shift ;;
        -h|--help) sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) fail "option inconnue : $1 (voir --help)" ;;
    esac
done

# Remplace la ligne CLE=... (non commentee) par CLE=VALEUR. La valeur passe
# par l'environnement : aucun caractere n'est interprete par awk.
set_var() {
    local key="$1" value="$2" file="$3"
    grep -q "^${key}=" "${file}" || fail "variable ${key} absente de ${file}."
    CLE="${key}" VALEUR="${value}" awk '
        index($0, ENVIRON["CLE"] "=") == 1 { print ENVIRON["CLE"] "=" ENVIRON["VALEUR"]; next }
        { print }
    ' "${file}" > "${file}.tmp" && mv "${file}.tmp" "${file}"
}

get_var() {
    sed -n "s/^$1=//p" "$2" | tail -n 1
}

check_adresse() {
    printf '%s' "$1" | grep -Eq '^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$' \
        || fail "adresse invalide : '$1'. Indiquez un nom (vdp.anssi.bf) ou une IP (10.20.0.10), sans http:// ni / final."
}

# --------------------------------------------------------------- mode HTTPS
if [ "${MODE}" = "https" ]; then
    [ -f "${ENV_FILE}" ] || fail ".env introuvable : lancez d'abord ce script sans --https."
    current="$(get_var SITE_BASE_URL "${ENV_FILE}")"
    ADRESSE="${ADRESSE:-${current#*://}}"
    ADRESSE="${ADRESSE%/}"
    check_adresse "${ADRESSE}"
    cp -p "${ENV_FILE}" "${ENV_FILE}.avant-https"
    set_var SECURE_SSL_REDIRECT True "${ENV_FILE}"
    set_var SECURE_HSTS_SECONDS 31536000 "${ENV_FILE}"
    set_var CSRF_TRUSTED_ORIGINS "https://${ADRESSE}" "${ENV_FILE}"
    set_var SITE_BASE_URL "https://${ADRESSE}" "${ENV_FILE}"
    chmod 600 "${ENV_FILE}"
    log "HTTPS active dans .env pour https://${ADRESSE}"
    log "Copie de l'ancien fichier : .env.avant-https"
    log "Appliquez : docker compose up -d --no-build"
    exit 0
fi

# --------------------------------------------------------------- creation
command -v docker >/dev/null 2>&1 || fail "docker est introuvable : installez Docker d'abord."
[ -f "${EXAMPLE_FILE}" ] || fail ".env.example introuvable dans ${PROJECT_DIR}."

if [ -f "${ENV_FILE}" ] && [ "${FORCE}" -ne 1 ]; then
    fail ".env existe deja. Il contient les cles de chiffrement : ne le remplacez que pour une installation neuve (--force)."
fi

if [ -z "${IMAGE}" ]; then
    IMAGE="$(docker image ls "${IMAGE_REPO}" --format '{{.Tag}}' \
        | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' | sort -V | tail -n 1 || true)"
    [ -n "${IMAGE}" ] || fail "aucune image ${IMAGE_REPO} chargee. Chargez d'abord les images (docker load)."
    IMAGE="${IMAGE_REPO}:${IMAGE}"
fi
docker image inspect "${IMAGE}" >/dev/null 2>&1 || fail "image ${IMAGE} absente. Chargez-la d'abord (docker load)."
log "Image de l'application : ${IMAGE}"

if [ -z "${ADRESSE}" ]; then
    printf 'Adresse du serveur (nom DNS ou IP, ex. vdp.anssi.bf ou 10.20.0.10) : '
    read -r ADRESSE
fi
ADRESSE="${ADRESSE#http://}"
ADRESSE="${ADRESSE#https://}"
ADRESSE="${ADRESSE%/}"
check_adresse "${ADRESSE}"

# Secrets generes dans l'image : Python et cryptography y sont presents.
SECRETS="$(docker run --rm --network none --entrypoint python "${IMAGE}" -c '
import secrets
from cryptography.fernet import Fernet
print("SECRET_KEY=" + secrets.token_urlsafe(64))
print("FIELD_ENCRYPTION_KEY=" + Fernet.generate_key().decode())
print("POSTGRES_PASSWORD=" + secrets.token_hex(24))
print("REDIS_PASSWORD=" + secrets.token_hex(24))
print("MESSAGE_INTEGRITY_KEY=" + secrets.token_urlsafe(48))
print("METRICS_TOKEN=" + secrets.token_urlsafe(48))
')" || fail "generation des secrets impossible avec ${IMAGE}."

secret() { printf '%s\n' "${SECRETS}" | sed -n "s/^$1=//p"; }

umask 077
cp "${EXAMPLE_FILE}" "${ENV_FILE}.nouveau"
f="${ENV_FILE}.nouveau"
for key in SECRET_KEY FIELD_ENCRYPTION_KEY POSTGRES_PASSWORD MESSAGE_INTEGRITY_KEY METRICS_TOKEN; do
    value="$(secret "${key}")"
    [ -n "${value}" ] || fail "secret ${key} vide."
    set_var "${key}" "${value}" "${f}"
done
redis="$(secret REDIS_PASSWORD)"
[ -n "${redis}" ] || fail "secret REDIS_PASSWORD vide."
set_var REDIS_PASSWORD "${redis}" "${f}"
for key in REDIS_URL CELERY_BROKER_URL CELERY_RESULT_BACKEND; do
    set_var "${key}" "redis://:${redis}@evdp-redis:6379/0" "${f}"
done

set_var ALLOWED_HOSTS "${ADRESSE},localhost,127.0.0.1,evdp-web,evdp-nginx" "${f}"
set_var CSRF_TRUSTED_ORIGINS "http://${ADRESSE}" "${f}"
set_var SITE_BASE_URL "http://${ADRESSE}" "${f}"

if grep -q '^EVDP_IMAGE=' "${f}"; then
    set_var EVDP_IMAGE "${IMAGE}" "${f}"
else
    printf '\nEVDP_IMAGE=%s\n' "${IMAGE}" >> "${f}"
fi

if grep -v '^[[:space:]]*#' "${f}" | grep -q 'CHANGEZ-MOI'; then
    fail "des valeurs CHANGEZ-MOI subsistent dans ${f} : verifiez .env.example."
fi

if [ -f "${ENV_FILE}" ]; then
    backup="${ENV_FILE}.ancien-$(date +%Y%m%d-%H%M%S)"
    cp -p "${ENV_FILE}" "${backup}"
    log "Ancien .env conserve : $(basename "${backup}")"
fi
mv "${f}" "${ENV_FILE}"
chmod 600 "${ENV_FILE}"

log ".env cree pour http://${ADRESSE} (droits 600)."
log "Secrets generes : SECRET_KEY, FIELD_ENCRYPTION_KEY, POSTGRES_PASSWORD,"
log "  REDIS_PASSWORD (x4), MESSAGE_INTEGRITY_KEY, METRICS_TOKEN."
log ""
log "IMPORTANT : copiez des maintenant .env sur un support sur, hors du serveur."
log "  Sans FIELD_ENCRYPTION_KEY et MESSAGE_INTEGRITY_KEY, les donnees"
log "  chiffrees et les signatures sont irrecuperables."
log ""
log "Messagerie : par defaut Mailpit (essai). Pour le vrai serveur SMTP,"
log "  voir docs/messagerie.md."
log "Etape suivante : docker compose up -d --no-build"
