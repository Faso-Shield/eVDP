#!/bin/sh
# Initialisation MinIO : creation du bucket prive des pieces jointes.
set -eu

echo "[evdp] Configuration du client MinIO…"
until mc alias set evdp "${MINIO_ENDPOINT}" "${MINIO_ROOT_USER}" "${MINIO_ROOT_PASSWORD}" >/dev/null 2>&1; do
    echo "[evdp] Attente de MinIO…"
    sleep 2
done

if ! mc ls "evdp/${MINIO_BUCKET}" >/dev/null 2>&1; then
    echo "[evdp] Creation du bucket ${MINIO_BUCKET}…"
    mc mb "evdp/${MINIO_BUCKET}"
fi

# Le bucket ne doit jamais etre lisible publiquement : les pieces jointes
# contiennent des preuves de concept.
mc anonymous set none "evdp/${MINIO_BUCKET}"

# Versionnement : protege contre la suppression accidentelle d'une preuve.
mc version enable "evdp/${MINIO_BUCKET}" || true

echo "[evdp] Bucket ${MINIO_BUCKET} pret (acces prive)."
