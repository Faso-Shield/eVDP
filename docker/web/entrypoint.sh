#!/bin/sh
# =============================================================================
# Point d'entree des conteneurs eVDP.
# Roles supportes : web | worker | beat | migrate | shell
# =============================================================================
set -eu

ROLE="${1:-web}"

wait_for() {
    host="$1"
    port="$2"
    label="$3"
    attempt=0
    until python -c "
import socket, sys
sock = socket.socket()
sock.settimeout(2)
try:
    sock.connect(('${host}', ${port}))
except OSError:
    sys.exit(1)
finally:
    sock.close()
" 2>/dev/null; do
        attempt=$((attempt + 1))
        if [ "${attempt}" -ge 60 ]; then
            echo "[evdp] ${label} (${host}:${port}) injoignable apres 60 tentatives." >&2
            exit 1
        fi
        echo "[evdp] Attente de ${label} (${host}:${port})…"
        sleep 2
    done
    echo "[evdp] ${label} disponible."
}

wait_for "${POSTGRES_HOST:-evdp-db}" "${POSTGRES_PORT:-5432}" "PostgreSQL"
wait_for "${REDIS_HOST:-evdp-redis}" "${REDIS_PORT:-6379}" "Redis"

case "${ROLE}" in
    web)
        echo "[evdp] Application des migrations…"
        python manage.py migrate --no-input
        echo "[evdp] Collecte des fichiers statiques…"
        python manage.py collectstatic --no-input --clear
        echo "[evdp] Demarrage de Gunicorn…"
        exec gunicorn config.wsgi:application \
            --bind 0.0.0.0:8000 \
            --workers "${GUNICORN_WORKERS:-3}" \
            --threads "${GUNICORN_THREADS:-2}" \
            --timeout "${GUNICORN_TIMEOUT:-60}" \
            --graceful-timeout 30 \
            --max-requests 1000 \
            --max-requests-jitter 100 \
            --access-logfile - \
            --error-logfile - \
            --capture-output
        ;;
    worker)
        exec celery -A config worker \
            --loglevel="${CELERY_LOG_LEVEL:-INFO}" \
            --concurrency="${CELERY_CONCURRENCY:-2}" \
            --max-tasks-per-child=200
        ;;
    beat)
        # Les migrations sont appliquees UNIQUEMENT par le role "web" :
        # deux processus migrate concurrents entrent en collision sur la
        # creation des tables. Le planificateur attend que le schema soit pret.
        attempt=0
        until python manage.py migrate --check --no-input >/dev/null 2>&1; do
            attempt=$((attempt + 1))
            if [ "${attempt}" -ge 60 ]; then
                echo "[evdp] Schema toujours incomplet apres 60 tentatives." >&2
                exit 1
            fi
            echo "[evdp] Attente de l'application des migrations par evdp-web…"
            sleep 5
        done
        echo "[evdp] Schema pret."
        # Le pidfile sert de sonde de sante : l'image slim ne fournit ni
        # pgrep ni ps.
        rm -f /tmp/celerybeat.pid
        exec celery -A config beat \
            --loglevel="${CELERY_LOG_LEVEL:-INFO}" \
            --pidfile=/tmp/celerybeat.pid \
            --scheduler django_celery_beat.schedulers:DatabaseScheduler
        ;;
    migrate)
        exec python manage.py migrate --no-input
        ;;
    seed)
        python manage.py migrate --no-input
        exec python manage.py seed_demo
        ;;
    shell)
        exec python manage.py shell
        ;;
    *)
        exec "$@"
        ;;
esac
