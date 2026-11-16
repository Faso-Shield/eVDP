# syntax=docker/dockerfile:1.7
# =============================================================================
# eVDP - image applicative (web, worker, beat)
# Construction multi-etapes : les outils de compilation ne sont pas embarques
# dans l'image finale.
# =============================================================================

FROM python:3.12-slim-bookworm AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install --no-install-recommends -y \
        build-essential=12.9 \
        libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /wheels
COPY requirements/base.txt requirements/lock.txt requirements/
RUN python -m pip install --upgrade pip \
    && pip wheel --wheel-dir /wheels/dist \
       -r requirements/base.txt -c requirements/lock.txt


# -----------------------------------------------------------------------------
FROM python:3.12-slim-bookworm AS runtime

LABEL org.opencontainers.image.title="eVDP" \
      org.opencontainers.image.description="Plateforme nationale de divulgation coordonnee de vulnerabilites" \
      org.opencontainers.image.vendor="ANSSI-BF / CSIRT National" \
      org.opencontainers.image.source="https://github.com/Faso-Shield/eVDP" \
      org.opencontainers.image.licenses="Proprietary"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DJANGO_SETTINGS_MODULE=config.settings.prod \
    PATH="/home/evdp/.local/bin:${PATH}"

# curl est requis par les healthchecks ; libpq5 par psycopg.
# apt-get upgrade applique les correctifs de securite Debian publies apres
# la derniere reconstruction de l'image python officielle (scan Trivy).
RUN apt-get update && apt-get upgrade -y \
    && apt-get install --no-install-recommends -y \
        libpq5 \
        curl \
        tini \
    && rm -rf /var/lib/apt/lists/*

# Utilisateur non privilegie : l'application ne tourne jamais en root.
RUN groupadd --gid 10001 evdp \
    && useradd --uid 10001 --gid evdp --create-home --shell /usr/sbin/nologin evdp

WORKDIR /app

COPY --from=builder /wheels/dist /wheels/dist
COPY requirements/base.txt requirements/lock.txt /tmp/
RUN pip install --no-index --find-links=/wheels/dist \
        -r /tmp/base.txt -c /tmp/lock.txt \
    && rm -rf /wheels /tmp/base.txt /tmp/lock.txt

COPY --chown=evdp:evdp . /app

RUN mkdir -p /app/staticfiles /app/media \
    && chown -R evdp:evdp /app/staticfiles /app/media \
    && chmod +x /app/docker/web/entrypoint.sh

USER evdp

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD ["sh", "-c", "curl -fsS http://localhost:8000/health/ || exit 1"]

ENTRYPOINT ["/usr/bin/tini", "--", "/app/docker/web/entrypoint.sh"]
CMD ["web"]
