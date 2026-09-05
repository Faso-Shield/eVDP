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
COPY requirements/base.txt requirements/base.txt
RUN python -m pip install --upgrade pip \
    && pip wheel --wheel-dir /wheels/dist -r requirements/base.txt


# -----------------------------------------------------------------------------
FROM python:3.12-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DJANGO_SETTINGS_MODULE=config.settings.prod \
    PATH="/home/evdp/.local/bin:${PATH}"

# curl est requis par les healthchecks ; libpq5 par psycopg.
RUN apt-get update && apt-get install --no-install-recommends -y \
        libpq5 \
        curl \
        tini \
    && rm -rf /var/lib/apt/lists/*

# Utilisateur non privilegie : l'application ne tourne jamais en root.
RUN groupadd --gid 10001 evdp \
    && useradd --uid 10001 --gid evdp --create-home --shell /usr/sbin/nologin evdp

WORKDIR /app

COPY --from=builder /wheels/dist /wheels/dist
COPY requirements/base.txt /tmp/base.txt
RUN pip install --no-index --find-links=/wheels/dist -r /tmp/base.txt \
    && rm -rf /wheels /tmp/base.txt

COPY --chown=evdp:evdp . /app

RUN mkdir -p /app/staticfiles /app/media \
    && chown -R evdp:evdp /app/staticfiles /app/media \
    && chmod +x /app/docker/web/entrypoint.sh

USER evdp

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD curl -fsS http://localhost:8000/health/ || exit 1

ENTRYPOINT ["/usr/bin/tini", "--", "/app/docker/web/entrypoint.sh"]
CMD ["web"]
