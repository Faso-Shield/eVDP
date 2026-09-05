"""Acces au cache tolerant a la panne.

La limitation de debit s'appuie sur Redis. Si Redis devient indisponible, la
plateforme doit continuer a servir les signalements : une indisponibilite du
cache ne doit pas provoquer une indisponibilite nationale.

Compromis assume : en cas de panne du cache, la limitation de debit s'ouvre
(fail-open) et l'evenement est journalise en niveau WARNING sur le logger
`evdp.security` afin d'etre detecte par la supervision.
"""

import logging

from django.core.cache import cache

logger = logging.getLogger("evdp.security")


class CacheUnavailable(Exception):
    """Le backend de cache ne repond pas."""


def _warn(operation, exc):
    logger.warning(
        "cache_unavailable",
        extra={"operation": operation, "error": exc.__class__.__name__},
    )


def safe_get(key, default=None):
    try:
        return cache.get(key, default)
    except Exception as exc:  # noqa: BLE001
        _warn("get", exc)
        raise CacheUnavailable from exc


def safe_set(key, value, timeout=None):
    try:
        cache.set(key, value, timeout=timeout)
        return True
    except Exception as exc:  # noqa: BLE001
        _warn("set", exc)
        raise CacheUnavailable from exc


def safe_add(key, value, timeout=None):
    try:
        return cache.add(key, value, timeout=timeout)
    except Exception as exc:  # noqa: BLE001
        _warn("add", exc)
        raise CacheUnavailable from exc


def safe_incr(key):
    try:
        return cache.incr(key)
    except ValueError:
        raise
    except Exception as exc:  # noqa: BLE001
        _warn("incr", exc)
        raise CacheUnavailable from exc


def safe_delete(key):
    try:
        cache.delete(key)
    except Exception as exc:  # noqa: BLE001
        _warn("delete", exc)


def is_available():
    try:
        cache.set("evdp:cache:probe", "1", timeout=5)
        return cache.get("evdp:cache:probe") == "1"
    except Exception:  # noqa: BLE001
        return False
