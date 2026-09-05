"""Limitation de debit applicative (anti brute-force / anti-abus).

Implementation sans dependance externe : compteur a fenetre fixe glissante
stocke dans le cache (Redis en production, locmem en test).

Resilience : si le cache est indisponible, la limitation s'ouvre plutot que de
rendre la plateforme inaccessible ; l'incident est journalise (voir
apps.core.cache).
"""

import functools
import hashlib
import time

from django.conf import settings
from django.http import HttpResponse

from .cache import CacheUnavailable, safe_add, safe_delete, safe_incr, safe_set
from .middleware import get_client_ip

_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_rate(rate):
    """'10/5m' -> (10, 300 secondes)."""
    count, _, period = rate.partition("/")
    period = period.strip() or "1m"
    unit = period[-1]
    amount = period[:-1] or "1"
    return int(count), int(amount) * _UNITS[unit]


def _bucket_key(scope, identifier, window):
    digest = hashlib.sha256(f"{scope}:{identifier}".encode()).hexdigest()[:32]
    return f"evdp:rl:{scope}:{digest}:{window}"


def hit(scope, identifier, rate):
    """Enregistre une tentative. Retourne (autorise, secondes_restantes)."""
    limit, seconds = parse_rate(rate)
    now = int(time.time())
    window = now // seconds
    key = _bucket_key(scope, identifier, window)
    remaining_window = seconds - (now % seconds)

    try:
        added = safe_add(key, 1, timeout=seconds)
        if added:
            current = 1
        else:
            try:
                current = safe_incr(key) or 1
            except ValueError:
                # La cle a expire entre le add et le incr.
                safe_set(key, 1, timeout=seconds)
                current = 1
    except CacheUnavailable:
        # Cache indisponible : on laisse passer plutot que de bloquer la
        # plateforme nationale. L'incident est deja journalise.
        return True, remaining_window

    return current <= limit, remaining_window


def reset(scope, identifier):
    """Remet le compteur a zero (par ex. apres une connexion reussie)."""
    now = int(time.time())
    for seconds in _UNITS.values():
        safe_delete(_bucket_key(scope, identifier, now // seconds))


def rate_limited(scope, rate=None, key_func=None, methods=("POST",)):
    """Decorateur de vue appliquant une limite de debit par IP."""

    def decorator(view_func):
        @functools.wraps(view_func)
        def wrapper(request, *args, **kwargs):
            effective = rate or settings.EVDP["RATE_LIMITS"].get(scope, "30/1m")
            if request.method in methods:
                identifier = key_func(request) if key_func else (get_client_ip(request) or "-")
                allowed, retry_after = hit(scope, identifier, effective)
                if not allowed:
                    response = HttpResponse(
                        "Trop de tentatives. Veuillez reessayer plus tard.",
                        status=429,
                        content_type="text/plain; charset=utf-8",
                    )
                    response["Retry-After"] = str(retry_after)
                    return response
            return view_func(request, *args, **kwargs)

        return wrapper

    return decorator
