"""Limitation de debit DRF resiliente.

La limitation standard de DRF leve une exception si le cache est injoignable,
ce qui transforme une panne de cache en panne totale de l'API. Cette variante
journalise l'incident et laisse passer la requete (fail-open), conformement au
choix documente dans docs/security.md.
"""

import logging

from rest_framework.throttling import ScopedRateThrottle

logger = logging.getLogger("evdp.security")


class ResilientScopedRateThrottle(ScopedRateThrottle):
    def allow_request(self, request, view):
        try:
            return super().allow_request(request, view)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "throttle_backend_unavailable",
                extra={"error": exc.__class__.__name__, "path": request.path},
            )
            return True

    def throttle_success(self):
        try:
            return super().throttle_success()
        except Exception:  # noqa: BLE001
            return True
