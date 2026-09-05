"""Service d'ecriture du journal d'audit."""

import logging

from apps.core.middleware import get_client_ip, get_current_request

from .models import AuditAction, AuditLog, AuditResult

logger = logging.getLogger("evdp.audit")


def _sanitize(metadata):
    """Retire les cles susceptibles de contenir des secrets."""
    if not isinstance(metadata, dict):
        return {}
    forbidden = ("password", "token", "secret", "key", "authorization", "cookie")
    clean = {}
    for key, value in metadata.items():
        if any(word in str(key).lower() for word in forbidden):
            clean[key] = "[redacted]"
        elif isinstance(value, str) and len(value) > 2000:
            clean[key] = value[:2000] + "…"
        else:
            clean[key] = value
    return clean


def log_action(
    action,
    actor=None,
    obj=None,
    object_type="",
    object_id="",
    object_repr="",
    result=AuditResult.SUCCESS,
    request=None,
    **metadata,
):
    """Enregistre un evenement sensible.

    L'echec d'ecriture d'un audit ne doit jamais casser l'action metier, mais
    il est journalise en niveau ERROR pour detection.
    """
    request = request or get_current_request()
    if actor is None and request is not None:
        candidate = getattr(request, "user", None)
        if candidate is not None and candidate.is_authenticated:
            actor = candidate

    if obj is not None:
        object_type = object_type or obj.__class__.__name__
        object_id = object_id or str(getattr(obj, "pk", ""))
        object_repr = object_repr or str(obj)[:255]

    payload = {
        "actor": actor if getattr(actor, "pk", None) else None,
        "actor_label": (getattr(actor, "email", "") or "anonyme")[:254],
        "action": action,
        "object_type": object_type[:64],
        "object_id": str(object_id)[:64],
        "object_repr": (object_repr or "")[:255],
        "result": result,
        "ip_address": (get_client_ip(request) or "")[:45],
        "user_agent": (request.META.get("HTTP_USER_AGENT", "") if request else "")[:300],
        "metadata": _sanitize(metadata),
    }

    try:
        entry = AuditLog.objects.create(**payload)
    except Exception:  # pragma: no cover - resilience
        logger.exception("audit_write_failed", extra={"action": action})
        return None

    logger.info(
        "audit",
        extra={
            "action": action,
            "actor": payload["actor_label"],
            "object_type": payload["object_type"],
            "object_id": payload["object_id"],
            "result": result,
            "ip": payload["ip_address"],
        },
    )
    return entry


def log_denied(action, actor=None, obj=None, request=None, **metadata):
    return log_action(
        action,
        actor=actor,
        obj=obj,
        result=AuditResult.DENIED,
        request=request,
        **metadata,
    )


__all__ = ["log_action", "log_denied", "AuditAction", "AuditResult"]
