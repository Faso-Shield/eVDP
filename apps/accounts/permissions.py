"""Controles d'acces reutilisables (vues Django et API DRF).

Toute decision d'autorisation est prise ici, cote serveur, a partir du role
persiste en base. Un refus est systematiquement audite.
"""

import functools

from django.core.exceptions import PermissionDenied
from rest_framework.permissions import BasePermission

from apps.audit.models import AuditAction
from apps.audit.services import log_denied

from .roles import Capability, Role


def user_has_capability(user, capability):
    return bool(
        user
        and user.is_authenticated
        and getattr(user, "has_capability", None)
        and user.has_capability(capability)
    )


def deny(request, reason, obj=None):
    log_denied(
        AuditAction.PERMISSION_DENIED,
        actor=getattr(request, "user", None),
        obj=obj,
        request=request,
        reason=reason,
        path=getattr(request, "path", ""),
    )
    raise PermissionDenied(reason)


def require_capability(*capabilities):
    """Exige au moins une des capacites indiquees."""

    def decorator(view_func):
        @functools.wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if not any(user_has_capability(request.user, cap) for cap in capabilities):
                deny(request, "Capacite requise: " + ", ".join(capabilities))
            return view_func(request, *args, **kwargs)

        return wrapper

    return decorator


def require_roles(*roles):
    """Exige l'un des roles indiques (le superutilisateur passe toujours)."""

    def decorator(view_func):
        @functools.wraps(view_func)
        def wrapper(request, *args, **kwargs):
            user = request.user
            if not (user.is_authenticated and (user.is_superuser or user.role in roles)):
                deny(request, "Role requis: " + ", ".join(roles))
            return view_func(request, *args, **kwargs)

        return wrapper

    return decorator


def require_not_read_only(view_func):
    """Empeche un role d'audit d'effectuer une ecriture metier."""

    @functools.wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if request.method not in ("GET", "HEAD", "OPTIONS") and getattr(
            request.user, "is_read_only", False
        ):
            deny(request, "Role en lecture seule.")
        return view_func(request, *args, **kwargs)

    return wrapper


# ---------------------------------------------------------------------------
# Permissions DRF
# ---------------------------------------------------------------------------
class HasCapability(BasePermission):
    """Verifie `required_capability` (ou `required_capabilities`) sur la vue."""

    message = "Vous ne disposez pas de la capacite requise."

    def has_permission(self, request, view):
        caps = getattr(view, "required_capabilities", None)
        if caps is None:
            single = getattr(view, "required_capability", None)
            caps = [single] if single else []
        if not caps:
            return request.user and request.user.is_authenticated
        allowed = any(user_has_capability(request.user, cap) for cap in caps)
        if not allowed:
            log_denied(
                AuditAction.PERMISSION_DENIED,
                actor=request.user if request.user.is_authenticated else None,
                request=request,
                reason="capability",
                path=request.path,
            )
        return allowed


class IsNationalStaff(BasePermission):
    message = "Reserve aux equipes nationales."

    def has_permission(self, request, view):
        return bool(
            request.user and request.user.is_authenticated and request.user.is_national
        )


class ReadOnlyForAuditors(BasePermission):
    def has_permission(self, request, view):
        if request.method in ("GET", "HEAD", "OPTIONS"):
            return True
        return not getattr(request.user, "is_read_only", False)


class IsVerifiedResearcher(BasePermission):
    message = "Votre adresse email doit etre verifiee."

    def has_permission(self, request, view):
        user = request.user
        return bool(user and user.is_authenticated and user.email_verified)


__all__ = [
    "Capability",
    "Role",
    "require_capability",
    "require_roles",
    "require_not_read_only",
    "user_has_capability",
    "deny",
    "HasCapability",
    "IsNationalStaff",
    "ReadOnlyForAuditors",
    "IsVerifiedResearcher",
]
