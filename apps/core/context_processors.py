"""Contexte global disponible dans tous les gabarits."""

from django.conf import settings


def evdp_context(request):
    user = getattr(request, "user", None)
    unread = 0
    nav = {
        "coordination": False,
        "manage_programs": False,
        "draft_advisory": False,
        "manage_organizations": False,
        "view_audit_log": False,
        "national_dashboard": False,
        "manage_users": False,
    }
    if user is not None and user.is_authenticated:
        from apps.accounts.roles import Capability
        from apps.notifications.models import Notification

        unread = Notification.objects.filter(recipient=user, read_at=None).count()
        # Un chercheur ne doit jamais voir de lien vers une zone reservee au
        # CSIRT/a une organisation : le backend refuse deja l'acces (isolation
        # stricte par capacite), mais un lien menant a un ecran "Acces refuse"
        # est une mauvaise experience, pas une protection.
        nav["coordination"] = bool(user.is_national or user.is_organization_user)
        nav["manage_programs"] = user.has_capability(Capability.MANAGE_PROGRAM)
        nav["draft_advisory"] = user.has_capability(Capability.DRAFT_ADVISORY)
        nav["manage_organizations"] = user.has_capability(
            Capability.MANAGE_ORGANIZATION
        ) or user.has_capability(Capability.MANAGE_ALL_ORGANIZATIONS)
        nav["view_audit_log"] = user.has_capability(Capability.VIEW_AUDIT_LOG)
        # dashboard:home aiguille vers national/csirt/organisation/chercheur
        # selon le role (apps/dashboard/views.py::home). Seul le premier cas
        # (national) n'a pas deja son propre lien de menu ci-dessous : pour
        # tous les autres roles, "Tableau de bord" menerait exactement a la
        # meme page que leur lien dedie (Vue CSIRT / Vue organisation /
        # Espace chercheur) — un doublon a masquer, meme logique que
        # ci-dessus plutot qu'un vrai second acces.
        nav["national_dashboard"] = user.has_capability(Capability.VIEW_NATIONAL_DASHBOARD)
        nav["manage_users"] = user.has_capability(Capability.MANAGE_USERS)
    return {
        "EVDP": settings.EVDP,
        "PLATFORM_NAME": settings.EVDP["PLATFORM_NAME"],
        "PLATFORM_TAGLINE": settings.EVDP["PLATFORM_TAGLINE"],
        "PROJECT_CODE": settings.EVDP["PROJECT_CODE"],
        "unread_notifications": unread,
        "nav": nav,
    }
