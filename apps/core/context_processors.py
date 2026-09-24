"""Contexte global disponible dans tous les gabarits."""

from django.conf import settings

from .navigation import sidebar_sections


def _can_report(user):
    from apps.reports.services import may_report

    return may_report(user)


def evdp_context(request):
    user = getattr(request, "user", None)
    unread = 0
    claims = []
    if user is not None and user.is_authenticated:
        from apps.notifications.models import Notification

        unread = Notification.objects.filter(recipient=user, read_at=None).count()
        if not user.is_researcher:
            from apps.coordination.services import my_claims

            claims = my_claims(user)
    return {
        "EVDP": settings.EVDP,
        "PLATFORM_NAME": settings.EVDP["PLATFORM_NAME"],
        "PLATFORM_TAGLINE": settings.EVDP["PLATFORM_TAGLINE"],
        "PROJECT_CODE": settings.EVDP["PROJECT_CODE"],
        "unread_notifications": unread,
        "can_report": _can_report(user),
        "my_claims_count": len(claims),
        "my_idle_claims_count": sum(1 for entry in claims if entry["idle"]),
        "sidebar_sections": sidebar_sections(user, claims_count=len(claims)),
    }
