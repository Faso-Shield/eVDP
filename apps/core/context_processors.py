"""Contexte global disponible dans tous les gabarits."""

from django.conf import settings

from .navigation import sidebar_sections


def evdp_context(request):
    user = getattr(request, "user", None)
    unread = 0
    if user is not None and user.is_authenticated:
        from apps.notifications.models import Notification

        unread = Notification.objects.filter(recipient=user, read_at=None).count()
    return {
        "EVDP": settings.EVDP,
        "PLATFORM_NAME": settings.EVDP["PLATFORM_NAME"],
        "PLATFORM_TAGLINE": settings.EVDP["PLATFORM_TAGLINE"],
        "PROJECT_CODE": settings.EVDP["PROJECT_CODE"],
        "unread_notifications": unread,
        "sidebar_sections": sidebar_sections(user),
        "MAP": {"tiles": settings.MAP_TILE_URL, "attribution": settings.MAP_ATTRIBUTION},
    }
