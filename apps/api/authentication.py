"""Authentification par cle d'API (integration machine)."""

import hashlib

from django.utils import timezone
from rest_framework import authentication, exceptions

from apps.accounts.models import ApiKey

HEADER = "HTTP_X_EVDP_API_KEY"
PREFIX_LENGTH = 8


def hash_key(raw_key):
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def generate_key():
    """Genere une cle d'API. La valeur en clair n'est retournee qu'une fois."""
    import secrets

    raw = f"evdp_{secrets.token_urlsafe(36)}"
    return raw, raw[:PREFIX_LENGTH], hash_key(raw)


class ApiKeyAuthentication(authentication.BaseAuthentication):
    """En-tete `X-eVDP-Api-Key`. Aucune cle n'est stockee en clair."""

    def authenticate(self, request):
        raw_key = request.META.get(HEADER, "").strip()
        if not raw_key:
            return None
        entry = (
            ApiKey.objects.select_related("user")
            .filter(key_hash=hash_key(raw_key), is_active=True)
            .first()
        )
        if entry is None or not entry.is_usable:
            raise exceptions.AuthenticationFailed("Cle d'API invalide ou expiree.")
        if not entry.user.is_active:
            raise exceptions.AuthenticationFailed("Compte desactive.")
        ApiKey.objects.filter(pk=entry.pk).update(last_used_at=timezone.now())
        return (entry.user, entry)

    def authenticate_header(self, request):
        return "X-eVDP-Api-Key"
