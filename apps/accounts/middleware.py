"""Impose la double authentification aux roles internes a privilege.

Le TOTP existe (apps.accounts.mfa) mais reste par defaut une option que
l'utilisateur peut ignorer indefiniment. Pour les roles qui voient des cases
sensibles (voir MFA_REQUIRED_ROLES), l'activation devient une porte
bloquante : toute requete est redirigee vers l'ecran d'activation tant que
mfa_enabled est faux, a l'exception stricte de ce qu'il faut pour l'activer
ou se deconnecter.
"""

from django.contrib import messages
from django.shortcuts import redirect
from django.urls import Resolver404, resolve, reverse

from .roles import MFA_REQUIRED_ROLES

#: Points d'entree accessibles sans MFA malgre un role a privilege : juste de
#: quoi activer le second facteur ou quitter la session.
EXEMPT_URL_NAMES = {
    "accounts:mfa_activate",
    "accounts:logout",
    "accounts:verify_email",
    "accounts:login",
    "accounts:mfa_verify",
}


class MFAEnforcementMiddleware:
    """Redirige vers l'activation MFA tant qu'un role a privilege ne l'a pas fait."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if self._must_enforce(request):
            messages.warning(
                request,
                "Votre role exige la double authentification. "
                "Activez-la pour accéder à la plateforme.",
            )
            return redirect(reverse("accounts:mfa_activate"))
        return self.get_response(request)

    @staticmethod
    def _must_enforce(request):
        user = getattr(request, "user", None)
        if user is None or not user.is_authenticated:
            return False
        if user.role not in MFA_REQUIRED_ROLES or user.mfa_enabled:
            return False
        if request.path.startswith("/api/"):
            # L'API s'authentifie par cle (apps.api.authentication), un canal
            # distinct du second facteur de connexion web.
            return False
        try:
            match = resolve(request.path)
        except Resolver404:
            return False
        url_name = f"{match.namespace}:{match.url_name}" if match.namespace else match.url_name
        return url_name not in EXEMPT_URL_NAMES
