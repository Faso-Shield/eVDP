"""Elevation de session par second facteur.

Le controle est un middleware et non un decorateur de vue. Trois raisons :

- `/admin/` a sa propre page de connexion, qui appelle `login()` sans passer
  par les vues de ce module. Un decorateur pose sur la connexion eVDP y
  laisserait une porte ouverte.
- La liste des vues a proteger est l'application entiere. En decorateur, une
  vue ajoutee demain serait accessible par oubli ; ici le refus est le
  defaut et la dispense est explicite, courte et relue.
- Le second facteur porte sur la session, pas sur une action : c'est un etat
  transverse, au meme rang que l'authentification elle-meme.

La session est authentifiee des la connexion mais reste **non elevee** tant
que le code TOTP n'a pas ete valide. Dans cet etat, seules les vues
d'enrolement, de verification et de deconnexion repondent.
"""

from django.contrib import messages
from django.http import JsonResponse
from django.shortcuts import redirect

from .mfa import is_required

#: Cle de session marquant une session elevee.
SESSION_KEY = "mfa_verified"

#: Prefixes joignables sans second facteur. Deconnexion comprise : un compte
#: en cours d'enrolement doit pouvoir renoncer et fermer sa session.
EXEMPT_PREFIXES = (
    "/mfa/",
    "/logout/",
    "/admin/logout/",
    "/static/",
    "/media/",
    "/health/",
    "/ready/",
    "/metrics/",
)


def session_is_elevated(request):
    return bool(request.session.get(SESSION_KEY))


def elevate(request):
    """Eleve la session, avec un identifiant neuf.

    Le privilege change a cet instant : l'identifiant de session change avec
    lui, comme `login()` le fait a l'authentification. Une session observee
    avant le second facteur ne vaut plus rien apres.
    """
    request.session.cycle_key()
    request.session[SESSION_KEY] = True


class MfaEnforcementMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        user = getattr(request, "user", None)
        if is_required(user) and not session_is_elevated(request):
            if not request.path.startswith(EXEMPT_PREFIXES):
                return self._refuse(request, user)
        return self.get_response(request)

    def _refuse(self, request, user):
        """Renvoie vers le parcours TOTP, ou refuse net hors navigation.

        Une requete d'API authentifiee par session recoit un 403 : une
        redirection vers une page HTML n'aurait aucun sens pour un client
        machine, et le laisser croire a un succes serait pire.
        """
        if request.path.startswith("/api/"):
            return JsonResponse(
                {"detail": "Double authentification requise sur ce compte."},
                status=403,
            )
        if user.mfa_pending_enrollment:
            messages.info(
                request,
                "Votre role exige la double authentification. "
                "Enregistrez un authentificateur pour continuer.",
            )
            return redirect("accounts:mfa_setup")
        return redirect("accounts:mfa_challenge")
