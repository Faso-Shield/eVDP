"""Middlewares transverses eVDP."""

import threading

from django.conf import settings

_request_local = threading.local()


def get_current_request():
    """Retourne la requete HTTP courante (utilisee par le journal d'audit)."""
    return getattr(_request_local, "request", None)


def get_client_ip(request):
    """Adresse IP client en tenant compte du reverse proxy Nginx."""
    if request is None:
        return None
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
    if forwarded:
        return forwarded.split(",")[0].strip()[:45]
    return (request.META.get("REMOTE_ADDR") or "")[:45] or None


class RequestContextMiddleware:
    """Expose la requete courante pour l'audit sans la passer partout."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        _request_local.request = request
        try:
            return self.get_response(request)
        finally:
            _request_local.request = None


class SecurityHeadersMiddleware:
    """Ajoute CSP, Permissions-Policy et les en-tetes de durcissement."""

    def __init__(self, get_response):
        self.get_response = get_response
        directives = getattr(settings, "CSP_DIRECTIVES", {})
        self.csp = "; ".join(f"{name} {value}".strip() for name, value in directives.items())
        self.permissions_policy = getattr(settings, "PERMISSIONS_POLICY", "")

    def __call__(self, request):
        response = self.get_response(request)
        if self.csp and "Content-Security-Policy" not in response:
            response["Content-Security-Policy"] = self.csp
        if self.permissions_policy:
            response["Permissions-Policy"] = self.permissions_policy
        response.setdefault("X-Content-Type-Options", "nosniff")
        response.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        # Les reponses applicatives ne doivent jamais etre mises en cache par
        # un intermediaire : elles peuvent contenir des donnees de case.
        if request.path.startswith(("/dashboard", "/cases", "/api", "/attachments")):
            response["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
            response["Pragma"] = "no-cache"
        return response
