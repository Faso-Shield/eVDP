"""Middlewares transverses eVDP."""

import threading
import uuid

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


class RequestIDMiddleware:
    """Propage un identifiant unique par requete (NIST AU-3, tracabilite).

    L'ID est lu depuis l'en-tete X-Request-ID pose par Nginx, ou genere
    a defaut. Il est expose dans la reponse et accessible partout via
    get_current_request().META.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        request_id = request.META.get("HTTP_X_REQUEST_ID") or uuid.uuid4().hex
        request.META["HTTP_X_REQUEST_ID"] = request_id
        response = self.get_response(request)
        response["X-Request-ID"] = request_id
        return response


class SecurityHeadersMiddleware:
    """Ajoute CSP, Permissions-Policy et les en-tetes de durcissement.

    Conformite : OWASP Secure Headers, FASO SHIELD v2.0 section 5.1.
    """

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
        response.setdefault("X-Permitted-Cross-Domain-Policies", "none")
        response.setdefault("Cross-Origin-Embedder-Policy", "require-corp")
        if request.path.startswith(
            ("/dashboard", "/cases", "/api", "/attachments", "/admin", "/bounty", "/audit")
        ):
            response["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
            response["Pragma"] = "no-cache"
        return response
