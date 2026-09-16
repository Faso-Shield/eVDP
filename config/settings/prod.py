"""Reglages de production eVDP (durcis)."""

from .base import *  # noqa: F401,F403
from .base import env

DEBUG = False

# En production, SECRET_KEY et ALLOWED_HOSTS sont obligatoires.
SECRET_KEY = env("SECRET_KEY")
ALLOWED_HOSTS = env.list("ALLOWED_HOSTS")
CSRF_TRUSTED_ORIGINS = env.list("CSRF_TRUSTED_ORIGINS", default=[])

# TLS termine par Nginx : on fait confiance a l'en-tete transmis par le proxy.
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SECURE_SSL_REDIRECT = env.bool("SECURE_SSL_REDIRECT", default=True)
# Les cookies/CSP "secure only" n'ont de sens que si le TLS est reellement
# actif (SECURE_SSL_REDIRECT=True) : sinon le navigateur refuse d'envoyer les
# cookies "Secure" et/ou force les sous-ressources (CSS/JS/images) en HTTPS
# inexistant, cassant respectivement l'authentification et le design.
SESSION_COOKIE_SECURE = SECURE_SSL_REDIRECT
CSRF_COOKIE_SECURE = SECURE_SSL_REDIRECT
SECURE_HSTS_SECONDS = env.int("SECURE_HSTS_SECONDS", default=31536000)
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

# Le CSP de production interdit l'inline non necessaire cote scripts.
CSP_DIRECTIVES = {
    "default-src": "'self'",
    "script-src": "'self'",
    "style-src": "'self' 'unsafe-inline'",
    "img-src": "'self' data:",
    "font-src": "'self' data:",
    "connect-src": "'self'",
    "frame-ancestors": "'none'",
    "base-uri": "'self'",
    "form-action": "'self'",
    "object-src": "'none'",
}
if SECURE_SSL_REDIRECT:
    CSP_DIRECTIVES["upgrade-insecure-requests"] = ""

STORAGES["staticfiles"] = {  # noqa: F405
    "BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage"
}
