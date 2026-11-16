"""Reglages de production eVDP (durcis).

Conformite : FASO SHIELD v2.0, ISO/IEC 29147, OWASP ASVS 4.0,
NIST 800-53, RFC 9116.
"""

from cryptography.fernet import Fernet
from django.core.exceptions import ImproperlyConfigured

from .base import *  # noqa: F401,F403
from .base import _IMG_SRC, env

DEBUG = False

# En production, SECRET_KEY et ALLOWED_HOSTS sont obligatoires.
SECRET_KEY = env("SECRET_KEY")
ALLOWED_HOSTS = env.list("ALLOWED_HOSTS")
CSRF_TRUSTED_ORIGINS = env.list("CSRF_TRUSTED_ORIGINS", default=[])

# Aucune cle derivee en production : elle doit etre generee et sauvegardee a
# part (voir docs/deployment.md). Perdue, les donnees de versement le sont aussi.
FIELD_ENCRYPTION_KEYS = env.list("FIELD_ENCRYPTION_KEY")
for _key in FIELD_ENCRYPTION_KEYS:
    try:
        Fernet(_key)
    except ValueError as _exc:
        raise ImproperlyConfigured(
            "FIELD_ENCRYPTION_KEY invalide : generez-la avec "
            '`python -c "from cryptography.fernet import Fernet; '
            'print(Fernet.generate_key().decode())"`.'
        ) from _exc

# ---------------------------------------------------------------------------
# TLS / HTTPS (cahier des charges : TLS 1.3 obligatoire, HSTS)
# ---------------------------------------------------------------------------
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SECURE_SSL_REDIRECT = env.bool("SECURE_SSL_REDIRECT", default=True)
SECURE_REDIRECT_EXEMPT = [r"^health/$", r"^ready/$"]
SESSION_COOKIE_SECURE = env.bool("SESSION_COOKIE_SECURE", default=SECURE_SSL_REDIRECT)
CSRF_COOKIE_SECURE = env.bool("CSRF_COOKIE_SECURE", default=SECURE_SSL_REDIRECT)
SECURE_HSTS_SECONDS = env.int("SECURE_HSTS_SECONDS", default=31536000)
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
# Pas d'inscription a la liste « preload » des navigateurs : elle engage tout
# le domaine (et ses sous-domaines) en HTTPS de facon quasi irreversible,
# decision qui revient au gestionnaire du domaine, pas a la plateforme.
SECURE_HSTS_PRELOAD = False
# check --deploy le signale (W021) : choix assume ci-dessus, la CI echoue
# sinon sur cet avertissement.
SILENCED_SYSTEM_CHECKS = ["security.W021"]

# ---------------------------------------------------------------------------
# Durcissement supplementaire des sessions (OWASP ASVS V3.3)
# ---------------------------------------------------------------------------
SESSION_COOKIE_AGE = env.int("SESSION_COOKIE_AGE", default=60 * 60 * 4)
SESSION_SAVE_EVERY_REQUEST = True
CSRF_COOKIE_AGE = SESSION_COOKIE_AGE

# ---------------------------------------------------------------------------
# Jeton de reinitialisation de mot de passe : 1 heure (OWASP ASVS V2.5.2)
# ---------------------------------------------------------------------------
PASSWORD_RESET_TIMEOUT = env.int("PASSWORD_RESET_TIMEOUT", default=3600)

# ---------------------------------------------------------------------------
# Limitation des champs de formulaire (HashDoS / NIST 800-53 SC-5)
# ---------------------------------------------------------------------------
DATA_UPLOAD_MAX_NUMBER_FIELDS = 100
DATA_UPLOAD_MAX_NUMBER_FILES = 10

# ---------------------------------------------------------------------------
# CSP de production (script inline interdit)
# ---------------------------------------------------------------------------
CSP_DIRECTIVES = {
    "default-src": "'self'",
    "script-src": "'self'",
    "style-src": "'self' 'unsafe-inline'",
    "img-src": _IMG_SRC,
    "font-src": "'self' data:",
    "connect-src": "'self'",
    "frame-ancestors": "'none'",
    "base-uri": "'self'",
    "form-action": "'self'",
    "object-src": "'none'",
    "worker-src": "'none'",
    "manifest-src": "'self'",
}
if SECURE_SSL_REDIRECT:
    CSP_DIRECTIVES["upgrade-insecure-requests"] = ""

# ---------------------------------------------------------------------------
# Integrite des messages (HMAC-SHA256) — obligatoire en production (M1)
# ---------------------------------------------------------------------------
_mik = env("MESSAGE_INTEGRITY_KEY", default="")
if len(_mik) < 32 or _mik.startswith("CHANGEZ"):
    raise ImproperlyConfigured(
        "MESSAGE_INTEGRITY_KEY absente ou faible. Generez-la avec : "
        'python -c "import secrets; print(secrets.token_urlsafe(48))"'
    )
MESSAGE_INTEGRITY_KEY = _mik

STORAGES["staticfiles"] = {  # noqa: F405
    "BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage"
}
