"""Reglages de developpement eVDP."""

from .base import *  # noqa: F401,F403
from .base import env  # noqa: F401

DEBUG = env.bool("DEBUG", default=True)
ALLOWED_HOSTS = ["*"]
CSRF_TRUSTED_ORIGINS = env.list(
    "CSRF_TRUSTED_ORIGINS",
    default=["http://localhost", "http://127.0.0.1", "http://localhost:8000"],
)

# En developpement, Mailpit capture tous les emails.
EMAIL_BACKEND = env("EMAIL_BACKEND", default="django.core.mail.backends.smtp.EmailBackend")

INTERNAL_IPS = ["127.0.0.1"]
