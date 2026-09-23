"""Reglages de developpement eVDP."""

from .base import *  # noqa: F401,F403
from .base import env  # noqa: F401

DEBUG = env.bool("DEBUG", default=True)

# Django active le loader de gabarits en cache par defaut, meme en DEBUG=True
# (comportement independant de DEBUG depuis Django 4.1). En developpement, le
# code est monte en volume pour etre modifiable sans reconstruire l'image
# (voir docker-compose.dev.yml) : un gabarit mis en cache par un worker
# Gunicorn deja demarre resterait invisible tant que le processus ne
# redemarre pas. On revient explicitement aux loaders non caches - APP_DIRS
# doit alors etre desactive, Django refusant de le combiner avec des loaders
# explicites (app_directories.Loader ci-dessous a le meme effet).
TEMPLATES[0]["APP_DIRS"] = False
TEMPLATES[0]["OPTIONS"]["loaders"] = [
    "django.template.loaders.filesystem.Loader",
    "django.template.loaders.app_directories.Loader",
]
ALLOWED_HOSTS = ["*"]
CSRF_TRUSTED_ORIGINS = env.list(
    "CSRF_TRUSTED_ORIGINS",
    default=["http://localhost", "http://127.0.0.1", "http://localhost:8000"],
)

# En developpement, Mailpit capture tous les emails.
EMAIL_BACKEND = env("EMAIL_BACKEND", default="django.core.mail.backends.smtp.EmailBackend")

INTERNAL_IPS = ["127.0.0.1"]
