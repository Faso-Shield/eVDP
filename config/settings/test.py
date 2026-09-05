"""Reglages utilises par la suite de tests.

Par defaut la suite tourne sur PostgreSQL (comme la production). Definir
DB_ENGINE=sqlite permet une execution rapide hors conteneur.
"""

import os

os.environ.setdefault("DB_ENGINE", "sqlite")
os.environ.setdefault("SECRET_KEY", "test-secret-key-not-used-in-production")

from .base import *  # noqa: F401,F403,E402

DEBUG = False
ALLOWED_HOSTS = ["*", "testserver"]

# Hachage rapide : les tests ne verifient pas la robustesse d'Argon2.
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "evdp-tests",
    }
}

EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"

CELERY_TASK_ALWAYS_EAGER = True
CELERY_TASK_EAGER_PROPAGATES = True

USE_S3 = False
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
}

MEDIA_ROOT = BASE_DIR / ".pytest-media"  # noqa: F405

LOGGING["root"]["level"] = "CRITICAL"  # noqa: F405
