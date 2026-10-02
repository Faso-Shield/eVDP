"""Reglages de production, charges dans un processus a part : ils sont lus
une seule fois a l'import, pytest tourne sur config.settings.test."""

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROBE = (
    "import django, json; django.setup(); from django.conf import settings as s; "
    "print(json.dumps([s.SESSION_COOKIE_SECURE, s.CSRF_COOKIE_SECURE, "
    "'upgrade-insecure-requests' in s.CSP_DIRECTIVES]))"
)


def prod_settings(**overrides):
    env = {
        **os.environ,
        "DJANGO_SETTINGS_MODULE": "config.settings.prod",
        "SECRET_KEY": "test-prod-settings",
        "ALLOWED_HOSTS": "localhost",
        "DB_ENGINE": "sqlite",
        "FIELD_ENCRYPTION_KEY": "Y2ktY2xlLWZlcm5ldC1ub24tdXRpbGlzZWUtZW4tcHI=",
        **overrides,
    }
    result = subprocess.run(  # noqa: S603 - interpreteur courant, arguments fixes
        [sys.executable, "-c", PROBE], cwd=ROOT, env=env, capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout.strip().splitlines()[-1])


def test_tls_deployment_keeps_secure_cookies_and_upgrade():
    assert prod_settings(SECURE_SSL_REDIRECT="True") == [True, True, True]


def test_http_deployment_can_still_log_in():
    """Sans TLS, un cookie Secure n'est jamais renvoye : connexion impossible."""
    assert prod_settings(SECURE_SSL_REDIRECT="False") == [False, False, False]


def test_prod_refuses_an_invalid_encryption_key():
    """Une cle absente est refusee de meme, mais le .env local d'un poste de
    developpement en fournit une : seul le cas explicite est teste ici."""
    env = {
        **os.environ,
        "DJANGO_SETTINGS_MODULE": "config.settings.prod",
        "SECRET_KEY": "x",
        "ALLOWED_HOSTS": "localhost",
        "DB_ENGINE": "sqlite",
        "FIELD_ENCRYPTION_KEY": "pas-une-cle-fernet",
    }
    result = subprocess.run(  # noqa: S603 - interpreteur courant, arguments fixes
        [sys.executable, "-c", "import django; django.setup()"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "FIELD_ENCRYPTION_KEY invalide" in result.stderr
