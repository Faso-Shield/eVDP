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

PROBE_HARDENING = (
    "import django, json; django.setup(); from django.conf import settings as s; "
    "print(json.dumps({"
    "'hsts': s.SECURE_HSTS_SECONDS, "
    "'hsts_subdomains': s.SECURE_HSTS_INCLUDE_SUBDOMAINS, "
    "'hsts_preload': s.SECURE_HSTS_PRELOAD, "
    "'session_age': s.SESSION_COOKIE_AGE, "
    "'session_save': s.SESSION_SAVE_EVERY_REQUEST, "
    "'worker_src': s.CSP_DIRECTIVES.get('worker-src', ''), "
    "'manifest_src': s.CSP_DIRECTIVES.get('manifest-src', ''), "
    "'pw_reset_timeout': s.PASSWORD_RESET_TIMEOUT, "
    "'max_fields': s.DATA_UPLOAD_MAX_NUMBER_FIELDS, "
    "'max_files': s.DATA_UPLOAD_MAX_NUMBER_FILES, "
    "'csrf_cookie_age': s.CSRF_COOKIE_AGE, "
    "}))"
)


def _prod_env(**overrides):
    return {
        **os.environ,
        "DJANGO_SETTINGS_MODULE": "config.settings.prod",
        "SECRET_KEY": "test-prod-settings",
        "ALLOWED_HOSTS": "localhost",
        "DB_ENGINE": "sqlite",
        "FIELD_ENCRYPTION_KEY": "Y2ktY2xlLWZlcm5ldC1ub24tdXRpbGlzZWUtZW4tcHI=",
        # Obligatoire en production : sans elle, le chargement echoue. Un poste
        # de developpement la tirait de son .env ; la CI n'en a pas.
        "MESSAGE_INTEGRITY_KEY": "k" * 48,
        **overrides,
    }


def prod_settings(**overrides):
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-c", PROBE],
        cwd=ROOT,
        env=_prod_env(**overrides),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout.strip().splitlines()[-1])


def prod_hardening(**overrides):
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-c", PROBE_HARDENING],
        cwd=ROOT,
        env=_prod_env(**overrides),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout.strip().splitlines()[-1])


def test_tls_deployment_keeps_secure_cookies_and_upgrade():
    assert prod_settings(SECURE_SSL_REDIRECT="True") == [True, True, True]


def test_http_deployment_can_still_log_in():
    """Sans TLS, un cookie Secure n'est jamais renvoye : connexion impossible."""
    assert prod_settings(SECURE_SSL_REDIRECT="False") == [False, False, False]


def test_prod_hardening_settings():
    """Verifie les mesures de durcissement FASO SHIELD v2.0 + OWASP ASVS 4.0."""
    data = prod_hardening(SECURE_SSL_REDIRECT="True", SECURE_HSTS_SECONDS="31536000")
    assert data["hsts"] == 31536000
    assert data["hsts_subdomains"] is True
    assert data["hsts_preload"] is False
    assert data["session_age"] <= 14400
    assert data["session_save"] is True
    assert data["worker_src"] == "'none'"
    assert data["manifest_src"] == "'self'"
    assert data["pw_reset_timeout"] <= 3600
    assert data["max_fields"] <= 200
    assert data["max_files"] <= 20
    assert data["csrf_cookie_age"] == data["session_age"]


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


def test_smtp_ssl_and_starttls_are_refused_together():
    """Django ne le refuserait qu'au premier envoi : chaque email echouerait."""
    result = subprocess.run(  # noqa: S603 - interpreteur courant, arguments fixes
        [sys.executable, "-c", "import django; django.setup()"],
        cwd=ROOT,
        env=_prod_env(EMAIL_USE_TLS="True", EMAIL_USE_SSL="True"),
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "EMAIL_USE_TLS et EMAIL_USE_SSL sont exclusifs" in result.stderr
