"""
Reglages communs eVDP.

Principes appliques :
  - Aucun secret en dur : tout provient des variables d'environnement.
  - Prive par defaut : aucune donnee de case n'est exposee sans controle.
  - Securite par defaut : en-tetes, cookies, hachage Argon2, uploads bornes.
"""

from pathlib import Path

import environ
from celery.schedules import crontab

BASE_DIR = Path(__file__).resolve().parent.parent.parent

env = environ.Env(
    DEBUG=(bool, False),
    ALLOWED_HOSTS=(list, ["localhost", "127.0.0.1"]),
    CSRF_TRUSTED_ORIGINS=(list, []),
    DB_ENGINE=(str, "postgres"),
    USE_S3=(bool, False),
    EVDP_CAPTCHA_ENABLED=(bool, False),
)

# Charge un fichier .env local s'il existe (jamais commite).
_env_file = BASE_DIR / ".env"
if _env_file.exists():
    env.read_env(str(_env_file))

SECRET_KEY = env("SECRET_KEY", default="dev-only-insecure-key-change-me")
DEBUG = env("DEBUG")
ALLOWED_HOSTS = env("ALLOWED_HOSTS")
CSRF_TRUSTED_ORIGINS = env("CSRF_TRUSTED_ORIGINS")

# ---------------------------------------------------------------------------
# Applications
# ---------------------------------------------------------------------------
DJANGO_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.humanize",
    "django.contrib.staticfiles",
]

THIRD_PARTY_APPS = [
    "rest_framework",
    "django_filters",
    "drf_spectacular",
    "django_celery_beat",
]

LOCAL_APPS = [
    "apps.core",
    "apps.accounts",
    "apps.organizations",
    "apps.researchers",
    "apps.programs",
    "apps.vulnerabilities",
    "apps.reports",
    "apps.coordination",
    "apps.attachments",
    "apps.bounty",
    "apps.disclosures",
    "apps.notifications",
    "apps.audit",
    "apps.dashboard",
    "apps.api",
    "apps.csaf",
]

INSTALLED_APPS = DJANGO_APPS + THIRD_PARTY_APPS + LOCAL_APPS

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "apps.core.middleware.RequestContextMiddleware",
    # Apres AuthenticationMiddleware : la session n'est elevee qu'une fois le
    # second facteur valide. Place ici, la regle couvre toute la plateforme,
    # y compris /admin/ qui a sa propre page de connexion.
    "apps.accounts.middleware.MfaEnforcementMiddleware",
    "apps.core.middleware.SecurityHeadersMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "apps.core.context_processors.evdp_context",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"

# ---------------------------------------------------------------------------
# Base de donnees
# ---------------------------------------------------------------------------
if env("DB_ENGINE") == "sqlite":
    # Uniquement pour l'execution rapide de la suite de tests hors conteneur.
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": env("SQLITE_PATH", default=str(BASE_DIR / "evdp.sqlite3")),
        }
    }
else:
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": env("POSTGRES_DB", default="evdp"),
            "USER": env("POSTGRES_USER", default="evdp"),
            "PASSWORD": env("POSTGRES_PASSWORD", default="evdp"),
            "HOST": env("POSTGRES_HOST", default="evdp-db"),
            "PORT": env("POSTGRES_PORT", default="5432"),
            "CONN_MAX_AGE": 60,
        }
    }

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
AUTH_USER_MODEL = "accounts.User"

# ---------------------------------------------------------------------------
# Authentification / mots de passe
# ---------------------------------------------------------------------------
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher",
]

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {"min_length": 12},
    },
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LOGIN_URL = "/login/"
LOGIN_REDIRECT_URL = "/dashboard/"
LOGOUT_REDIRECT_URL = "/"

# ---------------------------------------------------------------------------
# Internationalisation
# ---------------------------------------------------------------------------
LANGUAGE_CODE = "fr-fr"
TIME_ZONE = env("TIME_ZONE", default="Africa/Ouagadougou")
USE_I18N = True
USE_TZ = True

# ---------------------------------------------------------------------------
# Fichiers statiques et medias
# ---------------------------------------------------------------------------
STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = [BASE_DIR / "static"]
MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"

USE_S3 = env("USE_S3")

STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "whitenoise.storage.CompressedStaticFilesStorage"},
}

if USE_S3:
    # MinIO / S3 : stockage prive des pieces jointes, jamais expose publiquement.
    STORAGES["default"] = {
        "BACKEND": "storages.backends.s3.S3Storage",
        "OPTIONS": {
            "bucket_name": env("MINIO_BUCKET", default="evdp-attachments"),
            "access_key": env("MINIO_ACCESS_KEY", default=""),
            "secret_key": env("MINIO_SECRET_KEY", default=""),
            "endpoint_url": env("MINIO_ENDPOINT", default="http://evdp-minio:9000"),
            "region_name": env("MINIO_REGION", default="us-east-1"),
            "default_acl": "private",
            "querystring_auth": True,
            "file_overwrite": False,
            "signature_version": "s3v4",
            "addressing_style": "path",
        },
    }

# ---------------------------------------------------------------------------
# Cache / Celery
# ---------------------------------------------------------------------------
REDIS_URL = env("REDIS_URL", default="redis://evdp-redis:6379/0")

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.redis.RedisCache",
        "LOCATION": REDIS_URL,
    }
}

CELERY_BROKER_URL = env("CELERY_BROKER_URL", default=REDIS_URL)
CELERY_RESULT_BACKEND = env("CELERY_RESULT_BACKEND", default=REDIS_URL)
CELERY_TASK_SERIALIZER = "json"
CELERY_RESULT_SERIALIZER = "json"
CELERY_ACCEPT_CONTENT = ["json"]
CELERY_TIMEZONE = TIME_ZONE
CELERY_TASK_ALWAYS_EAGER = False
CELERY_BEAT_SCHEDULER = "django_celery_beat.schedulers:DatabaseScheduler"

# ---------------------------------------------------------------------------
# ClamAV - analyse antivirus des pièces jointes
# ---------------------------------------------------------------------------
CLAMAV_HOST = env("CLAMAV_HOST", default="")
CLAMAV_PORT = env.int("CLAMAV_PORT", default=3310)

CELERY_BEAT_SCHEDULE = {
    "evdp-sla-sweep": {
        "task": "apps.coordination.tasks.sweep_sla",
        "schedule": crontab(minute="*/30"),
    },
    "evdp-disclosure-sweep": {
        "task": "apps.coordination.tasks.sweep_disclosure_schedule",
        "schedule": crontab(minute=15),
    },
    "evdp-purge-expired-tokens": {
        "task": "apps.accounts.tasks.purge_expired_tokens",
        "schedule": crontab(minute=0, hour=3),
    },
    "evdp-relance-comptes-non-verifies": {
        "task": "apps.accounts.tasks.remind_unverified_accounts",
        "schedule": crontab(minute=30, hour=8),
    },
}

# ---------------------------------------------------------------------------
# Emails
# ---------------------------------------------------------------------------
EMAIL_BACKEND = env("EMAIL_BACKEND", default="django.core.mail.backends.smtp.EmailBackend")
EMAIL_HOST = env("EMAIL_HOST", default="evdp-mailpit")
EMAIL_PORT = env.int("EMAIL_PORT", default=1025)
EMAIL_HOST_USER = env("EMAIL_USER", default="")
EMAIL_HOST_PASSWORD = env("EMAIL_PASSWORD", default="")
EMAIL_USE_TLS = env.bool("EMAIL_USE_TLS", default=False)
DEFAULT_FROM_EMAIL = env("DEFAULT_FROM_EMAIL", default="eVDP <no-reply@evdp.bf>")
SERVER_EMAIL = DEFAULT_FROM_EMAIL

# URL publique de l'instance, utilisee pour construire les liens envoyes
# par email. A defaut, elle est deduite de ALLOWED_HOSTS.
SITE_BASE_URL = env("SITE_BASE_URL", default="")

# ---------------------------------------------------------------------------
# Securite HTTP
# ---------------------------------------------------------------------------
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_NAME = "evdp_sessionid"
SESSION_COOKIE_AGE = env.int("SESSION_COOKIE_AGE", default=60 * 60 * 8)
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
CSRF_COOKIE_HTTPONLY = False  # requis pour que HTMX lise le jeton
CSRF_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_NAME = "evdp_csrftoken"
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "strict-origin-when-cross-origin"
X_FRAME_OPTIONS = "DENY"
SECURE_CROSS_ORIGIN_OPENER_POLICY = "same-origin"
DATA_UPLOAD_MAX_MEMORY_SIZE = 10 * 1024 * 1024
FILE_UPLOAD_MAX_MEMORY_SIZE = 5 * 1024 * 1024

CSP_DIRECTIVES = {
    "default-src": "'self'",
    "script-src": "'self' 'unsafe-inline'",
    "style-src": "'self' 'unsafe-inline'",
    "img-src": "'self' data:",
    "font-src": "'self' data:",
    "connect-src": "'self'",
    "frame-ancestors": "'none'",
    "base-uri": "'self'",
    "form-action": "'self'",
    "object-src": "'none'",
}
PERMISSIONS_POLICY = (
    "geolocation=(), microphone=(), camera=(), payment=(), usb=(), "
    "magnetometer=(), gyroscope=()"
)

# ---------------------------------------------------------------------------
# Django REST Framework
# ---------------------------------------------------------------------------
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework.authentication.SessionAuthentication",
        "apps.api.authentication.ApiKeyAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
    "DEFAULT_PAGINATION_CLASS": "apps.api.pagination.DefaultPagination",
    "PAGE_SIZE": 25,
    "DEFAULT_FILTER_BACKENDS": [
        "django_filters.rest_framework.DjangoFilterBackend",
        "rest_framework.filters.SearchFilter",
        "rest_framework.filters.OrderingFilter",
    ],
    "DEFAULT_THROTTLE_CLASSES": [
        "apps.api.throttling.ResilientScopedRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "report-submission": env("THROTTLE_REPORT_SUBMISSION", default="10/hour"),
        "anon-read": env("THROTTLE_ANON_READ", default="60/hour"),
        "authenticated": env("THROTTLE_AUTHENTICATED", default="1000/day"),
    },
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    "EXCEPTION_HANDLER": "apps.api.exceptions.evdp_exception_handler",
}

SPECTACULAR_SETTINGS = {
    "TITLE": "eVDP API",
    "DESCRIPTION": (
        "API de la plateforme nationale de divulgation coordonnee de "
        "vulnerabilites et de Bug Bounty (CYBER-DEF 2)."
    ),
    "VERSION": "1.0.0",
    "SERVE_INCLUDE_SCHEMA": False,
    "SCHEMA_PATH_PREFIX": "/api/v1",
    "COMPONENT_SPLIT_REQUEST": True,
    # Plusieurs modeles exposent un champ "status" ou "severity" avec des
    # valeurs differentes : on nomme explicitement chaque enumeration pour
    # produire un schema OpenAPI lisible et stable.
    "ENUM_NAME_OVERRIDES": {
        "CaseStatusEnum": "apps.coordination.workflow.CaseStatus.choices",
        "SeverityEnum": "apps.vulnerabilities.constants.Severity.choices",
        "VulnerabilityTypeEnum": ("apps.vulnerabilities.constants.VulnerabilityType.choices"),
        "WorkflowTypeEnum": "apps.coordination.constants.WorkflowType.choices",
        "ProgramTypeEnum": "apps.programs.models.ProgramType.choices",
        "ProgramStatusEnum": "apps.programs.models.ProgramStatus.choices",
        "ConfidentialityLevelEnum": ("apps.programs.models.ConfidentialityLevel.choices"),
        "ScopeTargetTypeEnum": "apps.programs.models.ScopeTargetType.choices",
        "ScopePriorityEnum": "apps.programs.models.ScopePriority.choices",
        "BountyStatusEnum": "apps.bounty.models.BountyStatus.choices",
        "OrganizationStatusEnum": ("apps.organizations.models.OrganizationStatus.choices"),
        "OrganizationTypeEnum": "apps.organizations.models.OrganizationType.choices",
        "SectorEnum": "apps.organizations.models.Sector.choices",
        "MessageConfidentialityEnum": ("apps.coordination.constants.Confidentiality.choices"),
    },
}

# ---------------------------------------------------------------------------
# Parametres metier eVDP
# ---------------------------------------------------------------------------
EVDP = {
    "PLATFORM_NAME": "eVDP",
    "PLATFORM_TAGLINE": ("Plateforme nationale de divulgation coordonnee de vulnerabilites"),
    "PROJECT_CODE": "CYBER-DEF 2",
    "NATIONAL_TEAM": env("EVDP_NATIONAL_TEAM", default="ANSSI-BF / CSIRT National"),
    "CONTACT_EMAIL": env("EVDP_CONTACT_EMAIL", default="vdp@anssi.bf"),
    "CASE_PREFIX": "EVDP",
    "ADVISORY_PREFIX": "EVDP-ADV",
    "DEFAULT_CURRENCY": env("EVDP_DEFAULT_CURRENCY", default="XOF"),
    "DEFAULT_DISCLOSURE_DELAY_DAYS": env.int("EVDP_DISCLOSURE_DELAY_DAYS", default=90),
    # Exigence d'adresse verifiee : date de bascule, sursis accorde aux seuls
    # comptes anterieurs, et jalons de relance exprimes en jours restants.
    # Voir apps/accounts/verification.py.
    "VERIFICATION_ENFORCED_FROM": env("EVDP_VERIFICATION_ENFORCED_FROM", default=""),
    "VERIFICATION_GRACE_DAYS": env.int("EVDP_VERIFICATION_GRACE_DAYS", default=30),
    "VERIFICATION_REMINDER_DAYS": env.list(
        "EVDP_VERIFICATION_REMINDER_DAYS", default=["14", "7", "1"]
    ),
    "MAX_ATTACHMENT_SIZE": env.int("EVDP_MAX_ATTACHMENT_SIZE", default=25 * 1024 * 1024),
    "ATTACHMENT_ALLOWED_EXTENSIONS": env.list(
        "EVDP_ATTACHMENT_EXTENSIONS",
        default=[
            "png",
            "jpg",
            "jpeg",
            "gif",
            "webp",
            "pdf",
            "txt",
            "md",
            "log",
            "json",
            "csv",
            "xml",
            "yaml",
            "yml",
            "har",
            "pcap",
            "zip",
            "eml",
            "asc",
            "pgp",
        ],
    ),
    "ATTACHMENT_BLOCKED_EXTENSIONS": [
        "exe",
        "dll",
        "so",
        "bat",
        "cmd",
        "com",
        "cpl",
        "msi",
        "scr",
        "jar",
        "ps1",
        "sh",
        "vbs",
        "js",
        "php",
        "jsp",
        "asp",
        "aspx",
        "py",
        "pyc",
        "htaccess",
        "svg",
        "html",
        "htm",
    ],
    "MAX_ATTACHMENTS_PER_CASE": env.int("EVDP_MAX_ATTACHMENTS_PER_CASE", default=20),
    "CAPTCHA_ENABLED": env("EVDP_CAPTCHA_ENABLED"),
    "PGP_PUBLIC_KEY": env("PGP_PUBLIC_KEY", default=""),
    "PGP_FINGERPRINT": env("PGP_FINGERPRINT", default=""),
    "REPUTATION": {
        "VALIDATED": env.int("EVDP_REP_VALIDATED", default=10),
        "HIGH": env.int("EVDP_REP_HIGH", default=25),
        "CRITICAL": env.int("EVDP_REP_CRITICAL", default=50),
        "DUPLICATE": env.int("EVDP_REP_DUPLICATE", default=0),
        "ABUSIVE": env.int("EVDP_REP_ABUSIVE", default=-20),
    },
    "RATE_LIMITS": {
        "login": env("EVDP_RL_LOGIN", default="10/5m"),
        "register": env("EVDP_RL_REGISTER", default="5/1h"),
        "report": env("EVDP_RL_REPORT", default="10/1h"),
        "password_reset": env("EVDP_RL_PASSWORD_RESET", default="5/1h"),
        # Second facteur : limite par compte, pas par IP. Un code a six
        # chiffres se devine en 10^6 essais ; la limite les rend hors de
        # portee sans bloquer le titulaire legitime qui se trompe.
        "mfa": env("EVDP_RL_MFA", default="10/5m"),
        # Jeton de suivi long et aleatoire (haute entropie) : la limite sert
        # surtout a ralentir le crawl/scraping, pas a empecher un brute-force
        # qui serait de toute facon impraticable vu l'espace de recherche.
        "track_lookup": env("EVDP_RL_TRACK_LOOKUP", default="20/5m"),
    },
}

# ---------------------------------------------------------------------------
# Journalisation structuree JSON
# ---------------------------------------------------------------------------
LOG_LEVEL = env("LOG_LEVEL", default="INFO")

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "json": {"()": "apps.core.logging.JsonFormatter"},
        "simple": {"format": "%(levelname)s %(name)s %(message)s"},
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": env("LOG_FORMAT", default="json"),
        },
    },
    "root": {"handlers": ["console"], "level": LOG_LEVEL},
    "loggers": {
        "django.db.backends": {
            "level": "WARNING",
            "handlers": ["console"],
            "propagate": False,
        },
        "evdp": {"level": LOG_LEVEL, "handlers": ["console"], "propagate": False},
        "evdp.audit": {"level": "INFO", "handlers": ["console"], "propagate": False},
        "evdp.security": {"level": "INFO", "handlers": ["console"], "propagate": False},
    },
}
