from django.apps import AppConfig


class ApiConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.api"
    verbose_name = "API eVDP"

    def ready(self):
        # Enregistre les extensions de schema aupres de drf-spectacular.
        from . import schema  # noqa: F401
