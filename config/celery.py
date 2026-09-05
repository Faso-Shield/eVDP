"""Configuration Celery pour eVDP."""

import logging
import os

from celery import Celery

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.dev")

app = Celery("evdp")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()


logger = logging.getLogger("evdp")


@app.task(bind=True, ignore_result=True)
def debug_task(self):  # pragma: no cover - utilitaire de diagnostic
    logger.info("celery_debug_task", extra={"request": repr(self.request)})
