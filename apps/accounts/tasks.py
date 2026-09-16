"""Taches de maintenance des comptes."""

from datetime import timedelta

from celery import shared_task
from django.utils import timezone

from .models import UserToken


@shared_task(name="apps.accounts.tasks.purge_expired_tokens")
def purge_expired_tokens():
    """Supprime les jetons expires ou consommes depuis plus de 30 jours."""
    cutoff = timezone.now() - timedelta(days=30)
    expired = UserToken.objects.filter(expires_at__lt=timezone.now())
    consumed = UserToken.objects.filter(used_at__lt=cutoff)
    count = expired.count() + consumed.count()
    expired.delete()
    consumed.delete()
    return count
