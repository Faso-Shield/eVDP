"""Branchement des evenements d'authentification sur le journal d'audit."""

from django.contrib.auth.signals import (
    user_logged_in,
    user_logged_out,
    user_login_failed,
)
from django.dispatch import receiver

from .models import AuditAction, AuditResult
from .services import log_action


@receiver(user_logged_in)
def on_login(sender, request, user, **kwargs):
    log_action(AuditAction.LOGIN, actor=user, obj=user, request=request)


@receiver(user_logged_out)
def on_logout(sender, request, user, **kwargs):
    if user is not None:
        log_action(AuditAction.LOGOUT, actor=user, obj=user, request=request)


@receiver(user_login_failed)
def on_login_failed(sender, credentials, request=None, **kwargs):
    log_action(
        AuditAction.LOGIN_FAILED,
        result=AuditResult.FAILURE,
        request=request,
        object_type="User",
        object_repr=(credentials or {}).get("username", "")[:255],
    )
