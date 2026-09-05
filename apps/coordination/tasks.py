"""Taches periodiques de coordination : surveillance des SLA et divulgations."""

import logging
from datetime import timedelta

from celery import shared_task
from django.utils import timezone

from apps.audit.models import AuditAction
from apps.audit.services import log_action
from apps.notifications.models import NotificationKind
from apps.notifications.services import notify_case_team

from .constants import SLAState
from .models import Case, SLAEvent, SLAPolicy

logger = logging.getLogger("evdp.sla")


@shared_task(name="apps.coordination.tasks.sweep_sla")
def sweep_sla():
    """Detecte les echeances proches et les depassements de SLA."""
    now = timezone.now()
    default_policy = SLAPolicy.get_default()
    warning_ratio = (default_policy.warning_ratio if default_policy else 80) / 100

    breached = 0
    warned = 0

    pending = SLAEvent.objects.filter(
        state__in=[SLAState.PENDING, SLAState.APPROACHING]
    ).select_related("case", "policy")

    for event in pending:
        if event.due_at <= now:
            event.state = SLAState.BREACHED
            event.breached_at = now
            event.save(update_fields=["state", "breached_at", "updated_at"])
            breached += 1
            notify_case_team(event.case, NotificationKind.SLA_BREACHED)
            log_action(
                AuditAction.SLA_BREACHED,
                obj=event.case,
                kind=event.kind,
                due_at=event.due_at.isoformat(),
            )
            event.case.refresh_priority()
            continue

        if event.state == SLAState.PENDING:
            ratio = (event.policy.warning_ratio / 100) if event.policy else warning_ratio
            total = (event.due_at - event.created_at).total_seconds()
            elapsed = (now - event.created_at).total_seconds()
            if total > 0 and elapsed / total >= ratio:
                event.state = SLAState.APPROACHING
                event.warned_at = now
                event.save(update_fields=["state", "warned_at", "updated_at"])
                warned += 1
                notify_case_team(event.case, NotificationKind.SLA_APPROACHING)

    logger.info("sla_sweep", extra={"breached": breached, "warned": warned})
    return {"breached": breached, "warned": warned}


@shared_task(name="apps.coordination.tasks.sweep_disclosure_schedule")
def sweep_disclosure_schedule():
    """Alerte sur les divulgations coordonnees imminentes (J-7)."""
    horizon = timezone.localdate() + timedelta(days=7)
    upcoming = Case.objects.filter(
        disclosure_date__lte=horizon,
        disclosure_date__gte=timezone.localdate(),
        is_published=False,
    ).exclude(status="CLOSED")

    for case in upcoming:
        notify_case_team(case, NotificationKind.DISCLOSURE_UPCOMING)
    return upcoming.count()


@shared_task(name="apps.coordination.tasks.refresh_priorities")
def refresh_priorities():
    """Recalcule les scores de priorite des cases ouverts."""
    updated = 0
    for case in Case.objects.open().iterator():
        before = case.priority_score
        if case.refresh_priority() != before:
            updated += 1
    return updated
