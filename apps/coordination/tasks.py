"""Taches periodiques de coordination : surveillance des SLA et divulgations."""

import logging
from datetime import timedelta

from celery import shared_task
from django.utils import timezone

from apps.audit.models import AuditAction
from apps.audit.services import log_action
from apps.notifications.models import NotificationKind

from .constants import SLAKind, SLAState
from .models import Case, SLAEvent, SLAPolicy
from .services import escalate_case, notify_case_staff, perform_action
from .workflow import (
    ESCALATION_STATES,
    NEEDS_INFORMATION_TIMEOUT_DAYS,
    CaseStatus,
    TransitionNotAllowed,
)

#: SLA dont le depassement escalade automatiquement le dossier.
ESCALATING_SLA_KINDS = (SLAKind.VENDOR_RESPONSE, SLAKind.REMEDIATION)

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
            notify_case_staff(event.case, NotificationKind.SLA_BREACHED)
            log_action(
                AuditAction.SLA_BREACHED,
                obj=event.case,
                kind=event.kind,
                due_at=event.due_at.isoformat(),
            )
            # Etapes 6 et 7 : un SLA depasse cote organisation escalade le
            # dossier (alerte rouge, Coordinateur notifie).
            if event.kind in ESCALATING_SLA_KINDS and event.case.status in ESCALATION_STATES:
                escalate_case(event.case, None, f"SLA {event.kind} depasse")
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
                notify_case_staff(event.case, NotificationKind.SLA_APPROACHING)

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
        notify_case_staff(case, NotificationKind.DISCLOSURE_UPCOMING)
    return upcoming.count()


@shared_task(name="apps.coordination.tasks.sweep_needs_information")
def sweep_needs_information():
    """Sans complement du declarant sous 30 jours, le rejet est propose.

    Le rejet n'est que propose (REJECTION_PENDING) : le Coordinateur le
    confirme ou renvoie le dossier a son etape d'origine.
    """
    limit = timezone.now() - timedelta(days=NEEDS_INFORMATION_TIMEOUT_DAYS)
    stale = Case.objects.filter(
        status=CaseStatus.NEEDS_INFORMATION, sla_paused_at__lte=limit
    )
    proposed = 0
    for case in stale:
        try:
            perform_action(
                case,
                "propose_rejection",
                None,
                data={
                    "comment": (
                        f"Aucun complément reçu sous {NEEDS_INFORMATION_TIMEOUT_DAYS} jours : "
                        "rejet proposé automatiquement."
                    )
                },
            )
            proposed += 1
        except TransitionNotAllowed:
            logger.warning("needs_information_sweep_skipped", extra={"case": case.case_id})
    return proposed


@shared_task(name="apps.coordination.tasks.refresh_priorities")
def refresh_priorities():
    """Recalcule les scores de priorite des cases ouverts."""
    updated = 0
    for case in Case.objects.open().iterator():
        before = case.priority_score
        if case.refresh_priority() != before:
            updated += 1
    return updated
