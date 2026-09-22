"""Redaction et publication des advisories.

Principe 5 : aucune donnee interne du case n'est exposee publiquement.
Principe 6 : l'advisory est une representation assainie, construite par un
analyste a partir de champs explicitement selectionnes.
"""

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.utils import timezone

from apps.accounts.roles import Capability
from apps.audit.models import AuditAction
from apps.audit.services import log_action
from apps.coordination.constants import TimelineEventType
from apps.coordination.services import add_timeline_event
from apps.notifications.models import NotificationKind
from apps.notifications.services import notify

from .models import Advisory, AdvisoryStatus, AdvisoryTimelineEntry


def credit_for(case):
    """Credit public respectant le choix d'identite du chercheur."""
    report = getattr(case, "report", None)
    if report is None or not report.wants_credit or report.is_anonymous:
        return "Chercheur anonyme"
    if case.reporter_id:
        return case.reporter.public_identity()
    return report.reporter_name or "Chercheur anonyme"


@transaction.atomic
def create_advisory_from_case(case, actor, request=None, **overrides):
    """Prepare un brouillon d'advisory a partir d'un case valide.

    Seuls des champs non sensibles sont pre-remplis : ni PoC, ni etapes de
    reproduction, ni URL cible, ni pieces jointes.
    """
    if not actor.has_capability(Capability.DRAFT_ADVISORY):
        raise PermissionDenied("Capacité requise pour rédiger un advisory.")

    data = {
        "case": case,
        "organization": case.organization,
        "title": case.title,
        "summary": overrides.pop("summary", ""),
        "product": case.product,
        "severity": case.severity,
        "cvss_score": case.cvss_score,
        "cvss_vector": case.cvss_vector,
        "cwe": case.cwe,
        "cve": case.cve,
        "credit": credit_for(case),
        "created_by": actor,
        "status": AdvisoryStatus.DRAFT,
    }
    data.update(overrides)
    advisory = Advisory.objects.create(**data)

    # Chronologie publique : uniquement les jalons marques publics.
    for index, event in enumerate(case.timeline.filter(is_public=True)):
        AdvisoryTimelineEntry.objects.create(
            advisory=advisory,
            happened_on=timezone.localtime(event.occurred_at).date(),
            label=event.label,
            position=index,
        )

    log_action(
        AuditAction.ADVISORY_CREATED,
        actor=actor,
        obj=advisory,
        request=request,
        case=case.case_id,
    )
    return advisory


@transaction.atomic
def create_advisory(advisory, actor, case=None, request=None):
    """Enregistre un advisory redige a la main.

    Complement de `create_advisory_from_case` pour les advisories sans case
    source. La vue ne sauvegarde jamais le modele elle-meme : l'ecriture passe
    ici afin que la creation soit toujours auditee.
    """
    if not actor.has_capability(Capability.DRAFT_ADVISORY):
        raise PermissionDenied("Capacité requise pour rédiger un advisory.")

    advisory.created_by = actor
    if case is not None:
        advisory.case = case
        advisory.organization = case.organization
    advisory.save()

    log_action(
        AuditAction.ADVISORY_CREATED,
        actor=actor,
        obj=advisory,
        request=request,
        case=case.case_id if case is not None else None,
    )
    return advisory


@transaction.atomic
def update_advisory(advisory, actor, request=None):
    """Enregistre une modification redactionnelle et l'audite.

    Un advisory publie reste modifiable (correction editoriale), mais chaque
    modification laisse une trace nominative.
    """
    if not actor.has_capability(Capability.DRAFT_ADVISORY):
        raise PermissionDenied("Capacite requise pour modifier un advisory.")

    advisory.save()
    log_action(
        AuditAction.ADVISORY_UPDATED,
        actor=actor,
        obj=advisory,
        request=request,
        status=advisory.status,
    )
    return advisory


@transaction.atomic
def transition_advisory(advisory, target_status, actor, request=None):
    if target_status == AdvisoryStatus.PUBLISHED:
        return publish_advisory(advisory, actor, request=request)
    if not actor.has_capability(Capability.DRAFT_ADVISORY):
        raise PermissionDenied("Capacité requise.")
    if not advisory.can_transition_to(target_status):
        raise ValidationError(f"Transition interdite : {advisory.status} -> {target_status}.")
    advisory.status = target_status
    advisory.save(update_fields=["status", "updated_at"])
    log_action(
        AuditAction.ADVISORY_UPDATED,
        actor=actor,
        obj=advisory,
        request=request,
        to_status=target_status,
    )
    return advisory


@transaction.atomic
def publish_advisory(advisory, actor, request=None, published_at=None):
    """Publie l'advisory. Action irreversible hors retrait explicite."""
    if not actor.has_capability(Capability.PUBLISH_ADVISORY):
        raise PermissionDenied("Capacité requise pour publier un advisory.")
    if not advisory.can_transition_to(AdvisoryStatus.PUBLISHED):
        raise ValidationError("Un advisory doit être approuvé ou planifié avant publication.")
    if not advisory.summary.strip():
        raise ValidationError({"summary": "Un résumé public est obligatoire."})

    advisory.status = AdvisoryStatus.PUBLISHED
    advisory.published_at = published_at or timezone.now()
    advisory.published_by = actor
    advisory.save(update_fields=["status", "published_at", "published_by", "updated_at"])

    log_action(
        AuditAction.ADVISORY_PUBLISHED,
        actor=actor,
        obj=advisory,
        request=request,
        case=advisory.case.case_id if advisory.case_id else None,
    )

    if advisory.case_id:
        add_timeline_event(
            advisory.case,
            TimelineEventType.ADVISORY_PUBLISHED,
            f"Advisory {advisory.advisory_id} publie",
            actor=actor,
        )
        if advisory.case.reporter_id:
            notify(
                advisory.case.reporter,
                NotificationKind.ADVISORY_PUBLISHED,
                case=advisory.case,
                url=advisory.get_absolute_url(),
            )
    return advisory


@transaction.atomic
def retract_advisory(advisory, actor, reason, request=None):
    if not actor.has_capability(Capability.PUBLISH_ADVISORY):
        raise PermissionDenied("Capacité requise.")
    if not advisory.can_transition_to(AdvisoryStatus.RETRACTED):
        raise ValidationError("Seul un advisory publié peut être retiré.")
    if not reason.strip():
        raise ValidationError({"reason": "Un motif de retrait est obligatoire."})
    advisory.status = AdvisoryStatus.RETRACTED
    advisory.retracted_reason = reason
    advisory.save(update_fields=["status", "retracted_reason", "updated_at"])
    log_action(
        AuditAction.ADVISORY_RETRACTED,
        actor=actor,
        obj=advisory,
        request=request,
        reason=reason[:200],
    )
    return advisory
