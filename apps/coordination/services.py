"""Logique metier de la coordination : transitions, messagerie, SLA, doublons.

Aucune vue n'ecrit directement dans les modeles : tout passe par ces services,
qui garantissent la coherence workflow + audit + notifications + SLA.
"""

import secrets
from datetime import datetime, time, timedelta

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.utils import timezone

from apps.accounts.roles import Capability
from apps.audit.models import AuditAction, AuditResult
from apps.audit.services import log_action
from apps.core.utils import hash_text
from apps.notifications.models import NotificationKind
from apps.notifications.services import notify, notify_case_team, notify_external
from apps.vulnerabilities.constants import Severity

from .constants import (
    Confidentiality,
    ParticipantRole,
    SLAKind,
    SLAState,
    TimelineEventType,
    WorkflowType,
)
from .models import (
    CaseAssignment,
    CaseMessage,
    CaseParticipant,
    CaseStatusHistory,
    CaseTimelineEvent,
    CaseTrackingToken,
    SLAEvent,
    SLAPolicy,
)
from .workflow import CaseStatus, TransitionNotAllowed, check_transition, public_status_bucket

#: Duree de validite d'un jeton de suivi. Assez long pour couvrir un cycle
#: de divulgation coordonnee complet (jusqu'a 90 jours par defaut) sans
#: obliger le declarant a revenir avant que son dossier ne soit clos.
TRACKING_TOKEN_VALIDITY = timedelta(days=180)

#: Statut -> evenement de chronologie correspondant.
STATUS_TIMELINE_EVENTS = {
    CaseStatus.ACKNOWLEDGED: TimelineEventType.ACKNOWLEDGED,
    CaseStatus.TRIAGE: TimelineEventType.TRIAGE_STARTED,
    CaseStatus.NEEDS_INFORMATION: TimelineEventType.INFORMATION_REQUESTED,
    CaseStatus.VALIDATED: TimelineEventType.VALIDATED,
    CaseStatus.SEVERITY_ASSIGNED: TimelineEventType.SEVERITY_SET,
    CaseStatus.VENDOR_CONTACTED: TimelineEventType.ORGANIZATION_CONTACTED,
    CaseStatus.VENDOR_ACKNOWLEDGED: TimelineEventType.ORGANIZATION_ACKNOWLEDGED,
    CaseStatus.FIX_AVAILABLE: TimelineEventType.FIX_PROVIDED,
    CaseStatus.FIX_VERIFIED: TimelineEventType.FIX_VERIFIED,
    CaseStatus.DISCLOSURE_SCHEDULED: TimelineEventType.DISCLOSURE_SCHEDULED,
    CaseStatus.PUBLISHED: TimelineEventType.ADVISORY_PUBLISHED,
    CaseStatus.REWARD_APPROVED: TimelineEventType.REWARD_APPROVED,
    CaseStatus.DUPLICATE: TimelineEventType.DUPLICATE_MARKED,
    CaseStatus.REJECTED: TimelineEventType.REJECTED,
    CaseStatus.CLOSED: TimelineEventType.CLOSED,
}

#: Statuts declenchant une notification au declarant.
STATUS_NOTIFICATIONS = {
    CaseStatus.ACKNOWLEDGED: NotificationKind.ACKNOWLEDGEMENT,
    CaseStatus.NEEDS_INFORMATION: NotificationKind.INFORMATION_REQUESTED,
    CaseStatus.VALIDATED: NotificationKind.VALIDATED,
    CaseStatus.REJECTED: NotificationKind.REJECTED,
    CaseStatus.DUPLICATE: NotificationKind.DUPLICATE,
}

#: Evenements de chronologie publiables dans un advisory (non sensibles).
PUBLIC_TIMELINE_EVENTS = {
    TimelineEventType.REPORT_RECEIVED,
    TimelineEventType.ACKNOWLEDGED,
    TimelineEventType.VALIDATED,
    TimelineEventType.ORGANIZATION_CONTACTED,
    TimelineEventType.FIX_PROVIDED,
    TimelineEventType.FIX_VERIFIED,
    TimelineEventType.ADVISORY_PUBLISHED,
}


def _start_of_day(day):
    """Datetime aware correspondant au debut de la journee locale."""
    naive = datetime.combine(day, time.min)
    return timezone.make_aware(naive) if timezone.is_naive(naive) else naive


# ---------------------------------------------------------------------------
# Chronologie et participants
# ---------------------------------------------------------------------------
def add_timeline_event(case, event_type, label, actor=None, occurred_at=None, **metadata):
    return CaseTimelineEvent.objects.create(
        case=case,
        event_type=event_type,
        label=label,
        actor=actor,
        occurred_at=occurred_at or timezone.now(),
        is_public=event_type in PUBLIC_TIMELINE_EVENTS,
        metadata=metadata or {},
    )


def add_participant(case, user, role=ParticipantRole.OBSERVER, added_by=None):
    if user is None:
        return None
    participant, created = CaseParticipant.objects.get_or_create(
        case=case,
        user=user,
        defaults={"participant_role": role, "added_by": added_by},
    )
    if not created and not participant.is_active:
        participant.is_active = True
        participant.participant_role = role
        participant.save(update_fields=["is_active", "participant_role", "updated_at"])
    return participant


def ensure_default_participants(case):
    """Rattache automatiquement le declarant a la creation du dossier.

    Les contacts de l'organisation ne sont PAS rattaches ici : voir
    ensure_organization_participants(), appelee seulement une fois le CSIRT
    ayant explicitement engage l'organisation (VENDOR_CONTACTED). Sinon,
    is_participant() -- verifie avant tout controle de statut par
    Case.is_visible_to() -- leur donnerait acces au dossier des sa creation,
    en plein triage, contournant ORG_VISIBLE_STATES.
    """
    if case.reporter_id:
        add_participant(case, case.reporter, ParticipantRole.REPORTER)


def ensure_organization_participants(case):
    """Rattache les contacts de l'organisation affectee (Responsable/DSI/
    Contact securite) comme participants du dossier.

    A appeler uniquement au moment ou le CSIRT engage formellement
    l'organisation (transition vers VENDOR_CONTACTED) -- jamais avant, pour
    proteger le declarant pendant le triage (cf. ORG_VISIBLE_STATES).
    """
    if not case.organization_id:
        return
    from apps.organizations.models import MembershipRole

    members = case.organization.members.filter(
        is_active=True,
        membership_role__in=[
            MembershipRole.MANAGER,
            MembershipRole.DSI,
            MembershipRole.SECURITY_CONTACT,
        ],
    ).select_related("user")
    for member in members:
        role = (
            ParticipantRole.DSI
            if member.membership_role == MembershipRole.DSI
            else ParticipantRole.ORGANIZATION
        )
        add_participant(case, member.user, role)


# ---------------------------------------------------------------------------
# SLA
# ---------------------------------------------------------------------------
def resolve_sla_policy(case):
    if case.program_id and case.program.sla_policy_id:
        return case.program.sla_policy
    return SLAPolicy.get_default()


def schedule_initial_sla(case):
    """Cree les echeances d'accuse de reception et de premier triage."""
    policy = resolve_sla_policy(case)
    if policy is None:
        return []
    now = timezone.now()
    events = []
    for kind, due in (
        (SLAKind.ACKNOWLEDGEMENT, now + timedelta(hours=policy.acknowledgement_hours)),
        (SLAKind.TRIAGE, now + timedelta(days=policy.triage_days)),
    ):
        event, _ = SLAEvent.objects.get_or_create(
            case=case, kind=kind, defaults={"due_at": due, "policy": policy}
        )
        events.append(event)
    return events


def schedule_sla(case, kind, due_at):
    policy = resolve_sla_policy(case)
    event, created = SLAEvent.objects.get_or_create(
        case=case, kind=kind, defaults={"due_at": due_at, "policy": policy}
    )
    if not created and event.state == SLAState.PENDING:
        event.due_at = due_at
        event.save(update_fields=["due_at", "updated_at"])
    return event


def satisfy_sla(case, kind):
    event = case.sla_events.filter(kind=kind).first()
    if event:
        event.mark_met()
    return event


def _sla_side_effects(case, new_status):
    """Ouvre et solde les echeances au fil du workflow."""
    policy = resolve_sla_policy(case)
    now = timezone.now()

    if new_status in (CaseStatus.RECEIVED, CaseStatus.ACKNOWLEDGED):
        satisfy_sla(case, SLAKind.ACKNOWLEDGEMENT)
    if new_status in (
        CaseStatus.TRIAGE,
        CaseStatus.VALIDATED,
        CaseStatus.REJECTED,
        CaseStatus.DUPLICATE,
        CaseStatus.OUT_OF_SCOPE,
        CaseStatus.NOT_APPLICABLE,
        CaseStatus.INFORMATIVE,
    ):
        satisfy_sla(case, SLAKind.TRIAGE)
    if policy is None:
        return
    if new_status == CaseStatus.VENDOR_CONTACTED:
        schedule_sla(
            case,
            SLAKind.VENDOR_RESPONSE,
            now + timedelta(days=policy.vendor_response_days),
        )
    if new_status == CaseStatus.VENDOR_ACKNOWLEDGED:
        satisfy_sla(case, SLAKind.VENDOR_RESPONSE)
    if new_status in (CaseStatus.VALIDATED, CaseStatus.REMEDIATION):
        schedule_sla(
            case,
            SLAKind.REMEDIATION,
            now + timedelta(days=policy.remediation_days_for(case.severity)),
        )
    if new_status in (CaseStatus.FIX_AVAILABLE, CaseStatus.FIX_VERIFIED):
        satisfy_sla(case, SLAKind.REMEDIATION)
    if new_status in (CaseStatus.PUBLISHED, CaseStatus.CLOSED):
        case.sla_events.filter(state=SLAState.PENDING).update(state=SLAState.CANCELLED)


# ---------------------------------------------------------------------------
# Transition de statut
# ---------------------------------------------------------------------------
def transition_case(case, target_status, actor, comment="", request=None):
    """Applique une transition de statut controlee et tracee.

    La verification est faite HORS transaction : un refus doit laisser une
    trace d'audit persistante, or un rollback effacerait cette trace.
    """
    previous = case.status
    try:
        check_transition(previous, target_status, case.workflow, user=actor)
    except TransitionNotAllowed as exc:
        log_action(
            AuditAction.STATUS_CHANGED,
            actor=actor,
            obj=case,
            result=AuditResult.DENIED,
            request=request,
            from_status=previous,
            to_status=target_status,
            reason=str(exc),
        )
        raise
    return _apply_transition(case, target_status, actor, comment, request, previous)


@transaction.atomic
def _apply_transition(case, target_status, actor, comment, request, previous):
    """Applique effectivement la transition validee (atomique)."""
    case.status = target_status
    now = timezone.now()
    updates = ["status", "updated_at"]

    if target_status == CaseStatus.ACKNOWLEDGED and not case.acknowledged_at:
        case.acknowledged_at = now
        updates.append("acknowledged_at")
    if target_status == CaseStatus.VALIDATED and not case.validated_at:
        case.validated_at = now
        updates.append("validated_at")
        if case.program_id and case.disclosure_date is None:
            case.disclosure_date = (
                now + timedelta(days=case.program.disclosure_delay_days)
            ).date()
            updates.append("disclosure_date")
    if target_status == CaseStatus.VENDOR_CONTACTED:
        # C'est ICI, et pas avant, que l'organisation affectee obtient
        # effectivement acces au dossier (voir ORG_VISIBLE_STATES) : on ne
        # rattache ses contacts qu'a ce moment precis.
        ensure_organization_participants(case)
    if target_status in (CaseStatus.FIX_VERIFIED, CaseStatus.FIX_AVAILABLE):
        if not case.remediated_at:
            case.remediated_at = now
            updates.append("remediated_at")
    if target_status == CaseStatus.PUBLISHED:
        case.is_published = True
        updates.append("is_published")
    if target_status == CaseStatus.CLOSED and not case.closed_at:
        case.closed_at = now
        updates.append("closed_at")

    case.save(update_fields=updates)

    CaseStatusHistory.objects.create(
        case=case,
        from_status=previous,
        to_status=target_status,
        actor=actor,
        comment=comment,
    )
    add_timeline_event(
        case,
        STATUS_TIMELINE_EVENTS.get(target_status, TimelineEventType.STATUS_CHANGED),
        f"{case.get_status_display()}",
        actor=actor,
    )
    _sla_side_effects(case, target_status)
    case.refresh_priority()

    log_action(
        AuditAction.STATUS_CHANGED,
        actor=actor,
        obj=case,
        request=request,
        from_status=previous,
        to_status=target_status,
    )

    _notify_status_change(case, target_status, actor)
    _apply_reputation(case, target_status, actor)
    return case


def _notify_status_change(case, status, actor):
    kind = STATUS_NOTIFICATIONS.get(status, NotificationKind.STATUS_CHANGED)
    if case.reporter_id:
        notify(case.reporter, kind, case=case)
    elif getattr(case.report, "reporter_email", ""):
        notify_external(case.report.reporter_email, kind, case=case)
    notify_case_team(case, NotificationKind.STATUS_CHANGED, exclude=actor)


def _apply_reputation(case, status, actor):
    """Attribue les points de reputation lors de la validation d'un rapport."""
    from apps.researchers.services import award_reputation

    if status == CaseStatus.VALIDATED and case.reporter_id:
        award_reputation(case.reporter, case, granted_by=actor)


# ---------------------------------------------------------------------------
# Assignation
# ---------------------------------------------------------------------------
@transaction.atomic
def assign_case(case, assignee, actor, note="", request=None):
    if not actor.has_capability(Capability.ASSIGN_CASE):
        raise PermissionDenied("Vous n'etes pas autorise a assigner un case.")
    case.assignments.filter(is_active=True).update(is_active=False)
    case.assignee = assignee
    case.save(update_fields=["assignee", "updated_at"])
    if assignee is not None:
        CaseAssignment.objects.create(case=case, user=assignee, assigned_by=actor, note=note)
        add_participant(case, assignee, ParticipantRole.ANALYST, added_by=actor)
        notify(assignee, NotificationKind.CASE_ASSIGNED, case=case)
    add_timeline_event(
        case,
        TimelineEventType.ASSIGNED,
        f"Dossier assigne a {assignee}" if assignee else "Assignation retiree",
        actor=actor,
    )
    log_action(
        AuditAction.CASE_ASSIGNED,
        actor=actor,
        obj=case,
        request=request,
        assignee=str(assignee) if assignee else None,
    )
    return case


# ---------------------------------------------------------------------------
# Messagerie
# ---------------------------------------------------------------------------
@transaction.atomic
def post_message(
    case,
    author,
    body,
    confidentiality=Confidentiality.PARTICIPANTS,
    request=None,
    is_system=False,
):
    """Publie un message dans le fil securise du case."""
    if not is_system:
        if not case.is_visible_to(author):
            raise PermissionDenied("Vous n'avez pas acces a ce dossier.")
        if confidentiality != Confidentiality.PARTICIPANTS and not author.has_capability(
            Capability.POST_INTERNAL_MESSAGE
        ):
            raise PermissionDenied("Vous n'etes pas autorise a publier un message interne.")
        if getattr(author, "is_read_only", False):
            raise PermissionDenied("Role en lecture seule.")
    if not (body or "").strip():
        raise ValidationError("Le message ne peut pas etre vide.")

    message = CaseMessage.objects.create(
        case=case,
        author=None if is_system else author,
        body=body.strip(),
        confidentiality=confidentiality,
        is_system=is_system,
    )
    log_action(
        AuditAction.MESSAGE_SENT,
        actor=None if is_system else author,
        obj=case,
        request=request,
        message_id=str(message.pk),
        confidentiality=confidentiality,
    )
    if confidentiality == Confidentiality.PARTICIPANTS:
        notify_case_team(case, NotificationKind.NEW_MESSAGE, exclude=author)
    return message


def visible_messages(case, user):
    """Fil de discussion filtre selon le niveau de confidentialite."""
    queryset = case.messages.select_related("author").prefetch_related("attachments")
    if user.is_superuser or user.is_national:
        from apps.accounts.roles import Role

        if user.role in (Role.NATIONAL_COORDINATOR, Role.SUPER_ADMIN) or user.is_superuser:
            return queryset
        return queryset.exclude(confidentiality=Confidentiality.RESTRICTED)
    return queryset.filter(confidentiality=Confidentiality.PARTICIPANTS)


# ---------------------------------------------------------------------------
# Doublons
# ---------------------------------------------------------------------------
@transaction.atomic
def mark_duplicate(case, original, actor, comment="", request=None):
    """Marque un case comme doublon d'un autre.

    Le declarant est informe du doublon mais n'obtient AUCUNE information sur
    le case original (identifiant, organisation, contenu).
    """
    if not actor.has_capability(Capability.TRIAGE_CASE):
        raise PermissionDenied("Capacite de triage requise.")
    if original.pk == case.pk:
        raise ValidationError("Un case ne peut pas etre le doublon de lui-meme.")
    if original.duplicate_of_id == case.pk:
        raise ValidationError("Reference circulaire de doublon.")

    case.duplicate_of = original
    case.save(update_fields=["duplicate_of", "updated_at"])
    transition_case(case, CaseStatus.DUPLICATE, actor, comment=comment, request=request)
    log_action(
        AuditAction.REPORT_DUPLICATED,
        actor=actor,
        obj=case,
        request=request,
        original_case=original.case_id,
    )
    return case


# ---------------------------------------------------------------------------
# Severite
# ---------------------------------------------------------------------------
@transaction.atomic
def set_severity(case, actor, severity=None, cvss_vector="", request=None):
    """Definit la severite retenue, eventuellement calculee depuis un CVSS."""
    if not actor.has_capability(Capability.SET_SEVERITY):
        raise PermissionDenied("Capacite requise pour definir la severite.")
    from apps.vulnerabilities.cvss import CVSSError, evaluate

    updates = ["severity", "updated_at"]
    if cvss_vector:
        try:
            score, computed = evaluate(cvss_vector)
        except CVSSError as exc:
            raise ValidationError({"cvss_vector": str(exc)}) from exc
        case.cvss_vector = cvss_vector
        case.cvss_score = score
        severity = severity or computed
        updates += ["cvss_vector", "cvss_score"]
    case.severity = severity or case.severity
    case.save(update_fields=updates)
    case.refresh_priority()
    add_timeline_event(
        case,
        TimelineEventType.SEVERITY_SET,
        f"Severite retenue : {case.get_severity_display()}",
        actor=actor,
    )
    log_action(
        AuditAction.CASE_UPDATED,
        actor=actor,
        obj=case,
        request=request,
        severity=case.severity,
        cvss=case.cvss_vector,
    )
    return case


@transaction.atomic
def schedule_disclosure(case, actor, disclosure_date, request=None):
    if not actor.has_capability(Capability.CHANGE_CASE_STATUS):
        raise PermissionDenied("Capacite requise.")
    case.disclosure_date = disclosure_date
    case.save(update_fields=["disclosure_date", "updated_at"])
    schedule_sla(case, SLAKind.DISCLOSURE, _start_of_day(disclosure_date))
    add_timeline_event(
        case,
        TimelineEventType.DISCLOSURE_SCHEDULED,
        f"Divulgation planifiee le {disclosure_date:%d/%m/%Y}",
        actor=actor,
    )
    log_action(
        AuditAction.CASE_UPDATED,
        actor=actor,
        obj=case,
        request=request,
        disclosure_date=str(disclosure_date),
    )
    return case


def default_severity_for(report):
    from apps.vulnerabilities.cvss import CVSSError, evaluate

    if report.cvss_vector:
        try:
            _score, severity = evaluate(report.cvss_vector)
            return severity
        except CVSSError:
            pass
    return report.reported_severity or Severity.MEDIUM


def generate_tracking_token(case):
    """Cree (ou renouvelle) le jeton de suivi public d'un case sans compte.

    La valeur en clair n'est jamais persistee : seul son hash est stocke,
    au meme titre que les cles d'API. Elle est renvoyee a l'appelant pour
    etre transmise une seule fois (email ou affichage a l'ecran), puis
    perdue cote serveur.
    """
    raw = secrets.token_urlsafe(32)
    CaseTrackingToken.objects.update_or_create(
        case=case,
        defaults={
            "token_hash": hash_text(raw),
            "expires_at": timezone.now() + TRACKING_TOKEN_VALIDITY,
        },
    )
    return raw


def resolve_tracking_token(raw_token):
    """Retrouve le case associe a un jeton de suivi valide, ou None.

    Ne distingue jamais "jeton inconnu" de "jeton expire" dans la reponse
    appelante : les deux doivent produire le meme message generique cote vue,
    pour ne rien laisser deviner sur l'existence d'un jeton proche.
    """
    if not raw_token or not raw_token.strip():
        return None
    token = (
        CaseTrackingToken.objects.select_related("case")
        .filter(token_hash=hash_text(raw_token.strip()))
        .first()
    )
    if token is None or not token.is_valid:
        return None
    token.record_access()
    return token.case


def public_status_for(case):
    """(cle, libelle, resultat) simplifies pour la page de suivi publique."""
    key, label = public_status_bucket(case.status)
    return {
        "key": key,
        "label": label,
        "case_id": case.case_id,
        "submitted_at": case.created_at,
        "is_dismissed": key == "DISMISSED",
        "is_resolved": key == "RESOLVED",
    }


__all__ = [
    "transition_case",
    "assign_case",
    "post_message",
    "visible_messages",
    "mark_duplicate",
    "set_severity",
    "schedule_disclosure",
    "add_participant",
    "ensure_default_participants",
    "ensure_organization_participants",
    "add_timeline_event",
    "schedule_initial_sla",
    "generate_tracking_token",
    "resolve_tracking_token",
    "public_status_for",
    "WorkflowType",
]
