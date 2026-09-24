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
from apps.notifications.services import (
    notify,
    notify_case_team,
    notify_external,
    notify_many,
)
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
    channels_visible_to,
    channels_writable_by,
)
from .workflow import (
    DISMISSED_STATES,
    ESCALATION_STATES,
    EXCEPTION_STATES,
    ORG_VISIBLE_STATES,
    REMEDIATION_DAYS,
    TERMINAL_STATES,
    CaseBountyStatus,
    CaseStatus,
    TransitionNotAllowed,
    check_transition,
    public_status_bucket,
    resolve_target,
)

#: Duree de validite d'un lien de suivi remis a un declarant sans compte.
TRACKING_TOKEN_VALIDITY = timedelta(days=180)

#: Statut d'arrivee -> evenement de chronologie correspondant.
STATUS_TIMELINE_EVENTS = {
    CaseStatus.ACKNOWLEDGED: TimelineEventType.ACKNOWLEDGED,
    CaseStatus.IN_ANALYSIS: TimelineEventType.TRIAGE_STARTED,
    CaseStatus.NEEDS_INFORMATION: TimelineEventType.INFORMATION_REQUESTED,
    CaseStatus.VALIDATION_PENDING: TimelineEventType.QUALIFICATION_SUBMITTED,
    CaseStatus.VALIDATED: TimelineEventType.VALIDATED,
    CaseStatus.VENDOR_NOTIFIED: TimelineEventType.ORGANIZATION_CONTACTED,
    CaseStatus.REMEDIATION_IN_PROGRESS: TimelineEventType.REMEDIATION_PLANNED,
    CaseStatus.FIX_AVAILABLE: TimelineEventType.FIX_PROVIDED,
    CaseStatus.FIX_VERIFIED: TimelineEventType.FIX_VERIFIED,
    CaseStatus.ADVISORY_REVIEW: TimelineEventType.ADVISORY_SUBMITTED,
    CaseStatus.REJECTION_PENDING: TimelineEventType.REJECTION_PROPOSED,
    CaseStatus.DUPLICATE: TimelineEventType.DUPLICATE_MARKED,
    CaseStatus.REJECTED: TimelineEventType.REJECTED,
    CaseStatus.CLOSED: TimelineEventType.CLOSED,
}

#: Statuts declenchant une notification dediee au declarant.
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
    """Rattache automatiquement le declarant, puis -- a partir de l'etape 5
    seulement -- les contacts de l'organisation affectee."""
    if case.reporter_id:
        add_participant(case, case.reporter, ParticipantRole.REPORTER)
    if case.organization_id and case.status in ORG_VISIBLE_STATES:
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


def suspend_sla(case):
    """Gele les echeances en cours (compléments demandes au declarant)."""
    now = timezone.now()
    case.sla_events.filter(state__in=[SLAState.PENDING, SLAState.APPROACHING]).update(
        state=SLAState.SUSPENDED, suspended_at=now, updated_at=now
    )


def resume_sla(case):
    """Relance les echeances gelees, decalees de la duree de suspension."""
    now = timezone.now()
    for event in case.sla_events.filter(state=SLAState.SUSPENDED):
        if event.suspended_at:
            event.due_at += now - event.suspended_at
        event.state = SLAState.PENDING
        event.suspended_at = None
        event.save(update_fields=["due_at", "state", "suspended_at", "updated_at"])


def _sla_side_effects(case, previous, new_status):
    """Ouvre et solde les echeances au fil du workflow (une par etape)."""
    policy = resolve_sla_policy(case)
    now = timezone.now()

    if new_status == CaseStatus.NEEDS_INFORMATION:
        suspend_sla(case)
        return
    if previous == CaseStatus.NEEDS_INFORMATION:
        resume_sla(case)

    if new_status == CaseStatus.ACKNOWLEDGED:
        satisfy_sla(case, SLAKind.ACKNOWLEDGEMENT)
    if new_status in (CaseStatus.VALIDATION_PENDING, *DISMISSED_STATES):
        satisfy_sla(case, SLAKind.ACKNOWLEDGEMENT)
        satisfy_sla(case, SLAKind.TRIAGE)
    if previous == CaseStatus.VALIDATION_PENDING:
        satisfy_sla(case, SLAKind.VALIDATION)
    if new_status == CaseStatus.REMEDIATION_IN_PROGRESS:
        satisfy_sla(case, SLAKind.VENDOR_RESPONSE)
    if new_status == CaseStatus.FIX_AVAILABLE:
        satisfy_sla(case, SLAKind.REMEDIATION)
    if previous == CaseStatus.FIX_AVAILABLE:
        satisfy_sla(case, SLAKind.VERIFICATION)

    if policy is not None:
        if new_status == CaseStatus.VALIDATION_PENDING:
            _restart_sla(
                case, SLAKind.VALIDATION, now + timedelta(days=policy.validation_days)
            )
        if new_status == CaseStatus.VENDOR_NOTIFIED:
            schedule_sla(
                case,
                SLAKind.VENDOR_RESPONSE,
                now + timedelta(days=policy.vendor_response_days),
            )
        if new_status == CaseStatus.FIX_AVAILABLE:
            _restart_sla(
                case, SLAKind.VERIFICATION, now + timedelta(days=policy.verification_days)
            )
    if new_status == CaseStatus.REMEDIATION_IN_PROGRESS and case.remediation_due_date:
        _restart_sla(case, SLAKind.REMEDIATION, _start_of_day(case.remediation_due_date))
    if new_status in TERMINAL_STATES:
        case.sla_events.filter(
            state__in=[SLAState.PENDING, SLAState.APPROACHING, SLAState.SUSPENDED]
        ).update(state=SLAState.CANCELLED)


def _restart_sla(case, kind, due_at):
    """(Re)ouvre une echeance, y compris apres un renvoi a l'etape precedente."""
    policy = resolve_sla_policy(case)
    event, created = SLAEvent.objects.get_or_create(
        case=case, kind=kind, defaults={"due_at": due_at, "policy": policy}
    )
    if not created:
        event.due_at = due_at
        event.state = SLAState.PENDING
        event.satisfied_at = None
        event.warned_at = None
        event.breached_at = None
        event.save(
            update_fields=[
                "due_at",
                "state",
                "satisfied_at",
                "warned_at",
                "breached_at",
                "updated_at",
            ]
        )
    return event


def remediation_deadline(case):
    """Date cible maximale du correctif selon la severite validee."""
    policy = resolve_sla_policy(case)
    days = (
        policy.remediation_days_for(case.severity)
        if policy
        else REMEDIATION_DAYS.get(case.severity, 90)
    )
    return timezone.localdate() + timedelta(days=days)


# ---------------------------------------------------------------------------
# Transition de statut
# ---------------------------------------------------------------------------
def transition_case(case, action, actor, comment="", request=None):
    """Applique l'action `action` du workflow v2, controlee et tracee.

    La verification est faite HORS transaction : un refus doit laisser une
    trace d'audit persistante, or un rollback effacerait cette trace.
    """
    previous = case.status
    try:
        transition = check_transition(case, actor, action, comment)
    except TransitionNotAllowed as exc:
        log_action(
            AuditAction.STATUS_CHANGED,
            actor=actor,
            obj=case,
            result=AuditResult.DENIED,
            request=request,
            workflow_action=action,
            from_status=previous,
            reason=str(exc),
            code=exc.code,
        )
        raise
    target = resolve_target(case, transition)
    return _apply_transition(case, transition, target, actor, comment, request, previous)


@transaction.atomic
def _apply_transition(case, transition, target_status, actor, comment, request, previous):
    """Applique effectivement la transition validee (atomique)."""
    now = timezone.now()
    case.status = target_status
    updates = ["status", "updated_at"]

    # Memorise l'etape d'origine a l'entree dans une exception, et l'oublie
    # au retour sur le chemin principal.
    if target_status in EXCEPTION_STATES:
        if previous not in EXCEPTION_STATES:
            case.status_before_exception = previous
            updates.append("status_before_exception")
    elif case.status_before_exception:
        case.status_before_exception = ""
        updates.append("status_before_exception")
    if transition.action == "cancel_rejection" and case.duplicate_of_id:
        case.duplicate_of = None
        updates.append("duplicate_of")

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
        if case.bounty_status == CaseBountyStatus.UNDETERMINED:
            case.bounty_status = initial_bounty_status(case)
            updates.append("bounty_status")
    if target_status == CaseStatus.FIX_AVAILABLE and not case.remediated_at:
        case.remediated_at = now
        updates.append("remediated_at")
    if target_status == CaseStatus.CLOSED:
        case.is_published = True
        updates.append("is_published")
    if target_status in TERMINAL_STATES and not case.closed_at:
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
    event_type = STATUS_TIMELINE_EVENTS.get(target_status, TimelineEventType.STATUS_CHANGED)
    add_timeline_event(
        case,
        event_type,
        # Un jalon public (repris par l'advisory, visible du declarant) porte
        # un libelle neutre ; les autres gardent le detail interne.
        (
            event_type.label
            if event_type in PUBLIC_TIMELINE_EVENTS
            else f"{transition.label} -> {case.get_status_display()}"
        ),
        actor=actor,
        workflow_action=transition.action,
    )
    _sla_side_effects(case, previous, target_status)
    _action_side_effects(case, transition, target_status, actor, comment, request)
    case.refresh_priority()

    log_action(
        AuditAction.STATUS_CHANGED,
        actor=actor,
        obj=case,
        request=request,
        workflow_action=transition.action,
        from_status=previous,
        to_status=target_status,
    )
    if target_status == CaseStatus.REJECTED:
        log_action(AuditAction.REPORT_REJECTED, actor=actor, obj=case, request=request)
    if target_status == CaseStatus.DUPLICATE:
        log_action(
            AuditAction.REPORT_DUPLICATED,
            actor=actor,
            obj=case,
            request=request,
            original_case=case.duplicate_of.case_id if case.duplicate_of_id else None,
        )
    if target_status == CaseStatus.VALIDATED:
        log_action(AuditAction.REPORT_VALIDATED, actor=actor, obj=case, request=request)

    _notify_status_change(case, target_status, actor)
    _apply_reputation(case, target_status, actor)
    return case


def initial_bounty_status(case):
    """Branche prime ouverte a la validation, pour un programme eligible."""
    from apps.programs.models import ProgramType

    eligible = (
        case.program_id is not None
        and case.program.program_type == ProgramType.BUG_BOUNTY
        and case.reporter_id is not None
    )
    return CaseBountyStatus.BOUNTY_ELIGIBLE if eligible else CaseBountyStatus.NOT_ELIGIBLE


def _action_side_effects(case, transition, target_status, actor, comment, request):
    """Effets propres a certaines actions (organisation, advisory, rejet)."""
    if target_status == CaseStatus.VENDOR_NOTIFIED:
        # L'organisation entre dans le dossier a l'etape 5, et seulement la.
        ensure_default_participants(case)
        notify_case_team(case, NotificationKind.STATUS_CHANGED, exclude=actor)
    if transition.action in ("submit_advisory", "send_back_advisory", "publish_and_close"):
        from apps.disclosures.services import advance_case_advisory

        advance_case_advisory(case, transition.action, actor, request=request)
    if transition.action == "confirm_rejection" and case.status == CaseStatus.REJECTED:
        # Rien a ajouter : la notification dediee part via STATUS_NOTIFICATIONS.
        pass
    if transition.action in (
        "send_back_qualification",
        "send_back_advisory",
        "cancel_rejection",
        "reject_fix",
    ):
        add_timeline_event(
            case,
            TimelineEventType.SENT_BACK,
            f"{transition.label} : {comment[:180]}",
            actor=actor,
        )


def _notify_status_change(case, status, actor):
    """Le declarant n'est notifie qu'aux changements de palier visibles."""
    kind = STATUS_NOTIFICATIONS.get(status)
    if kind is not None:
        if case.reporter_id:
            notify(case.reporter, kind, case=case)
        elif getattr(case.report, "reporter_email", ""):
            notify_external(case.report.reporter_email, kind, case=case)
    notify_case_team(
        case,
        NotificationKind.STATUS_CHANGED,
        exclude=actor,
        include_reporter=False,
    )


def _apply_reputation(case, status, actor):
    """Attribue les points de reputation lors de la validation d'un rapport."""
    from apps.researchers.services import award_reputation

    if status == CaseStatus.VALIDATED and case.reporter_id:
        award_reputation(case.reporter, case, granted_by=actor)


# ---------------------------------------------------------------------------
# Donnees des etapes (pre-requis des boutons)
# ---------------------------------------------------------------------------
def _require(actor, capability, case):
    if not case.is_visible_to(actor):
        raise PermissionDenied("Dossier introuvable.")
    if getattr(actor, "is_read_only", False) or not actor.has_capability(capability):
        raise PermissionDenied("Vous n'êtes pas le propriétaire de cette étape.")


def _save_step(case, actor, fields, request, capability, **audit):
    _require(actor, capability, case)
    case.save(update_fields=fields + ["updated_at"])
    log_action(
        AuditAction.CASE_UPDATED,
        actor=actor,
        obj=case,
        request=request,
        fields=fields,
        **audit,
    )
    return case


@transaction.atomic
def record_admissibility(case, actor, scope_ok, organization_ok, attachment_ok, request=None):
    """Checklist de recevabilite (etape 2) : perimetre, organisation, PJ."""
    case.admissibility_scope_ok = bool(scope_ok)
    case.admissibility_organization_ok = bool(organization_ok)
    case.admissibility_attachment_ok = bool(attachment_ok)
    return _save_step(
        case,
        actor,
        [
            "admissibility_scope_ok",
            "admissibility_organization_ok",
            "admissibility_attachment_ok",
        ],
        request,
        Capability.TRIAGE_CASE,
    )


def build_vendor_summary(case):
    """Version « organisation » du rapport, identite du declarant protegee.

    Reprend la substance technique utile a la correction (description,
    impact, recommandations) sans jamais citer le declarant au-dela de ce
    que son mode d'identite autorise.
    """
    from apps.disclosures.services import credit_for

    report = case.report
    parts = [
        f"Dossier {case.case_id} - {case.title}",
        f"Produit : {case.product or 'non précisé'}",
        f"Sévérité validée : {case.get_severity_display()}"
        + (f" (CVSS {case.cvss_score})" if case.cvss_score is not None else ""),
    ]
    if case.cwe_id:
        parts.append(f"Faiblesse : {case.cwe.code} - {case.cwe.name}")
    parts.append(f"Signalé par : {credit_for(case)}")
    for title, body in (
        ("Description", report.description),
        ("Impact", report.impact),
        ("Recommandations", getattr(report, "recommendations", "")),
    ):
        if (body or "").strip():
            parts.append(f"## {title}\n\n{body.strip()}")
    return "\n\n".join(parts)


@transaction.atomic
def record_vendor_summary(case, actor, summary, request=None):
    """Version organisation du rapport (pre-requis de l'etape 5)."""
    case.vendor_summary = (summary or "").strip()
    return _save_step(case, actor, ["vendor_summary"], request, Capability.NOTIFY_VENDOR)


@transaction.atomic
def record_remediation_plan(case, actor, plan, due_date, request=None):
    """Plan de remediation de l'organisation (pre-requis de l'etape 6).

    La date cible ne peut depasser le delai de la severite validee
    (Critique 30 j, Elevee 60 j, Moyenne et Faible 90 j par defaut).
    """
    if due_date is not None:
        if due_date < timezone.localdate():
            raise ValidationError({"remediation_due_date": "La date cible est dépassée."})
        limit = remediation_deadline(case)
        if due_date > limit:
            raise ValidationError(
                {
                    "remediation_due_date": (
                        f"Date au-delà du délai de remédiation pour une sévérité "
                        f"{case.get_severity_display()} (au plus tard le {limit:%d/%m/%Y})."
                    )
                }
            )
    case.remediation_plan = (plan or "").strip()
    case.remediation_due_date = due_date
    _save_step(
        case,
        actor,
        ["remediation_plan", "remediation_due_date"],
        request,
        Capability.MANAGE_REMEDIATION,
    )
    if case.status == CaseStatus.REMEDIATION_IN_PROGRESS and due_date:
        _restart_sla(case, SLAKind.REMEDIATION, _start_of_day(due_date))
    return case


@transaction.atomic
def record_fix(case, actor, description, version="", request=None):
    """Description du correctif (pre-requis de l'etape 7)."""
    case.fix_description = (description or "").strip()
    case.fix_version = (version or "").strip()[:120]
    return _save_step(
        case,
        actor,
        ["fix_description", "fix_version"],
        request,
        Capability.MANAGE_REMEDIATION,
    )


@transaction.atomic
def record_fix_verification(case, actor, notes, request=None):
    """Compte rendu de contre-verification (pre-requis de l'etape 8)."""
    case.fix_verification_notes = (notes or "").strip()
    return _save_step(case, actor, ["fix_verification_notes"], request, Capability.VERIFY_FIX)


def system_propose_rejection(case, reason):
    """Proposition automatique de rejet (complements sans reponse sous 30 j).

    Aucun humain n'agit ici : la transition est appliquee sans acteur, puis
    le Coordinateur confirme ou renvoie comme pour toute proposition.
    """
    from .workflow import find_transition

    transition = find_transition(case.status, "propose_rejection")
    if transition is None:
        return None
    return _apply_transition(
        case,
        transition,
        transition.target,
        None,
        reason,
        None,
        case.status,
    )


# ---------------------------------------------------------------------------
# Escalade
# ---------------------------------------------------------------------------
@transaction.atomic
def escalate_case(case, actor=None, comment="", request=None, automatic=False):
    """Escalade vers la coordination nationale (alerte rouge).

    Automatique sur depassement de SLA, ou manuelle par le Coordinateur aux
    etapes 6 et 7. Pas de changement de statut : le Coordinateur peut ensuite
    decider une divulgation a echeance (voir schedule_disclosure).
    """
    from apps.accounts.models import User
    from apps.accounts.roles import Role

    if not automatic:
        _require(actor, Capability.ESCALATE_CASE, case)
        if case.status not in ESCALATION_STATES:
            raise ValidationError("L'escalade manuelle concerne les étapes 6 et 7.")
        if not (comment or "").strip():
            raise ValidationError("Un commentaire est obligatoire.")
    case.escalated_at = timezone.now()
    case.save(update_fields=["escalated_at", "updated_at"])
    add_timeline_event(
        case,
        TimelineEventType.ESCALATED,
        "Escalade automatique (SLA dépassé)" if automatic else f"Escalade : {comment[:180]}",
        actor=actor,
    )
    coordinators = User.objects.filter(role=Role.NATIONAL_COORDINATOR, is_active=True)
    notify_many(coordinators, NotificationKind.CASE_ESCALATED, case=case)
    log_action(
        AuditAction.CASE_ESCALATED,
        actor=actor,
        obj=case,
        request=request,
        automatic=automatic,
    )
    return case


# ---------------------------------------------------------------------------
# Assignation
# ---------------------------------------------------------------------------
@transaction.atomic
def assign_case(case, assignee, actor, note="", request=None):
    if not actor.has_capability(Capability.ASSIGN_CASE):
        raise PermissionDenied("Vous n'êtes pas autorisé à assigner un case.")
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
            raise PermissionDenied("Vous n'avez pas accès à ce dossier.")
        if getattr(author, "is_read_only", False):
            raise PermissionDenied("Rôle en lecture seule.")
        if confidentiality not in channels_writable_by(author, case):
            raise PermissionDenied("Vous n'êtes pas autorisé à écrire dans ce canal.")
    if not (body or "").strip():
        raise ValidationError("Le message ne peut pas être vide.")

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
    if confidentiality in (Confidentiality.PARTICIPANTS, Confidentiality.ORGANIZATION):
        notify_case_team(
            case,
            NotificationKind.NEW_MESSAGE,
            exclude=author,
            channel=confidentiality,
        )
    return message


def visible_messages(case, user):
    """Fil de discussion filtre selon les canaux lisibles par l'utilisateur."""
    queryset = case.messages.select_related("author").prefetch_related("attachments")
    return queryset.filter(confidentiality__in=channels_visible_to(user, case))


# ---------------------------------------------------------------------------
# Doublons
# ---------------------------------------------------------------------------
def propose_duplicate(case, original, actor, comment="", request=None):
    """Propose de clore un case comme doublon d'un autre (action secondaire).

    Le Coordinateur confirme ensuite (DUPLICATE) ou renvoie a l'etape
    d'origine. Le declarant n'obtient AUCUNE information sur le case
    original (identifiant, organisation, contenu).
    """
    if not actor.has_capability(Capability.PROPOSE_REJECTION):
        raise PermissionDenied("Capacité requise pour proposer un doublon.")
    if original.pk == case.pk:
        raise ValidationError("Un case ne peut pas être le doublon de lui-même.")
    if original.duplicate_of_id == case.pk:
        raise ValidationError("Référence circulaire de doublon.")

    previous = case.duplicate_of
    case.duplicate_of = original
    try:
        return transition_case(
            case, "propose_duplicate", actor, comment=comment, request=request
        )
    except TransitionNotAllowed:
        case.duplicate_of = previous
        raise
    finally:
        if case.status == CaseStatus.REJECTION_PENDING:
            case.save(update_fields=["duplicate_of", "updated_at"])


#: Compatibilite : ancien nom du service.
mark_duplicate = propose_duplicate


# ---------------------------------------------------------------------------
# Qualification
# ---------------------------------------------------------------------------
#: Statuts ou la qualification reste modifiable (avant sa soumission).
QUALIFICATION_OPEN_STATES = frozenset(
    {
        CaseStatus.SUBMITTED,
        CaseStatus.ACKNOWLEDGED,
        CaseStatus.IN_ANALYSIS,
        CaseStatus.NEEDS_INFORMATION,
    }
)


@transaction.atomic
def set_severity(case, actor, severity=None, cvss_vector="", request=None):
    """Qualification : severite retenue, calculee depuis un CVSS v3.1 ou v4.0.

    Seul l'analyste CSIRT saisit le CVSS (spec v2) ; l'auteur est memorise
    pour la regle des quatre yeux de l'etape 4. Une qualification soumise
    n'est plus modifiable, sauf renvoi par le valideur.
    """
    if not actor.has_capability(Capability.SET_SEVERITY):
        raise PermissionDenied("Capacité requise pour définir la sévérité.")
    if case.status not in QUALIFICATION_OPEN_STATES:
        raise ValidationError("La qualification n'est plus modifiable à ce stade du dossier.")
    from apps.vulnerabilities.cvss import CVSSError, evaluate

    updates = ["severity", "updated_at"]
    if cvss_vector:
        try:
            score, computed = evaluate(cvss_vector)
        except CVSSError as exc:
            raise ValidationError({"cvss_vector": str(exc)}) from exc
        case.cvss_vector = cvss_vector
        case.cvss_score = score
        case.cvss_set_by = actor
        severity = severity or computed
        updates += ["cvss_vector", "cvss_score", "cvss_set_by"]
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
    """Date de divulgation coordonnee (divulgation a echeance comprise)."""
    if not actor.has_capability(Capability.CHANGE_CASE_STATUS):
        raise PermissionDenied("Capacité requise.")
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


#: Alphabet du code de suivi : sans caracteres ambigus (0/O, 1/I/L), pour
#: qu'un declarant anonyme puisse le recopier a la main sans erreur.
TRACKING_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
#: 20 caracteres parmi 31 : environ 99 bits d'entropie, en 5 groupes de 4.
TRACKING_CODE_LENGTH = 20


def normalize_tracking_code(raw):
    """Forme canonique d'un code saisi : majuscules, groupes de 4 separes par
    des tirets. Tolere espaces, tirets manquants et minuscules."""
    compact = "".join(ch for ch in (raw or "").upper() if ch.isalnum())
    return "-".join(compact[i : i + 4] for i in range(0, len(compact), 4))


def generate_tracking_token(case):
    """Cree (ou renouvelle) le code de suivi public d'un case sans compte.

    Format XXXX-XXXX-XXXX-XXXX-XXXX, facile a noter et a recopier. La valeur
    en clair n'est jamais persistee : seul son hash est stocke, au meme titre
    que les cles d'API. Elle est renvoyee a l'appelant pour etre transmise
    une seule fois (email ou affichage a l'ecran), puis perdue cote serveur.
    """
    compact = "".join(secrets.choice(TRACKING_ALPHABET) for _ in range(TRACKING_CODE_LENGTH))
    raw = normalize_tracking_code(compact)
    CaseTrackingToken.objects.update_or_create(
        case=case,
        defaults={
            "token_hash": hash_text(raw),
            "expires_at": timezone.now() + TRACKING_TOKEN_VALIDITY,
        },
    )
    return raw


def resolve_tracking_token(raw_token):
    """Retrouve le case associe a un code de suivi valide, ou None.

    Accepte le code tel que saisi (anciens jetons, sensibles a la casse) ou
    sous sa forme canonique (casse et tirets indifferents). Ne distingue
    jamais "code inconnu" de "code expire" dans la reponse appelante : les
    deux doivent produire le meme message generique cote vue.
    """
    if not raw_token or not raw_token.strip():
        return None
    candidates = {hash_text(raw_token.strip()), hash_text(normalize_tracking_code(raw_token))}
    token = (
        CaseTrackingToken.objects.select_related("case")
        .filter(token_hash__in=candidates)
        .first()
    )
    if token is None or not token.is_valid:
        return None
    token.record_access()
    return token.case


#: Paliers affiches au declarant, dans l'ordre (barre de progression).
PUBLIC_STEPS = [
    ("RECEIVED", "Reçu"),
    ("ANALYSIS", "En analyse"),
    ("VALIDATED", "Validé"),
    ("IN_PROGRESS", "En correction"),
    ("RESOLVED", "Publié"),
]


def information_request_for(case):
    """Question posee au declarant lors de la derniere demande de complements."""
    entry = (
        case.status_history.filter(to_status=CaseStatus.NEEDS_INFORMATION)
        .order_by("-created_at")
        .first()
    )
    return entry.comment if entry else ""


def public_status_for(case):
    """Statut simplifie (5 paliers) pour la page de suivi publique."""
    key, label = public_status_bucket(case.status)
    keys = [k for k, _ in PUBLIC_STEPS]
    # Une demande de complements intervient pendant l'analyse.
    current = (
        keys.index("ANALYSIS")
        if key == "NEEDS_INFORMATION"
        else (keys.index(key) if key in keys else -1)
    )
    needs_information = key == "NEEDS_INFORMATION"
    return {
        "key": key,
        "label": label,
        "case_id": case.case_id,
        "submitted_at": case.created_at,
        "is_dismissed": key == "DISMISSED",
        "is_resolved": key == "RESOLVED",
        "needs_information": needs_information,
        "question": information_request_for(case) if needs_information else "",
        "steps": [
            {"label": step_label, "done": i < current, "current": i == current}
            for i, (_k, step_label) in enumerate(PUBLIC_STEPS)
        ],
    }


@transaction.atomic
def provide_information_anonymously(case, body, attachments=(), request=None):
    """Reponse d'un declarant SANS compte a une demande de complements.

    Le code de suivi tient lieu d'authentification (possession du code).
    Le message rejoint le canal chercheur, les pieces jointes deviennent des
    preuves en lecture seule, et le dossier revient a son etape d'origine,
    exactement comme le bouton « Envoyer les compléments » d'un compte.
    """
    from apps.attachments.services import store_attachment, validate_upload

    from .workflow import find_transition

    transition = find_transition(case.status, "provide_information")
    if transition is None or case.reporter_id is not None:
        raise ValidationError("Aucune demande de compléments n'attend de réponse.")
    body = (body or "").strip()
    if not body:
        raise ValidationError({"body": "Votre réponse ne peut pas être vide."})
    attachments = list(attachments or [])[:5]
    for uploaded in attachments:
        validate_upload(uploaded)

    CaseMessage.objects.create(
        case=case,
        author=None,
        body=f"**Compléments du déclarant (lien de suivi)**\n\n{body}",
        confidentiality=Confidentiality.PARTICIPANTS,
    )
    for uploaded in attachments:
        store_attachment(uploaded, None, case=case, report=case.report, request=request)
    log_action(
        AuditAction.MESSAGE_SENT,
        obj=case,
        request=request,
        via="tracking_code",
        attachments=len(attachments),
    )
    _apply_transition(
        case,
        transition,
        resolve_target(case, transition),
        None,
        "Compléments envoyés par le déclarant via son code de suivi.",
        request,
        case.status,
    )
    return case


__all__ = [
    "transition_case",
    "assign_case",
    "post_message",
    "visible_messages",
    "mark_duplicate",
    "propose_duplicate",
    "set_severity",
    "escalate_case",
    "record_admissibility",
    "record_vendor_summary",
    "record_remediation_plan",
    "record_fix",
    "record_fix_verification",
    "schedule_disclosure",
    "add_participant",
    "ensure_default_participants",
    "add_timeline_event",
    "schedule_initial_sla",
    "generate_tracking_token",
    "resolve_tracking_token",
    "public_status_for",
    "provide_information_anonymously",
    "WorkflowType",
]
