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
from apps.notifications.services import notify, notify_external, notify_many
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
from .visibility import readable_channels, writable_channels
from .workflow import (
    ADMISSIBILITY_CHECKLIST,
    ORG_VISIBLE_STATES,
    PRIMARY,
    TERMINAL_STATES,
    BountyStage,
    CaseStatus,
    TransitionNotAllowed,
    available_actions,
    check_transition,
    claim_action,
    claim_holder,
    current_actions,
    current_owner_ids,
    get_action,
    public_status_bucket,
    public_status_of,
    resolve_target,
    step_owners,
    working_advisory,
)

#: Duree de validite d'un lien de suivi remis a un declarant sans compte.
TRACKING_TOKEN_VALIDITY = timedelta(days=180)

#: Statut -> evenement de chronologie correspondant.
STATUS_TIMELINE_EVENTS = {
    CaseStatus.ACKNOWLEDGED: TimelineEventType.ACKNOWLEDGED,
    CaseStatus.IN_ANALYSIS: TimelineEventType.TRIAGE_STARTED,
    CaseStatus.NEEDS_INFORMATION: TimelineEventType.INFORMATION_REQUESTED,
    CaseStatus.VALIDATION_PENDING: TimelineEventType.QUALIFICATION_SUBMITTED,
    CaseStatus.VALIDATED: TimelineEventType.VALIDATED,
    CaseStatus.VENDOR_NOTIFIED: TimelineEventType.ORGANIZATION_CONTACTED,
    CaseStatus.REMEDIATION_IN_PROGRESS: TimelineEventType.ORGANIZATION_ACKNOWLEDGED,
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
    """Rattache le declarant, puis les contacts de l'organisation.

    Les contacts de l'organisation ne sont rattaches qu'a partir de l'etape 5
    (transmission a l'organisation) : jamais pendant le triage.
    """
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
    """Ouvre l'echeance de l'etape 1 (accuse de reception, 72 h)."""
    policy = resolve_sla_policy(case)
    if policy is None:
        return []
    due = timezone.now() + timedelta(hours=policy.acknowledgement_hours)
    return [open_sla(case, SLAKind.ACKNOWLEDGEMENT, due, policy=policy)]


def open_sla(case, kind, due_at, policy=None):
    """Ouvre (ou rouvre) l'echeance d'une etape.

    Une etape peut etre rejouee (renvoi a l'auteur, correctif insuffisant) :
    son echeance repart alors de zero au lieu de rester soldee.
    """
    policy = policy or resolve_sla_policy(case)
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
        # created_at sert de point de depart au calcul du seuil orange.
        SLAEvent.objects.filter(pk=event.pk).update(created_at=timezone.now())
        event.refresh_from_db(fields=["created_at"])
    return event


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


#: Echeance ouverte en entrant dans un statut : type et delai selon la politique.
_SLA_ON_ENTRY = {
    CaseStatus.ACKNOWLEDGED: (SLAKind.TRIAGE, "triage_days"),
    CaseStatus.VALIDATION_PENDING: (SLAKind.VALIDATION, "validation_days"),
    CaseStatus.VENDOR_NOTIFIED: (SLAKind.VENDOR_RESPONSE, "vendor_response_days"),
    CaseStatus.FIX_AVAILABLE: (SLAKind.VERIFICATION, "verification_days"),
}

#: Echeance soldee en quittant un statut vers l'avant.
_SLA_ON_EXIT = {
    CaseStatus.SUBMITTED: SLAKind.ACKNOWLEDGEMENT,
    CaseStatus.IN_ANALYSIS: SLAKind.TRIAGE,
    CaseStatus.VALIDATION_PENDING: SLAKind.VALIDATION,
    CaseStatus.VENDOR_NOTIFIED: SLAKind.VENDOR_RESPONSE,
    CaseStatus.REMEDIATION_IN_PROGRESS: SLAKind.REMEDIATION,
    CaseStatus.FIX_AVAILABLE: SLAKind.VERIFICATION,
}

#: Statuts d'exception : l'echeance de l'etape d'origine n'est pas soldee.
_SUSPENDING_STATES = (CaseStatus.NEEDS_INFORMATION, CaseStatus.REJECTION_PENDING)


def _sla_side_effects(case, previous, new_status):
    """Ouvre et solde les echeances au fil des etapes."""
    exit_kind = _SLA_ON_EXIT.get(previous)
    if exit_kind and new_status not in _SUSPENDING_STATES:
        satisfy_sla(case, exit_kind)
    if new_status in TERMINAL_STATES:
        case.sla_events.filter(state__in=[SLAState.PENDING, SLAState.APPROACHING]).update(
            state=SLAState.CANCELLED
        )
        return
    if previous in _SUSPENDING_STATES:
        # Retour a l'etape d'origine : son echeance, reportee, reste en cours.
        return
    policy = resolve_sla_policy(case)
    if policy is None:
        return
    entry = _SLA_ON_ENTRY.get(new_status)
    if entry:
        kind, days_field = entry
        due = timezone.now() + timedelta(days=getattr(policy, days_field))
        open_sla(case, kind, due, policy=policy)
    if new_status == CaseStatus.REMEDIATION_IN_PROGRESS and case.remediation_target_date:
        open_sla(
            case,
            SLAKind.REMEDIATION,
            _start_of_day(case.remediation_target_date + timedelta(days=1)),
            policy=policy,
        )


def _pause_sla(case):
    case.sla_paused_at = timezone.now()


def _resume_sla(case):
    """Reporte les echeances en cours de la duree de la suspension."""
    if case.sla_paused_at is None:
        return
    paused_for = timezone.now() - case.sla_paused_at
    for event in case.sla_events.filter(state__in=[SLAState.PENDING, SLAState.APPROACHING]):
        event.due_at = event.due_at + paused_for
        event.save(update_fields=["due_at", "updated_at"])
    case.sla_paused_at = None


# ---------------------------------------------------------------------------
# Actions de workflow
# ---------------------------------------------------------------------------
def perform_action(case, action_key, actor, data=None, request=None):
    """Execute une action du workflow v2 apres les controles serveur.

    La verification est faite HORS transaction : un refus doit laisser une
    trace d'audit persistante, or un rollback effacerait cette trace.
    `actor=None` designe le systeme (taches planifiees).
    """
    data = dict(data or {})
    data["comment"] = (data.get("comment") or "").strip()
    try:
        action = get_action(action_key)
        check_transition(case, action, user=actor, data=data)
    except TransitionNotAllowed as exc:
        log_action(
            AuditAction.STATUS_CHANGED,
            actor=actor,
            obj=case,
            result=AuditResult.DENIED,
            request=request,
            workflow_action=action_key,
            from_status=case.status,
            reason=str(exc),
        )
        raise
    return _apply_action(case, action, actor, data, request)


def transition_case(case, target_status, actor, comment="", request=None, data=None):
    """Compatibilite : applique l'action qui mene au statut demande.

    Chaque etape n'ayant qu'une action par cible, le statut vise suffit a
    retrouver le bouton correspondant ; tous les controles s'appliquent.
    """
    for action in available_actions(case):
        if (
            action.track == "case"
            and action.target
            and resolve_target(case, action) == target_status
        ):
            payload = dict(data or {})
            payload["comment"] = comment
            return perform_action(case, action.key, actor, data=payload, request=request)
    log_action(
        AuditAction.STATUS_CHANGED,
        actor=actor,
        obj=case,
        result=AuditResult.DENIED,
        request=request,
        from_status=case.status,
        to_status=target_status,
        reason="transition inexistante",
    )
    raise TransitionNotAllowed(f"Transition interdite : {case.status} -> {target_status}.")


@transaction.atomic
def _apply_action(case, action, actor, data, request):
    """Applique effectivement l'action validee (atomique et auditee)."""
    now = timezone.now()
    previous = case.status
    target = resolve_target(case, action) if action.track == "case" else None
    updates = set()
    handler = _ACTION_HANDLERS.get(action.key)
    if handler is not None:
        updates |= set(handler(case, actor, data, now, request) or ())

    if target is not None and target != previous:
        case.status = target
        updates.add("status")
        updates |= _status_timestamps(case, target, now)
        if previous in _SUSPENDING_STATES and target == case.return_status:
            case.return_status = ""
            updates.add("return_status")
    if updates:
        case.save(update_fields=sorted(updates | {"updated_at"}))

    if case.status in ORG_VISIBLE_STATES and previous not in ORG_VISIBLE_STATES:
        ensure_default_participants(case)
    if case.status != previous:
        CaseStatusHistory.objects.create(
            case=case,
            from_status=previous,
            to_status=case.status,
            actor=actor,
            comment=data["comment"],
        )
        add_timeline_event(
            case,
            STATUS_TIMELINE_EVENTS.get(case.status, TimelineEventType.STATUS_CHANGED),
            case.get_status_display(),
            actor=actor,
            action=action.key,
        )
        _sla_side_effects(case, previous, case.status)
        case.refresh_priority()
        log_action(
            AuditAction.STATUS_CHANGED,
            actor=actor,
            obj=case,
            request=request,
            workflow_action=action.key,
            from_status=previous,
            to_status=case.status,
        )
        _notify_status_change(case, previous, case.status, actor)
        _apply_reputation(case, case.status, actor)
    else:
        log_action(
            AuditAction.CASE_UPDATED,
            actor=actor,
            obj=case,
            request=request,
            workflow_action=action.key,
            bounty_stage=case.bounty_stage,
            comment=data["comment"][:200],
        )
    _notify_next_owner(case, actor)
    return case


def _status_timestamps(case, target, now):
    updates = set()
    if target == CaseStatus.ACKNOWLEDGED and not case.acknowledged_at:
        case.acknowledged_at = now
        updates.add("acknowledged_at")
    if target == CaseStatus.FIX_AVAILABLE and not case.remediated_at:
        case.remediated_at = now
        updates.add("remediated_at")
    if target in TERMINAL_STATES and not case.closed_at:
        case.closed_at = now
        updates.add("closed_at")
    return updates


# -- Effets propres a chaque action -------------------------------------------
def _on_declare_admissible(case, actor, data, now, request):
    case.admissibility_checklist = {
        key: bool(data.get(key)) for key, _label in ADMISSIBILITY_CHECKLIST
    }
    return ["admissibility_checklist"]


def _on_validate(case, actor, data, now, request):
    from apps.programs.models import ProgramType

    updates = []
    if not case.validated_at:
        case.validated_at = now
        updates.append("validated_at")
        if case.program_id and case.disclosure_date is None:
            case.disclosure_date = (
                now + timedelta(days=case.program.disclosure_delay_days)
            ).date()
            updates.append("disclosure_date")
    # Branche prime : ouverte des la validation pour un programme eligible,
    # afin de ne pas faire attendre le chercheur la fin de la remediation.
    if not case.bounty_stage:
        eligible = (
            case.program_id is not None
            and case.program.program_type == ProgramType.BUG_BOUNTY
            and case.reporter_id is not None
        )
        case.bounty_stage = BountyStage.ELIGIBLE if eligible else BountyStage.NOT_ELIGIBLE
        updates.append("bounty_stage")
    return updates


def _on_notify_vendor(case, actor, data, now, request):
    case.vendor_notified_at = now
    return ["vendor_notified_at"]


def _on_remediation_plan(case, actor, data, now, request):
    case.remediation_plan = data["remediation_plan"].strip()
    case.remediation_target_date = data["remediation_target_date"]
    return ["remediation_plan", "remediation_target_date"]


def _on_declare_fix(case, actor, data, now, request):
    case.fix_description = data["fix_description"].strip()
    case.fix_version = (data.get("fix_version") or "").strip()[:120]
    case.fix_deployed_on = data.get("fix_deployed_on") or None
    return ["fix_description", "fix_version", "fix_deployed_on"]


def _on_confirm_fix(case, actor, data, now, request):
    case.verification_report = data["verification_report"].strip()
    return ["verification_report"]


def _on_insufficient_fix(case, actor, data, now, request):
    post_message(
        case,
        None,
        "Correctif jugé insuffisant par le CSIRT :\n\n" + data["comment"],
        confidentiality=Confidentiality.ORGANIZATION,
        is_system=True,
    )
    return []


def _on_submit_advisory(case, actor, data, now, request):
    from apps.disclosures.models import AdvisoryStatus

    advisory = working_advisory(case)
    if advisory.status == AdvisoryStatus.DRAFT:
        advisory.status = AdvisoryStatus.IN_REVIEW
        advisory.save(update_fields=["status", "updated_at"])
    return []


def _on_publish(case, actor, data, now, request):
    from apps.disclosures.models import AdvisoryStatus
    from apps.disclosures.services import publish_advisory

    advisory = working_advisory(case)
    if advisory.status in (AdvisoryStatus.DRAFT, AdvisoryStatus.IN_REVIEW):
        advisory.status = AdvisoryStatus.APPROVED
        advisory.save(update_fields=["status", "updated_at"])
    publish_advisory(advisory, actor, request=request, from_workflow=True)
    case.is_published = True
    return ["is_published"]


def _on_propose_bounty(case, actor, data, now, request):
    from apps.bounty.services import propose_bounty

    propose_bounty(
        case,
        actor,
        amount=data.get("amount"),
        justification=data.get("justification", ""),
        request=request,
    )
    add_timeline_event(case, TimelineEventType.REWARD_PROPOSED, "Prime proposée", actor)
    return []


def _on_approve_bounty(case, actor, data, now, request):
    from apps.bounty.services import approve_bounty

    approve_bounty(
        case.bounty, actor, amount=data.get("amount"), note=data["comment"], request=request
    )
    return []


def _on_return_bounty(case, actor, data, now, request):
    bounty = case.bounty
    bounty.decision_note = data["comment"]
    bounty.save(update_fields=["decision_note", "updated_at"])
    case.bounty_stage = BountyStage.ELIGIBLE
    add_timeline_event(case, TimelineEventType.RETURNED, "Prime renvoyée au proposeur", actor)
    return ["bounty_stage"]


def _on_request_information(case, actor, data, now, request):
    case.return_status = case.status
    _pause_sla(case)
    post_message(
        case,
        None,
        "Compléments demandés par l'équipe de coordination :\n\n" + data["comment"],
        confidentiality=Confidentiality.RESEARCHER,
        is_system=True,
    )
    return ["return_status", "sla_paused_at"]


def _on_send_information(case, actor, data, now, request):
    _resume_sla(case)
    post_message(case, actor, data["comment"], confidentiality=Confidentiality.RESEARCHER)
    add_timeline_event(
        case, TimelineEventType.INFORMATION_PROVIDED, "Compléments reçus", actor
    )
    return ["sla_paused_at"]


def _on_propose_rejection(case, actor, data, now, request):
    if case.status != CaseStatus.NEEDS_INFORMATION:
        case.return_status = case.status
    case.duplicate_of = None
    return ["return_status", "duplicate_of"]


def _on_propose_duplicate(case, actor, data, now, request):
    case.return_status = case.status
    case.duplicate_of = data["original"]
    return ["return_status", "duplicate_of"]


def _on_confirm_rejection(case, actor, data, now, request):
    if case.duplicate_of_id:
        log_action(
            AuditAction.REPORT_DUPLICATED,
            actor=actor,
            obj=case,
            request=request,
            original_case=case.duplicate_of.case_id,
        )
    else:
        log_action(AuditAction.REPORT_REJECTED, actor=actor, obj=case, request=request)
    case.sla_paused_at = None
    return ["sla_paused_at"]


def _on_return_rejection(case, actor, data, now, request):
    case.duplicate_of = None
    _resume_sla(case)
    add_timeline_event(
        case, TimelineEventType.RETURNED, "Rejet renvoyé à l'étape d'origine", actor
    )
    return ["duplicate_of", "sla_paused_at"]


def _on_propose_closure(case, actor, data, now, request):
    add_timeline_event(
        case, TimelineEventType.RETURNED, "Clôture sans advisory proposée", actor
    )
    return []


def _on_close_without_advisory(case, actor, data, now, request):
    add_timeline_event(
        case, TimelineEventType.CLOSED, "Dossier clos sans publication d'advisory", actor
    )
    return []


def _on_return_to_author(case, actor, data, now, request):
    add_timeline_event(case, TimelineEventType.RETURNED, "Renvoyé à l'auteur", actor)
    return []


def _on_escalate(case, actor, data, now, request):
    escalate_case(case, actor, data["comment"], request=request, save=False)
    return ["escalated_at"]


def _on_deadline_disclosure(case, actor, data, now, request):
    case.deadline_disclosure_at = now
    add_timeline_event(
        case,
        TimelineEventType.DISCLOSURE_SCHEDULED,
        "Divulgation à échéance décidée",
        actor,
    )
    return ["deadline_disclosure_at"]


_ACTION_HANDLERS = {
    "declare_admissible": _on_declare_admissible,
    "validate_qualification": _on_validate,
    "notify_vendor": _on_notify_vendor,
    "submit_remediation_plan": _on_remediation_plan,
    "declare_fix": _on_declare_fix,
    "confirm_fix": _on_confirm_fix,
    "insufficient_fix": _on_insufficient_fix,
    "submit_advisory": _on_submit_advisory,
    "publish_and_close": _on_publish,
    "propose_bounty": _on_propose_bounty,
    "approve_bounty": _on_approve_bounty,
    "return_bounty": _on_return_bounty,
    "request_information": _on_request_information,
    "send_information": _on_send_information,
    "propose_rejection": _on_propose_rejection,
    "propose_duplicate": _on_propose_duplicate,
    "confirm_rejection": _on_confirm_rejection,
    "return_rejection": _on_return_rejection,
    "return_to_author": _on_return_to_author,
    "propose_closure": _on_propose_closure,
    "close_without_advisory": _on_close_without_advisory,
    "escalate": _on_escalate,
    "decide_deadline_disclosure": _on_deadline_disclosure,
}


def escalate_case(case, actor, reason, request=None, save=True):
    """Alerte rouge : le Coordinateur est notifie, le statut ne change pas."""
    from apps.accounts.models import User
    from apps.accounts.roles import Role

    if case.escalated_at:
        return case
    case.escalated_at = timezone.now()
    if save:
        case.save(update_fields=["escalated_at", "updated_at"])
        log_action(
            AuditAction.CASE_UPDATED,
            actor=actor,
            obj=case,
            request=request,
            workflow_action="escalate",
            reason=reason[:200],
        )
    add_timeline_event(case, TimelineEventType.ESCALATED, "Dossier escaladé", actor)
    coordinators = User.objects.filter(is_active=True, role=Role.NATIONAL_COORDINATOR)
    notify_many(coordinators, NotificationKind.ESCALATED, case=case)
    return case


def _notify_status_change(case, previous, status, actor):
    """Declarant : seulement quand son statut simplifie evolue (ou action dediee)."""
    kind = STATUS_NOTIFICATIONS.get(status)
    if kind is None and public_status_bucket(previous) != public_status_bucket(status):
        kind = NotificationKind.STATUS_CHANGED
    if kind is not None:
        if case.reporter_id:
            if actor is None or case.reporter_id != actor.pk:
                notify(case.reporter, kind, case=case)
        elif getattr(case.report, "reporter_email", ""):
            notify_external(case.report.reporter_email, kind, case=case)
    # Les responsables de l'etape suivante recoivent leur propre avis
    # (notify_step_owners) : pas de doublon « statut modifie ».
    notify_case_staff(
        case, NotificationKind.STATUS_CHANGED, exclude=actor, skip=current_owner_ids(case)
    )


def notify_case_staff(case, kind, exclude=None, skip=()):
    """Equipe du dossier hors declarant, limitee a qui voit le dossier."""
    from apps.accounts.models import User

    ids = set(case.participant_user_ids())
    if case.assignee_id:
        ids.add(case.assignee_id)
    ids.discard(case.reporter_id)
    ids -= set(skip)
    if exclude is not None:
        ids.discard(exclude.pk)
    recipients = [
        user
        for user in User.objects.filter(id__in=ids, is_active=True)
        if case.is_visible_to(user)
    ]
    return notify_many(recipients, kind, case=case)


def owners_of(case, action):
    """Utilisateurs pouvant cliquer le bouton `action` sur ce dossier."""
    return step_owners(case, action)


def notify_step_owners(case, actor=None):
    """Notification et email au responsable de chaque etape en cours.

    Appelee a chaque etape franchie (et a la soumission) : le responsable
    du bouton attendu -- dossier et branche prime -- est avise dans la
    plateforme et par email (« En attente de : … »). Le declarant, quand
    l'etape lui revient, l'est par sa propre notification de statut.
    """
    notified = []
    for action in current_actions(case):
        # L'escalade a son propre avis (NotificationKind.ESCALATED).
        if action.reporter_only or action.kind != PRIMARY:
            continue
        recipients = [
            user for user in step_owners(case, action) if actor is None or user.pk != actor.pk
        ]
        notified += notify_many(
            recipients,
            NotificationKind.ACTION_REQUIRED,
            case=case,
            title=f"[{case.case_id}] {action.label}",
            body=f"Étape {action.step or '—'} : {action.label}. Vous en êtes responsable.",
        )
    return notified


def _notify_next_owner(case, actor):
    notify_step_owners(case, actor)


def _apply_reputation(case, status, actor):
    """Attribue les points de reputation lors de la validation d'un rapport."""
    from apps.researchers.services import award_reputation

    if status == CaseStatus.VALIDATED and case.reporter_id:
        award_reputation(case.reporter, case, granted_by=actor)


# ---------------------------------------------------------------------------
# Assignation
# ---------------------------------------------------------------------------
@transaction.atomic
def _record_claim(case, user, actor, note, request, pool):
    """Enregistre la prise en charge de `user`, liberant ses collegues."""
    pool_ids = {member.pk for member in pool}
    case.assignments.filter(is_active=True, user_id__in=pool_ids).update(is_active=False)
    CaseAssignment.objects.create(case=case, user=user, assigned_by=actor, note=note[:255])
    case.assignee = user
    case.save(update_fields=["assignee", "updated_at"])
    add_participant(case, user, ParticipantRole.ANALYST, added_by=actor)


@transaction.atomic
def claim_case(case, actor, request=None):
    """« Prendre en charge » : le responsable de l'etape s'attribue le dossier.

    Le dossier disparait alors de la file de ses collegues du meme role, qui
    ne recoivent plus ses avis. L'attribution vaut pour les etapes suivantes
    de ce meme role (l'analyste suit son dossier de l'etape 3 a l'etape 9) et
    ne gene jamais les autres roles.
    """
    action = claim_action(case)
    pool = step_owners(case, action, ignore_claim=True) if action else []
    if actor.pk not in {user.pk for user in pool}:
        raise PermissionDenied("Réservé au responsable de l'étape en cours.")
    holder = claim_holder(case)
    if holder is not None:
        raise ValidationError(f"Dossier déjà pris en charge par {holder.display_name}.")
    _record_claim(case, actor, actor, "Prise en charge", request, pool)
    add_timeline_event(case, TimelineEventType.ASSIGNED, "Dossier pris en charge", actor=actor)
    log_action(
        AuditAction.CASE_ASSIGNED,
        actor=actor,
        obj=case,
        request=request,
        claimed_by=str(actor),
        step=action.step,
    )
    return case


@transaction.atomic
def transfer_case(case, actor, target, note="", request=None):
    """« Transférer à un collègue » : passage de relais au sein du meme role."""
    action = claim_action(case)
    if claim_holder(case) != actor:
        raise PermissionDenied("Seul le compte qui a pris le dossier en charge le transfère.")
    pool = step_owners(case, action, ignore_claim=True)
    if target is None or target.pk == actor.pk or target.pk not in {u.pk for u in pool}:
        raise ValidationError(
            "Le destinataire doit être un collègue responsable de cette étape."
        )
    _record_claim(case, target, actor, note or "Transfert", request, pool)
    notify(target, NotificationKind.CASE_ASSIGNED, case=case)
    add_timeline_event(
        case, TimelineEventType.ASSIGNED, f"Dossier transféré à {target}", actor=actor
    )
    log_action(
        AuditAction.CASE_ASSIGNED,
        actor=actor,
        obj=case,
        request=request,
        transferred_to=str(target),
        note=note[:200],
    )
    return case


def transfer_candidates(case, user):
    """Collegues a qui `user` peut transferer le dossier (meme role, meme etape)."""
    if claim_holder(case) != user:
        return []
    action = claim_action(case)
    return [
        member
        for member in step_owners(case, action, ignore_claim=True)
        if member.pk != user.pk
    ]


# ---------------------------------------------------------------------------
# Messagerie
# ---------------------------------------------------------------------------
@transaction.atomic
def post_message(
    case,
    author,
    body,
    confidentiality=Confidentiality.RESEARCHER,
    request=None,
    is_system=False,
):
    """Publie un message dans l'un des canaux du dossier.

    Le canal doit etre ouvert en ecriture a l'auteur selon la matrice de
    visibilite : la DSI n'ecrit jamais au chercheur, le declarant jamais a
    l'organisation.
    """
    if not is_system:
        if not case.is_visible_to(author):
            raise PermissionDenied("Vous n'avez pas accès à ce dossier.")
        if getattr(author, "is_read_only", False):
            raise PermissionDenied("Rôle en lecture seule.")
        if confidentiality not in writable_channels(case, author):
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
    _notify_channel(case, confidentiality, exclude=None if is_system else author)
    return message


def _notify_channel(case, confidentiality, exclude=None):
    """Avise les lecteurs du canal, jamais au-dela."""
    from apps.accounts.models import User

    ids = set(case.participant_user_ids())
    if case.assignee_id:
        ids.add(case.assignee_id)
    if case.reporter_id:
        ids.add(case.reporter_id)
    if exclude is not None:
        ids.discard(exclude.pk)
    recipients = [
        user
        for user in User.objects.filter(id__in=ids, is_active=True)
        if confidentiality in readable_channels(case, user)
    ]
    return notify_many(recipients, NotificationKind.NEW_MESSAGE, case=case)


def visible_messages(case, user):
    """Fil de discussion filtre selon les canaux lisibles par l'utilisateur."""
    return (
        case.messages.select_related("author")
        .prefetch_related("attachments")
        .filter(confidentiality__in=readable_channels(case, user))
    )


# ---------------------------------------------------------------------------
# Doublons
# ---------------------------------------------------------------------------
def mark_duplicate(case, original, actor, comment="", request=None):
    """Propose le dossier comme doublon d'un autre (etapes 1 a 3).

    Le Coordinateur confirme ensuite (DUPLICATE). Le declarant est informe
    du doublon mais n'obtient AUCUNE information sur le dossier original.
    """
    return perform_action(
        case,
        "propose_duplicate",
        actor,
        data={"comment": comment, "original": original},
        request=request,
    )


# ---------------------------------------------------------------------------
# Qualification
# ---------------------------------------------------------------------------
#: Etats ou la qualification reste modifiable : une fois soumise a
#: validation, elle ne change plus sans renvoi a l'auteur.
QUALIFICATION_EDITABLE_STATES = (
    CaseStatus.SUBMITTED,
    CaseStatus.ACKNOWLEDGED,
    CaseStatus.IN_ANALYSIS,
    CaseStatus.NEEDS_INFORMATION,
)


@transaction.atomic
def set_severity(case, actor, severity=None, cvss_vector="", request=None):
    """Definit la severite retenue, calculee depuis un CVSS v3.1 ou v4.0.

    Seul l'analyste CSIRT saisit le CVSS (matrice v2).
    """
    if not actor.has_capability(Capability.SET_SEVERITY):
        raise PermissionDenied("Capacité requise pour définir la sévérité.")
    if case.status not in QUALIFICATION_EDITABLE_STATES:
        raise ValidationError("La qualification n'est plus modifiable à cette étape.")
    from apps.vulnerabilities.cvss import CVSSError, evaluate, score_as_decimal

    updates = ["severity", "updated_at"]
    if cvss_vector:
        try:
            score, computed = evaluate(cvss_vector)
        except CVSSError as exc:
            raise ValidationError({"cvss_vector": str(exc)}) from exc
        case.cvss_vector = cvss_vector
        case.cvss_score = score_as_decimal(score)
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
    if not (
        actor.has_capability(Capability.ARBITRATE_CASE)
        or actor.has_capability(Capability.COORDINATE_VENDOR)
    ):
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
    key, label = public_status_of(case)
    return {
        "key": key,
        "label": label,
        "case_id": case.case_id,
        "submitted_at": case.created_at,
        "is_dismissed": key == "DISMISSED",
        "is_resolved": key == "RESOLVED",
    }


__all__ = [
    "perform_action",
    "escalate_case",
    "transition_case",
    "claim_case",
    "transfer_case",
    "post_message",
    "visible_messages",
    "mark_duplicate",
    "set_severity",
    "schedule_disclosure",
    "add_participant",
    "ensure_default_participants",
    "add_timeline_event",
    "schedule_initial_sla",
    "generate_tracking_token",
    "resolve_tracking_token",
    "public_status_for",
    "WorkflowType",
]
