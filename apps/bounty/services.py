"""Cycle de vie des recompenses Bug Bounty."""

from decimal import Decimal

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
from apps.programs.models import ProgramType

from .models import (
    Bounty,
    BountyPayment,
    BountyReview,
    BountyStatus,
    PaymentStatus,
    ReviewDecision,
)


def suggested_amount(case):
    """Montant suggere par la matrice du programme (jamais code en dur)."""
    program = case.program
    policy = getattr(program, "reward_policy", None) if program else None
    if not policy or not policy.is_active:
        return Decimal("0"), "XOF"
    return policy.suggested_amount(case.severity), policy.currency


@transaction.atomic
def propose_bounty(case, actor, amount=None, justification="", request=None):
    """Cree ou met a jour la proposition de recompense d'un case Bug Bounty."""
    if not actor.has_capability(Capability.PROPOSE_BOUNTY):
        raise PermissionDenied("Capacite requise pour proposer une recompense.")
    if not case.program_id or case.program.program_type != ProgramType.BUG_BOUNTY:
        raise ValidationError(
            "Une recompense ne peut etre proposee que sur un programme Bug Bounty."
        )
    if case.reporter_id is None:
        raise ValidationError(
            "Aucun chercheur identifie : impossible d'attribuer une recompense."
        )

    default_amount, currency = suggested_amount(case)
    amount = Decimal(amount) if amount is not None else default_amount
    if amount < 0:
        raise ValidationError({"amount": "Montant negatif interdit."})

    bounty = getattr(case, "bounty", None)
    if bounty is None:
        bounty = Bounty(case=case, program=case.program, researcher=case.reporter)
    elif bounty.is_final:
        raise ValidationError("Cette recompense a deja fait l'objet d'une decision finale.")

    bounty.severity = case.severity
    bounty.proposed_amount = amount
    bounty.currency = currency
    bounty.justification = justification
    bounty.proposed_by = actor
    bounty.status = BountyStatus.PENDING
    bounty.full_clean(exclude=["approved_amount"])
    bounty.save()

    log_action(
        AuditAction.BOUNTY_PROPOSED,
        actor=actor,
        obj=bounty,
        request=request,
        case=case.case_id,
        amount=str(amount),
        currency=currency,
    )
    notify(case.reporter, NotificationKind.BOUNTY_PROPOSED, case=case)
    return bounty


@transaction.atomic
def review_bounty(bounty, reviewer, decision, comment="", suggested=None, request=None):
    """Enregistre un avis de revue (sans decision finale)."""
    if not reviewer.has_capability(Capability.PROPOSE_BOUNTY):
        raise PermissionDenied("Capacite requise pour participer a la revue.")
    review = BountyReview.objects.create(
        bounty=bounty,
        reviewer=reviewer,
        decision=decision,
        comment=comment,
        suggested_amount=suggested,
    )
    if bounty.status == BountyStatus.PENDING:
        bounty.status = BountyStatus.UNDER_REVIEW
        bounty.save(update_fields=["status", "updated_at"])
    log_action(
        AuditAction.CASE_UPDATED,
        actor=reviewer,
        obj=bounty,
        request=request,
        decision=decision,
    )
    return review


@transaction.atomic
def approve_bounty(bounty, approver, amount=None, note="", request=None):
    """Approuve une recompense. Seul un valideur habilite peut le faire."""
    if not approver.has_capability(Capability.APPROVE_BOUNTY):
        raise PermissionDenied("Capacite requise pour approuver une recompense.")
    if not bounty.can_transition_to(BountyStatus.APPROVED):
        raise ValidationError(
            f"Transition interdite depuis l'etat {bounty.get_status_display()}."
        )
    amount = Decimal(amount) if amount is not None else bounty.proposed_amount
    if amount < 0:
        raise ValidationError({"amount": "Montant negatif interdit."})

    bounty.approved_amount = amount
    bounty.status = BountyStatus.APPROVED
    bounty.decided_by = approver
    bounty.decided_at = timezone.now()
    bounty.decision_note = note
    bounty.save(
        update_fields=[
            "approved_amount",
            "status",
            "decided_by",
            "decided_at",
            "decision_note",
            "updated_at",
        ]
    )

    if not bounty.within_policy():
        log_action(
            AuditAction.BOUNTY_APPROVED,
            actor=approver,
            obj=bounty,
            request=request,
            warning="montant hors matrice du programme",
            amount=str(amount),
        )
    log_action(
        AuditAction.BOUNTY_APPROVED,
        actor=approver,
        obj=bounty,
        request=request,
        case=bounty.case.case_id,
        amount=str(amount),
        currency=bounty.currency,
    )
    add_timeline_event(
        bounty.case,
        TimelineEventType.REWARD_APPROVED,
        f"Recompense approuvee : {bounty.display_amount}",
        actor=approver,
    )
    if bounty.researcher_id:
        notify(bounty.researcher, NotificationKind.BOUNTY_APPROVED, case=bounty.case)
        profile = getattr(bounty.researcher, "researcher_profile", None)
        if profile:
            profile.recompute()
    return bounty


@transaction.atomic
def reject_bounty(bounty, approver, note="", request=None):
    if not approver.has_capability(Capability.APPROVE_BOUNTY):
        raise PermissionDenied("Capacite requise pour statuer sur une recompense.")
    if not bounty.can_transition_to(BountyStatus.REJECTED):
        raise ValidationError("Transition interdite.")
    bounty.status = BountyStatus.REJECTED
    bounty.decided_by = approver
    bounty.decided_at = timezone.now()
    bounty.decision_note = note
    bounty.save(
        update_fields=["status", "decided_by", "decided_at", "decision_note", "updated_at"]
    )
    log_action(
        AuditAction.BOUNTY_REJECTED,
        actor=approver,
        obj=bounty,
        request=request,
        case=bounty.case.case_id,
        reason=note[:200],
    )
    if bounty.researcher_id:
        notify(bounty.researcher, NotificationKind.BOUNTY_REJECTED, case=bounty.case)
    return bounty


@transaction.atomic
def record_payment(bounty, actor, amount=None, method=None, reference="", request=None):
    """Enregistre la trace comptable d'un versement.

    MVP : aucun flux financier reel n'est declenche. L'integration avec un
    prestataire de paiement se branchera ici.
    """
    if not actor.has_capability(Capability.RECORD_PAYMENT):
        raise PermissionDenied("Capacite requise pour enregistrer un paiement.")
    if bounty.status != BountyStatus.APPROVED:
        raise ValidationError("Seule une recompense approuvee peut etre versee.")

    payment = BountyPayment.objects.create(
        bounty=bounty,
        amount=Decimal(amount) if amount is not None else bounty.approved_amount,
        currency=bounty.currency,
        method=method or BountyPayment._meta.get_field("method").default,
        reference=reference[:120],
        status=PaymentStatus.RECORDED,
        recorded_by=actor,
    )
    bounty.status = BountyStatus.PAID
    bounty.save(update_fields=["status", "updated_at"])

    log_action(
        AuditAction.BOUNTY_PAID,
        actor=actor,
        obj=bounty,
        request=request,
        case=bounty.case.case_id,
        amount=str(payment.amount),
        reference=payment.reference,
    )
    if bounty.researcher_id:
        notify(bounty.researcher, NotificationKind.BOUNTY_PAID, case=bounty.case)
        profile = getattr(bounty.researcher, "researcher_profile", None)
        if profile:
            profile.recompute()
    return payment


__all__ = [
    "propose_bounty",
    "review_bounty",
    "approve_bounty",
    "reject_bounty",
    "record_payment",
    "suggested_amount",
    "ReviewDecision",
]
