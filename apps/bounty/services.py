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
    """Montant suggere par la matrice du programme (jamais code en dur).

    La grille peut varier par actif : une faille critique sur une API de
    production ne vaut pas la meme chose que sur un site vitrine. On passe
    donc l'actif retenu au triage ; sans actif, ou sans palier propre a cet
    actif, la grille par defaut du programme s'applique.
    """
    program = case.program
    policy = getattr(program, "reward_policy", None) if program else None
    if not policy or not policy.is_active:
        return Decimal("0"), "XOF"
    return policy.suggested_amount(case.severity, case.scope), policy.currency


def budget_status(bounty, amount=None):
    """Projection du budget du programme si `amount` etait approuve.

    Retourne None quand le programme ne declare aucun budget total. Sinon un
    dictionnaire decrivant la consommation avant / apres la decision.

    `RewardPolicy.budget_consumed()` additionne les recompenses deja APPROVED
    ou PAID : la recompense courante en est retranchee quand elle y figure
    deja, afin de ne jamais la compter deux fois.
    """
    policy = getattr(bounty.program, "reward_policy", None) if bounty.program_id else None
    if policy is None or policy.total_budget is None:
        return None

    consumed = policy.budget_consumed()
    if bounty.status in (BountyStatus.APPROVED, BountyStatus.PAID):
        consumed -= bounty.approved_amount or Decimal("0")
    if amount is None:
        amount = (
            bounty.approved_amount
            if bounty.approved_amount is not None
            else bounty.proposed_amount
        )

    projected = consumed + amount
    return {
        "currency": policy.currency,
        "total": policy.total_budget,
        "consumed": consumed,
        "projected": projected,
        "remaining": policy.total_budget - projected,
        "exceeded": projected > policy.total_budget,
    }


@transaction.atomic
def propose_bounty(case, actor, amount=None, justification="", request=None):
    """Cree ou met a jour la proposition de recompense d'un case Bug Bounty."""
    if not actor.has_capability(Capability.PROPOSE_BOUNTY):
        raise PermissionDenied("Capacité requise pour proposer une récompense.")
    if not case.program_id or case.program.program_type != ProgramType.BUG_BOUNTY:
        raise ValidationError(
            "Une récompense ne peut être proposée que sur un programme Bug Bounty."
        )
    if case.reporter_id is None:
        raise ValidationError(
            "Aucun chercheur identifié : impossible d'attribuer une récompense."
        )
    # Second controle, apres celui de la soumission : le programme a pu
    # devenir exigeant depuis, et une recompense ne doit jamais partir vers
    # une adresse dont personne n'a prouve le controle.
    if case.program.requires_verified_email and not case.reporter.email_verified:
        raise ValidationError(
            "Le chercheur n'a pas vérifié son adresse email : aucune récompense "
            "ne peut lui être attribuée sur ce programme."
        )

    default_amount, currency = suggested_amount(case)
    amount = Decimal(amount) if amount is not None else default_amount
    if amount < 0:
        raise ValidationError({"amount": "Montant négatif interdit."})

    bounty = getattr(case, "bounty", None)
    if bounty is None:
        bounty = Bounty(case=case, program=case.program, researcher=case.reporter)
    elif bounty.is_final:
        raise ValidationError("Cette récompense a déjà fait l'objet d'une décision finale.")

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
        raise PermissionDenied("Capacité requise pour participer à la revue.")
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
        raise PermissionDenied("Capacité requise pour approuver une récompense.")
    if bounty.proposed_by_id and approver.pk == bounty.proposed_by_id:
        raise PermissionDenied(
            "Le proposant d'une récompense ne peut pas l'approuver lui-même."
        )
    if not bounty.can_transition_to(BountyStatus.APPROVED):
        raise ValidationError(
            f"Transition interdite depuis l'état {bounty.get_status_display()}."
        )
    amount = Decimal(amount) if amount is not None else bounty.proposed_amount
    if amount < 0:
        raise ValidationError({"amount": "Montant négatif interdit."})

    # Calcule avant enregistrement : la recompense courante ne doit pas encore
    # peser dans la consommation constatee.
    budget = budget_status(bounty, amount)

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

    # Un depassement reste possible - les situations exceptionnelles existent -
    # mais il n'est jamais silencieux : il laisse une trace d'audit dediee.
    warnings = []
    if not bounty.within_policy():
        warnings.append("montant hors matrice du programme")
    if budget and budget["exceeded"]:
        warnings.append(
            f"budget du programme depasse ({budget['projected']} / "
            f"{budget['total']} {budget['currency']})"
        )
    if warnings:
        log_action(
            AuditAction.BOUNTY_APPROVED,
            actor=approver,
            obj=bounty,
            request=request,
            warning="; ".join(warnings),
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
        raise PermissionDenied("Capacité requise pour statuer sur une récompense.")
    if bounty.proposed_by_id and approver.pk == bounty.proposed_by_id:
        raise PermissionDenied(
            "Le proposant d'une récompense ne peut pas la rejeter lui-même."
        )
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
        raise PermissionDenied("Capacité requise pour enregistrer un paiement.")
    if bounty.status != BountyStatus.APPROVED:
        raise ValidationError("Seule une récompense approuvée peut être versée.")

    # Simple copie a titre indicatif du moyen principal declare par le
    # chercheur (voir apps.researchers.PayoutMethod) : jamais une reference
    # forte (pas de ForeignKey) pour ne pas coupler les deux modules ni
    # perdre l'historique si le wallet change ensuite. Meme principe que le
    # depassement de budget plus haut : jamais bloquant, jamais silencieux.
    payout_profile = (
        getattr(bounty.researcher, "payout_profile", None) if bounty.researcher_id else None
    )
    primary_method = (
        payout_profile.methods.filter(is_primary=True, is_active=True).first()
        if payout_profile
        else None
    )
    payout_warnings = []
    if not payout_profile or not payout_profile.is_complete:
        payout_warnings.append("portefeuille du chercheur incomplet")
    if not primary_method:
        payout_warnings.append("aucun moyen de paiement principal declare")

    payment = BountyPayment.objects.create(
        bounty=bounty,
        amount=Decimal(amount) if amount is not None else bounty.approved_amount,
        currency=bounty.currency,
        method=method or BountyPayment._meta.get_field("method").default,
        reference=reference[:120],
        payout_snapshot=primary_method.summary if primary_method else "",
        status=PaymentStatus.RECORDED,
        recorded_by=actor,
    )
    bounty.status = BountyStatus.PAID
    bounty.save(update_fields=["status", "updated_at"])

    if payout_warnings:
        log_action(
            AuditAction.BOUNTY_PAID,
            actor=actor,
            obj=bounty,
            request=request,
            warning="; ".join(payout_warnings),
        )
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
    # Transitoire, non persiste : permet a la vue d'afficher l'avertissement
    # sans recalculer la meme logique.
    payment.payout_warning = "; ".join(payout_warnings)
    return payment


__all__ = [
    "budget_status",
    "propose_bounty",
    "review_bounty",
    "approve_bounty",
    "reject_bounty",
    "record_payment",
    "suggested_amount",
    "ReviewDecision",
]
