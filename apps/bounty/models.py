"""Recompenses Bug Bounty.

Aucun paiement reel n'est execute par le MVP : le module trace la proposition,
la revue, l'approbation et l'enregistrement comptable du versement. Une
integration avec un prestataire de paiement viendra s'y brancher plus tard
(voir BountyPayment.method et docs/bug-bounty.md).
"""

from decimal import Decimal

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import MinValueValidator
from django.db import models
from django.utils import timezone

from apps.core.models import BaseModel
from apps.vulnerabilities.constants import Severity


class BountyStatus(models.TextChoices):
    PENDING = "PENDING", "Proposée"
    UNDER_REVIEW = "UNDER_REVIEW", "En revue"
    APPROVED = "APPROVED", "Approuvée"
    REJECTED = "REJECTED", "Rejetée"
    PAID = "PAID", "Payée"
    CANCELLED = "CANCELLED", "Annulée"


#: Transitions autorisees du cycle de vie d'une recompense.
BOUNTY_TRANSITIONS = {
    BountyStatus.PENDING: [
        BountyStatus.UNDER_REVIEW,
        BountyStatus.APPROVED,
        BountyStatus.REJECTED,
        BountyStatus.CANCELLED,
    ],
    BountyStatus.UNDER_REVIEW: [
        BountyStatus.APPROVED,
        BountyStatus.REJECTED,
        BountyStatus.CANCELLED,
    ],
    BountyStatus.APPROVED: [BountyStatus.PAID, BountyStatus.CANCELLED],
    BountyStatus.REJECTED: [],
    BountyStatus.PAID: [],
    BountyStatus.CANCELLED: [],
}


class Bounty(BaseModel):
    case = models.OneToOneField(
        "coordination.Case", on_delete=models.CASCADE, related_name="bounty"
    )
    program = models.ForeignKey(
        "programs.Program",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="bounties",
    )
    researcher = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="bounties",
    )
    severity = models.CharField(
        max_length=16, choices=Severity.choices, default=Severity.MEDIUM
    )
    proposed_amount = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        default=Decimal("0"),
        validators=[MinValueValidator(Decimal("0"))],
    )
    approved_amount = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        null=True,
        blank=True,
        validators=[MinValueValidator(Decimal("0"))],
    )
    currency = models.CharField(max_length=8, default="XOF")
    status = models.CharField(
        max_length=16,
        choices=BountyStatus.choices,
        default=BountyStatus.PENDING,
        db_index=True,
    )
    justification = models.TextField(blank=True, help_text="Markdown autorisé.")
    proposed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="proposed_bounties",
    )
    decided_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="decided_bounties",
    )
    decided_at = models.DateTimeField(null=True, blank=True)
    decision_note = models.TextField(blank=True)

    class Meta:
        db_table = "bounties"
        ordering = ["-created_at"]
        verbose_name = "Récompense"
        verbose_name_plural = "Récompenses"

    def __str__(self):
        return f"{self.case.case_id} - {self.display_amount}"

    def clean(self):
        if self.approved_amount is not None and self.approved_amount < 0:
            raise ValidationError({"approved_amount": "Montant négatif interdit."})

    @property
    def display_amount(self):
        amount = (
            self.approved_amount if self.approved_amount is not None else self.proposed_amount
        )
        return f"{amount:,.0f} {self.currency}".replace(",", " ")

    @property
    def is_final(self):
        return self.status in (
            BountyStatus.PAID,
            BountyStatus.REJECTED,
            BountyStatus.CANCELLED,
        )

    def can_transition_to(self, status):
        return status in BOUNTY_TRANSITIONS.get(self.status, [])

    def within_policy(self):
        """Verifie que le montant approuve respecte la matrice du programme."""
        policy = getattr(self.program, "reward_policy", None) if self.program else None
        if not policy:
            return True
        tier = policy.tier_for(self.severity)
        amount = (
            self.approved_amount if self.approved_amount is not None else self.proposed_amount
        )
        return tier.contains(amount) if tier else True


class ReviewDecision(models.TextChoices):
    APPROVE = "APPROVE", "Favorable"
    REJECT = "REJECT", "Défavorable"
    ADJUST = "ADJUST", "Ajustement proposé"
    COMMENT = "COMMENT", "Commentaire"


class BountyReview(BaseModel):
    bounty = models.ForeignKey(Bounty, on_delete=models.CASCADE, related_name="reviews")
    reviewer = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="bounty_reviews",
    )
    decision = models.CharField(max_length=16, choices=ReviewDecision.choices)
    suggested_amount = models.DecimalField(
        max_digits=12, decimal_places=2, null=True, blank=True
    )
    comment = models.TextField(blank=True)

    class Meta:
        db_table = "bounty_reviews"
        ordering = ["-created_at"]
        verbose_name = "Revue de récompense"
        verbose_name_plural = "Revues de récompense"

    def __str__(self):
        return f"{self.bounty} - {self.decision}"


class PaymentMethod(models.TextChoices):
    BANK_TRANSFER = "BANK_TRANSFER", "Virement bancaire"
    MOBILE_MONEY = "MOBILE_MONEY", "Mobile money"
    OTHER = "OTHER", "Autre"


class PaymentStatus(models.TextChoices):
    RECORDED = "RECORDED", "Enregistré"
    SETTLED = "SETTLED", "Versé"
    FAILED = "FAILED", "Échec"


class BountyPayment(BaseModel):
    """Trace comptable d'un versement. Aucun flux financier n'est declenche."""

    bounty = models.ForeignKey(Bounty, on_delete=models.CASCADE, related_name="payments")
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    currency = models.CharField(max_length=8, default="XOF")
    method = models.CharField(
        max_length=24, choices=PaymentMethod.choices, default=PaymentMethod.BANK_TRANSFER
    )
    status = models.CharField(
        max_length=16, choices=PaymentStatus.choices, default=PaymentStatus.RECORDED
    )
    reference = models.CharField(
        max_length=120, blank=True, help_text="Référence comptable externe."
    )
    settled_at = models.DateTimeField(null=True, blank=True)
    recorded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="recorded_payments",
    )
    note = models.CharField(max_length=255, blank=True)

    class Meta:
        db_table = "bounty_payments"
        ordering = ["-created_at"]
        verbose_name = "Paiement de récompense"
        verbose_name_plural = "Paiements de récompense"

    def __str__(self):
        return f"{self.amount} {self.currency} ({self.status})"

    def mark_settled(self):
        self.status = PaymentStatus.SETTLED
        self.settled_at = timezone.now()
        self.save(update_fields=["status", "settled_at", "updated_at"])
