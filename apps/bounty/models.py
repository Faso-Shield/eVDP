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
    PAYMENT_PENDING = "PAYMENT_PENDING", "Versement en attente de confirmation"
    PAID = "PAID", "Payée"
    CANCELLED = "CANCELLED", "Annulée"


#: Transitions autorisees du cycle de vie d'une recompense.
#
# PAYMENT_PENDING est deliberement distinct de PAID : un versement enregistre
# (bounty.services.record_payment) n'est qu'une intention, jamais confirmee
# tant qu'aucune preuve n'a ete televersee (bounty.services.confirm_settlement).
# Afficher "Payee" des l'enregistrement serait un statut positif non merite -
# voir le retour utilisateur qui a motive cette distinction. Un versement en
# echec (mark_payment_failed) fait revenir la recompense a APPROVED : un
# nouveau versement peut alors etre enregistre.
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
    BountyStatus.APPROVED: [BountyStatus.PAYMENT_PENDING, BountyStatus.CANCELLED],
    BountyStatus.PAYMENT_PENDING: [
        BountyStatus.PAID,
        BountyStatus.APPROVED,
        BountyStatus.CANCELLED,
    ],
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
        verbose_name = "Recompense"
        verbose_name_plural = "Recompenses"

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
        verbose_name = "Revue de recompense"
        verbose_name_plural = "Revues de recompense"

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


def payment_proof_upload_path(instance, filename):
    """Chemin de stockage opaque : aucune donnee utilisateur dans le chemin.

    Le nom d'origine (`filename`) est ignore : seul `proof_storage_name`,
    genere par le service au moment du televersement, determine le chemin.
    Meme principe que apps.researchers.models.payout_document_upload_path.
    """
    return f"bounty_payment_proofs/{instance.created_at:%Y/%m}/{instance.proof_storage_name}"


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
    payout_snapshot = models.CharField(
        max_length=255,
        blank=True,
        help_text=(
            "Resume masque du moyen de paiement principal declare par le "
            "chercheur au moment du versement (voir apps.researchers.PayoutMethod). "
            "Copie a titre indicatif, jamais une reference forte : le wallet "
            "peut changer ou etre desactive apres coup sans alterer cet historique."
        ),
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

    # -- Reglement : confirmation qu'un virement reel a eu lieu -------------
    # La comptabilite agit hors plateforme et notifie l'agent par email avec
    # une preuve ; cette preuve est televersee ici au moment de la
    # confirmation. Memes principes de securite que le justificatif
    # d'identite du portefeuille : nom de stockage opaque, jamais servi
    # directement (voir apps.bounty.views.payment_proof_download).
    proof_file = models.FileField(
        upload_to=payment_proof_upload_path, max_length=300, blank=True
    )
    proof_storage_name = models.CharField(max_length=80, blank=True, editable=False)
    proof_original_filename = models.CharField(max_length=255, blank=True)
    proof_content_type = models.CharField(max_length=120, blank=True)
    proof_size = models.PositiveBigIntegerField(default=0, editable=False)
    proof_sha256 = models.CharField(max_length=64, blank=True, editable=False)
    proof_uploaded_at = models.DateTimeField(null=True, blank=True)
    failure_reason = models.TextField(blank=True)

    class Meta:
        db_table = "bounty_payments"
        ordering = ["-created_at"]
        verbose_name = "Paiement de recompense"
        verbose_name_plural = "Paiements de recompense"

    def __str__(self):
        return f"{self.amount} {self.currency} ({self.status})"

    def mark_settled(self):
        self.status = PaymentStatus.SETTLED
        self.settled_at = timezone.now()
        self.save(update_fields=["status", "settled_at", "updated_at"])

    def mark_failed(self, reason):
        self.status = PaymentStatus.FAILED
        self.failure_reason = reason
        self.save(update_fields=["status", "failure_reason", "updated_at"])

class WalletEntryKind(models.TextChoices):
    CREDIT = "CREDIT", "Crédit (prime approuvée)"
    ADJUSTMENT = "ADJUSTMENT", "Ajustement"
    PAYOUT = "PAYOUT", "Versement hors plateforme"


class WalletEntryQuerySet(models.QuerySet):
    def update(self, **kwargs):  # pragma: no cover - garde-fou
        raise NotImplementedError("Le grand livre du Wallet est append-only.")

    def delete(self):  # pragma: no cover - garde-fou
        raise NotImplementedError("Le grand livre du Wallet est append-only.")


class WalletEntry(BaseModel):
    """Ecriture du grand livre du Wallet d'un chercheur.

    Le solde n'est jamais stocke ni modifiable : il se calcule en sommant les
    ecritures (voir bounty.services.wallet_balance). Une erreur se corrige par
    une ecriture d'ajustement, jamais en modifiant une ecriture existante.
    Aucun flux financier reel n'est declenche : le versement effectif reste
    hors plateforme (MVP).
    """

    researcher = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="wallet_entries",
    )
    bounty = models.ForeignKey(
        Bounty,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="wallet_entries",
    )
    kind = models.CharField(max_length=16, choices=WalletEntryKind.choices)
    amount = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        help_text="Montant signé : positif au crédit, négatif au débit.",
    )
    currency = models.CharField(max_length=8, default="XOF")
    label = models.CharField(max_length=255, blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="wallet_entries_recorded",
    )

    objects = WalletEntryQuerySet.as_manager()

    class Meta:
        db_table = "wallet_entries"
        ordering = ["-created_at"]
        verbose_name = "Écriture de Wallet"
        verbose_name_plural = "Grand livre du Wallet"

    def __str__(self):
        return f"{self.get_kind_display()} {self.amount} {self.currency}"

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ValidationError("Une écriture de Wallet ne se modifie pas.")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError("Une écriture de Wallet ne se supprime pas.")
