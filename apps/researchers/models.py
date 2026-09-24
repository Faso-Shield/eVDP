"""Profils chercheurs et systeme de reputation."""

from django.conf import settings
from django.db import models
from django.utils.text import slugify

from apps.core.models import BaseModel


class IdentityMode(models.TextChoices):
    PUBLIC = "PUBLIC", "Identité publique"
    PSEUDONYM = "PSEUDONYM", "Pseudonyme"
    PRIVATE = "PRIVATE", "Anonyme"


class ResearcherProfile(BaseModel):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="researcher_profile",
    )
    pseudonym = models.CharField(max_length=60, blank=True, db_index=True)
    slug = models.SlugField(max_length=80, unique=True, blank=True)
    country = models.CharField(max_length=80, default="Burkina Faso")
    biography = models.TextField(blank=True, help_text="Markdown autorisé.")
    affiliation = models.CharField(
        max_length=180, blank=True, help_text="Organisation ou université de rattachement."
    )
    website = models.URLField(blank=True)
    identity_mode = models.CharField(
        max_length=16, choices=IdentityMode.choices, default=IdentityMode.PSEUDONYM
    )
    is_public_profile = models.BooleanField(
        default=False, help_text="Apparaît dans l'annuaire public des chercheurs."
    )

    # Compteurs denormalises, recalculables via recompute().
    reputation = models.IntegerField(default=0, editable=False)
    reports_submitted = models.PositiveIntegerField(default=0, editable=False)
    reports_validated = models.PositiveIntegerField(default=0, editable=False)
    critical_reports = models.PositiveIntegerField(default=0, editable=False)
    total_rewards = models.DecimalField(
        max_digits=14, decimal_places=2, default=0, editable=False
    )

    class Meta:
        db_table = "researcher_profiles"
        ordering = ["-reputation", "pseudonym"]
        verbose_name = "Profil chercheur"
        verbose_name_plural = "Profils chercheurs"

    def __str__(self):
        return self.public_identity()

    def save(self, *args, **kwargs):
        if not self.slug:
            base = slugify(self.pseudonym or self.user.display_name or "chercheur")[:60]
            slug, index = base or "chercheur", 1
            while ResearcherProfile.objects.filter(slug=slug).exclude(pk=self.pk).exists():
                index += 1
                slug = f"{base}-{index}"
            self.slug = slug
        return super().save(*args, **kwargs)

    def public_identity(self):
        """Nom affichable selon le mode d'identite choisi par le chercheur."""
        if self.identity_mode == IdentityMode.PUBLIC:
            return self.user.full_name or self.user.display_name or self.user.email
        if self.identity_mode == IdentityMode.PSEUDONYM:
            return self.pseudonym or self.user.display_name or "Chercheur"
        return "Chercheur anonyme"

    @property
    def validation_rate(self):
        if not self.reports_submitted:
            return 0
        return round(self.reports_validated * 100 / self.reports_submitted, 1)

    def recompute(self):
        """Recalcule les compteurs a partir des donnees sources."""
        from apps.bounty.models import Bounty, BountyStatus
        from apps.coordination.models import Case, CaseStatus, Severity

        cases = Case.objects.filter(reporter=self.user)
        validated_states = CaseStatus.validated_states()
        self.reports_submitted = cases.count()
        self.reports_validated = cases.filter(status__in=validated_states).count()
        self.critical_reports = cases.filter(
            severity=Severity.CRITICAL, status__in=validated_states
        ).count()
        paid = Bounty.objects.filter(researcher=self.user, status=BountyStatus.PAID).aggregate(
            total=models.Sum("approved_amount")
        )["total"]
        self.total_rewards = paid or 0
        self.reputation = (
            self.reputation_events.aggregate(total=models.Sum("points"))["total"] or 0
        )
        self.save(
            update_fields=[
                "reports_submitted",
                "reports_validated",
                "critical_reports",
                "total_rewards",
                "reputation",
                "updated_at",
            ]
        )
        return self


class ReputationReason(models.TextChoices):
    VALIDATED = "VALIDATED", "Rapport validé"
    HIGH = "HIGH", "Vulnérabilité High"
    CRITICAL = "CRITICAL", "Vulnérabilité Critical"
    DUPLICATE = "DUPLICATE", "Rapport en doublon"
    ABUSIVE = "ABUSIVE", "Rapport abusif"
    MANUAL = "MANUAL", "Ajustement manuel"


class ReputationEvent(BaseModel):
    """Historique de reputation : le chercheur ne peut jamais l'editer."""

    profile = models.ForeignKey(
        ResearcherProfile, on_delete=models.CASCADE, related_name="reputation_events"
    )
    reason = models.CharField(max_length=24, choices=ReputationReason.choices)
    points = models.IntegerField()
    case = models.ForeignKey(
        "coordination.Case",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="reputation_events",
    )
    note = models.CharField(max_length=255, blank=True)
    granted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="granted_reputation_events",
    )

    class Meta:
        db_table = "reputation_events"
        ordering = ["-created_at"]
        verbose_name = "Evenement de reputation"
        verbose_name_plural = "Evenements de reputation"

    def __str__(self):
        return f"{self.profile} {self.points:+d} ({self.reason})"


# ---------------------------------------------------------------------------
# Portefeuille de versement
# ---------------------------------------------------------------------------
# Distinct de ResearcherProfile (identite PUBLIQUE, choisie par le chercheur) :
# ces donnees ne sont jamais publiees ni partagees, uniquement utilisees en
# interne pour executer un virement (voir apps.bounty.services.record_payment
# et docs/bug-bounty.md). Elles sont strictement en libre-service : seul le
# titulaire du compte peut les consulter ou les modifier.


class IdDocumentType(models.TextChoices):
    CNIB = "CNIB", "Carte Nationale d'Identite Burkinabe (CNIB)"
    PASSPORT = "PASSPORT", "Passeport"
    OTHER = "OTHER", "Autre piece d'identite"


def payout_document_upload_path(instance, filename):
    """Chemin de stockage opaque : aucune donnee utilisateur dans le chemin.

    Le nom d'origine (`filename`) est ignore : seul `id_document_storage_name`,
    genere par le service au moment du televersement, determine le chemin.
    """
    return f"payout_documents/{instance.created_at:%Y/%m}/{instance.id_document_storage_name}"


class PayoutProfile(BaseModel):
    """Informations personnelles necessaires au versement d'une recompense."""

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="payout_profile",
    )
    legal_full_name = models.CharField(
        max_length=150,
        blank=True,
        help_text="Nom complet tel qu'il figure sur votre piece d'identite.",
    )
    id_document_type = models.CharField(
        max_length=16, choices=IdDocumentType.choices, blank=True
    )
    id_document_number = models.CharField(max_length=60, blank=True)
    contact_phone = models.CharField(
        max_length=32,
        blank=True,
        help_text="Numero utilisable pour vous joindre au sujet d'un versement.",
    )
    address = models.TextField(blank=True)
    country = models.CharField(max_length=80, default="Burkina Faso")
    accepted_terms = models.BooleanField(
        default=False,
        help_text="Le chercheur atteste l'exactitude des informations fournies.",
    )

    # -- Justificatif d'identite -------------------------------------------
    # Stocke sous nom opaque, jamais servi directement (voir
    # apps.researchers.views.id_document_download) : memes principes que les
    # pieces jointes de dossier (apps.attachments), perimetre de formats
    # volontairement plus etroit (voir apps.researchers.services).
    id_document_file = models.FileField(
        upload_to=payout_document_upload_path, max_length=300, blank=True
    )
    id_document_storage_name = models.CharField(max_length=80, blank=True, editable=False)
    id_document_original_filename = models.CharField(max_length=255, blank=True)
    id_document_content_type = models.CharField(max_length=120, blank=True)
    id_document_size = models.PositiveBigIntegerField(default=0, editable=False)
    id_document_sha256 = models.CharField(max_length=64, blank=True, editable=False)
    id_document_uploaded_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "payout_profiles"
        verbose_name = "Profil de versement"
        verbose_name_plural = "Profils de versement"

    def __str__(self):
        return f"Profil de versement - {self.user}"

    @property
    def is_complete(self):
        """Conditionne l'affichage d'un moyen de paiement comme utilisable."""
        return bool(
            self.legal_full_name.strip()
            and self.contact_phone.strip()
            and self.accepted_terms
            and self.id_document_file
        )


class PayoutMethodType(models.TextChoices):
    BANK_TRANSFER = "BANK_TRANSFER", "Virement bancaire"
    MOBILE_MONEY = "MOBILE_MONEY", "Mobile money"
    CRYPTO = "CRYPTO", "Cryptomonnaie"
    PAYPAL = "PAYPAL", "PayPal"
    OTHER = "OTHER", "Autre"


class MobileMoneyOperator(models.TextChoices):
    ORANGE_MONEY = "ORANGE_MONEY", "Orange Money"
    MOOV_MONEY = "MOOV_MONEY", "Moov Money"
    TELECEL_MONEY = "TELECEL_MONEY", "Telecel Money"
    OTHER = "OTHER", "Autre operateur"


class PayoutMethod(BaseModel):
    """Moyen de paiement declare par le chercheur pour recevoir une recompense.

    Plusieurs moyens peuvent coexister ; un seul est marque principal a la
    fois (voir save()). La suppression depuis l'interface desactive
    (is_active=False) plutot que supprimer : la trace reste disponible pour
    l'audit et aucune reference existante n'est cassee.
    """

    profile = models.ForeignKey(
        PayoutProfile, on_delete=models.CASCADE, related_name="methods"
    )
    method_type = models.CharField(max_length=16, choices=PayoutMethodType.choices)
    label = models.CharField(
        max_length=80, blank=True, help_text="Nom libre pour vous y retrouver."
    )
    is_primary = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)

    # -- Virement bancaire ----------------------------------------------------
    bank_name = models.CharField(max_length=150, blank=True)
    account_holder_name = models.CharField(max_length=150, blank=True)
    account_number = models.CharField(
        max_length=64, blank=True, help_text="IBAN ou numero de compte."
    )

    # -- Mobile money -----------------------------------------------------------
    mobile_operator = models.CharField(
        max_length=16, choices=MobileMoneyOperator.choices, blank=True
    )
    mobile_number = models.CharField(max_length=32, blank=True)
    mobile_holder_name = models.CharField(max_length=150, blank=True)

    # -- Cryptomonnaie ------------------------------------------------------
    crypto_currency = models.CharField(max_length=16, blank=True, help_text="BTC, ETH, USDT…")
    crypto_network = models.CharField(
        max_length=60,
        blank=True,
        help_text="Reseau/chaine (ex. Bitcoin, Ethereum ERC-20, Tron TRC-20). "
        "Un envoi sur le mauvais reseau est irrecuperable.",
    )
    crypto_wallet_address = models.CharField(max_length=128, blank=True)

    # -- PayPal ---------------------------------------------------------------
    paypal_email = models.EmailField(blank=True)

    # -- Autre ------------------------------------------------------------------
    other_label = models.CharField(max_length=120, blank=True)
    other_reference = models.CharField(max_length=120, blank=True)

    class Meta:
        db_table = "payout_methods"
        ordering = ["-is_primary", "-created_at"]
        verbose_name = "Moyen de paiement"
        verbose_name_plural = "Moyens de paiement"

    def __str__(self):
        return f"{self.get_method_type_display()} - {self.masked_identifier}"

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        if self.is_primary:
            PayoutMethod.objects.filter(profile_id=self.profile_id).exclude(pk=self.pk).update(
                is_primary=False
            )

    @property
    def masked_identifier(self):
        """Identifiant partiellement masque, pour l'affichage dans les listes."""
        from apps.core.utils import mask_value

        if self.method_type == PayoutMethodType.BANK_TRANSFER:
            return mask_value(self.account_number)
        if self.method_type == PayoutMethodType.MOBILE_MONEY:
            return mask_value(self.mobile_number)
        if self.method_type == PayoutMethodType.CRYPTO:
            return mask_value(self.crypto_wallet_address)
        if self.method_type == PayoutMethodType.PAYPAL:
            return mask_value(self.paypal_email)
        return self.other_reference or "—"

    @property
    def summary(self):
        """Libelle complet mais masque, utilise dans les listes."""
        if self.method_type == PayoutMethodType.BANK_TRANSFER:
            return f"{self.bank_name or 'Banque'} — {self.masked_identifier}"
        if self.method_type == PayoutMethodType.MOBILE_MONEY:
            operator = self.get_mobile_operator_display() if self.mobile_operator else "Mobile"
            return f"{operator} — {self.masked_identifier}"
        if self.method_type == PayoutMethodType.CRYPTO:
            currency = self.crypto_currency or "Crypto"
            if self.crypto_network:
                return f"{currency} ({self.crypto_network}) — {self.masked_identifier}"
            return f"{currency} — {self.masked_identifier}"
        if self.method_type == PayoutMethodType.PAYPAL:
            return f"PayPal — {self.masked_identifier}"
        return self.other_label or "Autre moyen"

    @property
    def full_identifier(self):
        """Identifiant en clair, jamais masque.

        Contrairement a `masked_identifier`, ne jamais afficher directement :
        reserve aux parcours explicitement restreints au super-administrateur
        (voir apps.coordination.views.case_detail), toujours journalises.
        """
        if self.method_type == PayoutMethodType.BANK_TRANSFER:
            return self.account_number
        if self.method_type == PayoutMethodType.MOBILE_MONEY:
            return self.mobile_number
        if self.method_type == PayoutMethodType.CRYPTO:
            return self.crypto_wallet_address
        if self.method_type == PayoutMethodType.PAYPAL:
            return self.paypal_email
        return self.other_reference or "—"

    @property
    def full_summary(self):
        """Libelle complet en clair. Memes reserves que `full_identifier`."""
        if self.method_type == PayoutMethodType.BANK_TRANSFER:
            holder = self.account_holder_name or "—"
            return f"{self.bank_name or 'Banque'} — {self.full_identifier} ({holder})"
        if self.method_type == PayoutMethodType.MOBILE_MONEY:
            operator = self.get_mobile_operator_display() if self.mobile_operator else "Mobile"
            holder = self.mobile_holder_name or "—"
            return f"{operator} — {self.full_identifier} ({holder})"
        if self.method_type == PayoutMethodType.CRYPTO:
            currency = self.crypto_currency or "Crypto"
            if self.crypto_network:
                return f"{currency} ({self.crypto_network}) — {self.full_identifier}"
            return f"{currency} — {self.full_identifier}"
        if self.method_type == PayoutMethodType.PAYPAL:
            return f"PayPal — {self.full_identifier}"
        return f"{self.other_label or 'Autre moyen'} — {self.full_identifier}"
