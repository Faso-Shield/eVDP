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
        """Nom affichable selon le mode d'identité choisi par le chercheur."""
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
