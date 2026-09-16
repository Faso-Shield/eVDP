"""Advisories publics.

Principe 6 : l'advisory est une representation ASSAINIE du case prive. Il est
un objet distinct, alimente explicitement par un analyste ; aucune donnee du
case n'y est copiee automatiquement sans validation humaine.
"""

from django.conf import settings
from django.db import models
from django.urls import reverse
from django.utils import timezone
from django.utils.text import slugify

from apps.core.models import BaseModel
from apps.core.utils import next_sequence
from apps.vulnerabilities.constants import Severity


class AdvisoryStatus(models.TextChoices):
    DRAFT = "DRAFT", "Brouillon"
    IN_REVIEW = "IN_REVIEW", "En relecture"
    APPROVED = "APPROVED", "Approuvé"
    SCHEDULED = "SCHEDULED", "Planifié"
    PUBLISHED = "PUBLISHED", "Publié"
    RETRACTED = "RETRACTED", "Retiré"


ADVISORY_TRANSITIONS = {
    AdvisoryStatus.DRAFT: [AdvisoryStatus.IN_REVIEW],
    AdvisoryStatus.IN_REVIEW: [AdvisoryStatus.APPROVED, AdvisoryStatus.DRAFT],
    AdvisoryStatus.APPROVED: [AdvisoryStatus.SCHEDULED, AdvisoryStatus.PUBLISHED],
    AdvisoryStatus.SCHEDULED: [AdvisoryStatus.PUBLISHED, AdvisoryStatus.APPROVED],
    AdvisoryStatus.PUBLISHED: [AdvisoryStatus.RETRACTED],
    AdvisoryStatus.RETRACTED: [],
}


class AdvisoryQuerySet(models.QuerySet):
    def published(self):
        return self.filter(status=AdvisoryStatus.PUBLISHED, published_at__lte=timezone.now())

    def visible_to(self, user):
        if user and user.is_authenticated and user.is_national:
            return self
        return self.published()


class Advisory(BaseModel):
    advisory_id = models.CharField(max_length=32, unique=True, editable=False, db_index=True)
    slug = models.SlugField(max_length=220, unique=True, blank=True)
    case = models.ForeignKey(
        "coordination.Case",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="advisories",
        help_text="Case privé source. Jamais exposé publiquement.",
    )
    organization = models.ForeignKey(
        "organizations.Organization",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="advisories",
    )
    title = models.CharField(max_length=250)
    summary = models.TextField(help_text="Résumé public. Markdown autorisé.")
    product = models.CharField(max_length=200, blank=True)
    affected_versions = models.CharField(max_length=255, blank=True)
    fixed_versions = models.CharField(max_length=255, blank=True)
    description = models.TextField(blank=True, help_text="Markdown autorisé.")
    impact = models.TextField(blank=True, help_text="Markdown autorisé.")
    solution = models.TextField(blank=True, help_text="Markdown autorisé.")
    workaround = models.TextField(blank=True, help_text="Markdown autorisé.")
    severity = models.CharField(
        max_length=16, choices=Severity.choices, default=Severity.MEDIUM, db_index=True
    )
    cvss_score = models.DecimalField(max_digits=3, decimal_places=1, null=True, blank=True)
    cvss_vector = models.CharField(max_length=120, blank=True)
    cwe = models.ForeignKey(
        "vulnerabilities.CWE",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="advisories",
    )
    cve = models.ForeignKey(
        "vulnerabilities.CVE",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="advisories",
    )
    credit = models.CharField(
        max_length=255,
        blank=True,
        help_text="Crédit affiché publiquement, conforme au choix du chercheur.",
    )
    status = models.CharField(
        max_length=16,
        choices=AdvisoryStatus.choices,
        default=AdvisoryStatus.DRAFT,
        db_index=True,
    )
    scheduled_for = models.DateTimeField(null=True, blank=True)
    published_at = models.DateTimeField(null=True, blank=True)
    retracted_reason = models.TextField(blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="created_advisories",
    )
    published_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="published_advisories",
    )

    objects = AdvisoryQuerySet.as_manager()

    class Meta:
        db_table = "advisories"
        ordering = ["-published_at", "-created_at"]
        verbose_name = "Advisory"
        verbose_name_plural = "Advisories"
        indexes = [models.Index(fields=["status", "-published_at"])]

    def __str__(self):
        return f"{self.advisory_id} - {self.title}"

    def save(self, *args, **kwargs):
        if not self.advisory_id:
            self.advisory_id = next_sequence(
                Advisory, "advisory_id", settings.EVDP["ADVISORY_PREFIX"]
            )
        if not self.slug:
            self.slug = slugify(f"{self.advisory_id}-{self.title}")[:220]
        return super().save(*args, **kwargs)

    def get_absolute_url(self):
        return reverse("disclosures:advisory_detail", args=[self.advisory_id])

    @property
    def is_published(self):
        return (
            self.status == AdvisoryStatus.PUBLISHED
            and self.published_at is not None
            and self.published_at <= timezone.now()
        )

    def can_transition_to(self, status):
        return status in ADVISORY_TRANSITIONS.get(self.status, [])


class AdvisoryTimelineEntry(BaseModel):
    """Chronologie publique : recopiee explicitement, jamais generee du case."""

    advisory = models.ForeignKey(Advisory, on_delete=models.CASCADE, related_name="timeline")
    happened_on = models.DateField()
    label = models.CharField(max_length=255)
    position = models.PositiveSmallIntegerField(default=0)

    class Meta:
        db_table = "advisory_timeline_entries"
        ordering = ["happened_on", "position"]
        verbose_name = "Étape de chronologie"
        verbose_name_plural = "Chronologie publique"

    def __str__(self):
        return f"{self.happened_on:%d/%m/%Y} - {self.label}"


class AdvisoryReference(BaseModel):
    advisory = models.ForeignKey(
        Advisory, on_delete=models.CASCADE, related_name="external_references"
    )
    title = models.CharField(max_length=255)
    url = models.URLField(max_length=500)

    class Meta:
        db_table = "advisory_references"
        ordering = ["title"]
        verbose_name = "Référence d'advisory"
        verbose_name_plural = "Références d'advisory"

    def __str__(self):
        return self.title
