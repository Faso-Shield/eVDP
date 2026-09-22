"""Referentiels de vulnerabilites : CWE, CVE et references externes."""

from django.core.validators import RegexValidator
from django.db import models

from apps.core.models import BaseModel, TimeStampedModel

from .constants import ReportSource, Severity, VulnerabilityType  # noqa: F401


class CWE(TimeStampedModel):
    """Common Weakness Enumeration (referentiel local, alimentable hors ligne)."""

    code = models.CharField(
        max_length=16,
        primary_key=True,
        validators=[RegexValidator(r"^CWE-\d+$", "Format attendu: CWE-79")],
    )
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    url = models.URLField(blank=True)

    class Meta:
        db_table = "cwes"
        ordering = ["code"]
        verbose_name = "CWE"
        verbose_name_plural = "CWE"

    def __str__(self):
        return f"{self.code} - {self.name}"

    def save(self, *args, **kwargs):
        self.code = self.code.upper().strip()
        if not self.url:
            self.url = f"https://cwe.mitre.org/data/definitions/{self.code[4:]}.html"
        return super().save(*args, **kwargs)


class CVEState(models.TextChoices):
    REQUESTED = "REQUESTED", "Demandé"
    RESERVED = "RESERVED", "Réservé"
    PUBLISHED = "PUBLISHED", "Publié"
    REJECTED = "REJECTED", "Rejeté"


class CVE(TimeStampedModel):
    """Identifiant CVE suivi par la plateforme."""

    cve_id = models.CharField(
        max_length=24,
        primary_key=True,
        validators=[RegexValidator(r"^CVE-\d{4}-\d{4,10}$", "Format attendu: CVE-2026-1234")],
    )
    state = models.CharField(
        max_length=16, choices=CVEState.choices, default=CVEState.RESERVED
    )
    summary = models.TextField(blank=True)
    published_at = models.DateTimeField(null=True, blank=True)
    cvss_score = models.DecimalField(max_digits=3, decimal_places=1, null=True, blank=True)
    cvss_vector = models.CharField(max_length=120, blank=True)
    url = models.URLField(blank=True)
    # Champs alimentables ulterieurement par une synchronisation NVD/KEV/EPSS.
    in_cisa_kev = models.BooleanField(default=False)
    epss_score = models.DecimalField(max_digits=6, decimal_places=5, null=True, blank=True)
    last_synced_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "cves"
        ordering = ["-cve_id"]
        verbose_name = "CVE"
        verbose_name_plural = "CVE"

    def __str__(self):
        return self.cve_id

    def save(self, *args, **kwargs):
        self.cve_id = self.cve_id.upper().strip()
        if not self.url:
            self.url = f"https://www.cve.org/CVERecord?id={self.cve_id}"
        return super().save(*args, **kwargs)


class ReferenceKind(models.TextChoices):
    ADVISORY = "ADVISORY", "Advisory"
    PATCH = "PATCH", "Correctif"
    EXPLOIT = "EXPLOIT", "Exploit"
    ARTICLE = "ARTICLE", "Article"
    VENDOR = "VENDOR", "Éditeur"
    OTHER = "OTHER", "Autre"


class VulnerabilityReference(BaseModel):
    """Reference externe rattachee a un case ou a un advisory."""

    case = models.ForeignKey(
        "coordination.Case",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="references",
    )
    advisory = models.ForeignKey(
        "disclosures.Advisory",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="references",
    )
    title = models.CharField(max_length=255)
    url = models.URLField(max_length=500)
    kind = models.CharField(
        max_length=16, choices=ReferenceKind.choices, default=ReferenceKind.OTHER
    )
    is_public = models.BooleanField(
        default=False, help_text="Une référence publique peut apparaître dans un advisory."
    )

    class Meta:
        db_table = "vulnerability_references"
        ordering = ["kind", "title"]
        verbose_name = "Reference"
        verbose_name_plural = "References"

    def __str__(self):
        return self.title
