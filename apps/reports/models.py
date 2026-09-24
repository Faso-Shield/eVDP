"""Rapport de vulnerabilite tel que soumis par le declarant.

Le rapport est la matiere brute : il n'est jamais modifie par les analystes.
Le traitement se fait sur le Case associe (apps.coordination), qui porte le
workflow, la severite retenue et la coordination multipartite.

Principe 2 : un rapport est PRIVE par defaut et ne devient jamais public
automatiquement.
"""

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models

from apps.core.models import BaseModel
from apps.core.pgp import is_encrypted_blob
from apps.vulnerabilities.constants import (
    ReportSource,
    Severity,
    VulnerabilityType,
)


class ReportStatus(models.TextChoices):
    DRAFT = "DRAFT", "Brouillon"
    SUBMITTED = "SUBMITTED", "Soumis"


class VulnerabilityReport(BaseModel):
    """Contenu declaratif d'un signalement."""

    # --- Identification -----------------------------------------------------
    title = models.CharField(max_length=200)
    product = models.CharField(
        max_length=200, blank=True, help_text="Produit, service ou application affecté."
    )
    affected_organization = models.ForeignKey(
        "organizations.Organization",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="reports",
    )
    affected_organization_name = models.CharField(
        max_length=200,
        blank=True,
        help_text="Nom saisi librement si l'organisation n'est pas encore référencée.",
    )
    program = models.ForeignKey(
        "programs.Program",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="reports",
    )
    target_url = models.CharField(max_length=500, blank=True)

    # --- Qualification technique -------------------------------------------
    vulnerability_type = models.CharField(
        max_length=24, choices=VulnerabilityType.choices, default=VulnerabilityType.OTHER
    )
    cwe = models.ForeignKey(
        "vulnerabilities.CWE",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="reports",
    )
    cvss_vector = models.CharField(max_length=255, blank=True)
    cvss_score = models.DecimalField(max_digits=3, decimal_places=1, null=True, blank=True)
    reported_severity = models.CharField(
        max_length=16,
        choices=Severity.choices,
        default=Severity.MEDIUM,
        help_text="Sévérité estimée par le déclarant (revue lors du triage).",
    )

    # --- Contenu (Markdown) -------------------------------------------------
    description = models.TextField(help_text="Markdown autorisé.")
    steps_to_reproduce = models.TextField(blank=True, help_text="Markdown autorisé.")
    impact = models.TextField(blank=True, help_text="Markdown autorisé.")
    proof_of_concept = models.TextField(blank=True, help_text="Markdown autorisé.")
    recommendations = models.TextField(blank=True, help_text="Markdown autorisé.")
    affected_version = models.CharField(max_length=120, blank=True)
    fixed_version = models.CharField(max_length=120, blank=True)
    environment = models.CharField(max_length=180, blank=True)
    external_reference = models.CharField(max_length=500, blank=True)

    # --- Declarant ----------------------------------------------------------
    reporter = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="submitted_reports",
    )
    reporter_email = models.EmailField(
        blank=True, help_text="Utilisé pour les signalements anonymes."
    )
    reporter_name = models.CharField(max_length=150, blank=True)
    is_anonymous = models.BooleanField(default=False)
    wants_credit = models.BooleanField(
        default=True, help_text="Souhaite être crédité dans l'advisory public."
    )
    requests_cve = models.BooleanField(default=False)
    accepted_policy = models.BooleanField(default=False)

    # --- Confidentialite ----------------------------------------------------
    is_pgp_encrypted = models.BooleanField(default=False)
    pgp_payload = models.TextField(
        blank=True,
        help_text="Bloc PGP chiffré. eVDP ne détient aucune clé privée : "
        "le déchiffrement est effectué hors ligne par l'équipe destinataire.",
    )

    # --- Metadonnees --------------------------------------------------------
    status = models.CharField(
        max_length=16, choices=ReportStatus.choices, default=ReportStatus.SUBMITTED
    )
    source = models.CharField(
        max_length=16, choices=ReportSource.choices, default=ReportSource.WEB
    )
    submitted_at = models.DateTimeField(null=True, blank=True)
    submitter_ip_hash = models.CharField(
        max_length=64,
        blank=True,
        help_text="Empreinte de l'IP (anti-abus) - l'IP brute n'est pas conservée.",
    )

    class Meta:
        db_table = "vulnerability_reports"
        ordering = ["-created_at"]
        verbose_name = "Rapport de vulnerabilite"
        verbose_name_plural = "Rapports de vulnerabilite"
        indexes = [
            models.Index(fields=["-created_at"]),
            models.Index(fields=["vulnerability_type"]),
        ]

    def __str__(self):
        return self.title

    def clean(self):
        if not self.reporter and not self.reporter_email and not self.is_anonymous:
            raise ValidationError(
                "Un rapport doit être rattaché à un compte, à une adresse de "
                "contact, ou être explicitement anonyme."
            )
        if self.pgp_payload and not is_encrypted_blob(self.pgp_payload):
            raise ValidationError(
                {"pgp_payload": "Le bloc fourni n'est pas un message PGP chiffré."}
            )

    def save(self, *args, **kwargs):
        self.is_pgp_encrypted = bool(self.pgp_payload)
        if self.affected_organization and not self.affected_organization_name:
            self.affected_organization_name = self.affected_organization.name
        return super().save(*args, **kwargs)

    @property
    def reporter_display(self):
        if self.is_anonymous:
            return "Declarant anonyme"
        if self.reporter:
            return self.reporter.public_identity()
        return self.reporter_name or self.reporter_email or "Declarant externe"

    @property
    def notification_email(self):
        if self.reporter:
            return self.reporter.email
        return self.reporter_email or ""
