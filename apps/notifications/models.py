"""Notifications internes et modeles d'email.

Regle : aucun contenu sensible dans un email. Le corps se limite a annoncer
qu'une action est disponible dans l'espace eVDP authentifie.
"""

from django.conf import settings
from django.db import models
from django.utils import timezone

from apps.core.models import BaseModel, TimeStampedModel


class NotificationKind(models.TextChoices):
    REPORT_RECEIVED = "REPORT_RECEIVED", "Nouveau rapport"
    ACKNOWLEDGEMENT = "ACKNOWLEDGEMENT", "Accusé de réception"
    INFORMATION_REQUESTED = "INFORMATION_REQUESTED", "Demande d'informations"
    STATUS_CHANGED = "STATUS_CHANGED", "Changement de statut"
    NEW_MESSAGE = "NEW_MESSAGE", "Nouveau message"
    NEW_ATTACHMENT = "NEW_ATTACHMENT", "Nouvelle pièce jointe"
    CASE_ASSIGNED = "CASE_ASSIGNED", "Case assigné"
    VALIDATED = "VALIDATED", "Rapport validé"
    REJECTED = "REJECTED", "Rapport rejeté"
    DUPLICATE = "DUPLICATE", "Rapport en doublon"
    SLA_APPROACHING = "SLA_APPROACHING", "Échéance SLA proche"
    SLA_BREACHED = "SLA_BREACHED", "SLA dépassé"
    DISCLOSURE_UPCOMING = "DISCLOSURE_UPCOMING", "Divulgation imminente"
    ADVISORY_PUBLISHED = "ADVISORY_PUBLISHED", "Advisory publié"
    BOUNTY_PROPOSED = "BOUNTY_PROPOSED", "Récompense proposée"
    BOUNTY_APPROVED = "BOUNTY_APPROVED", "Récompense approuvée"
    BOUNTY_REJECTED = "BOUNTY_REJECTED", "Récompense rejetée"
    BOUNTY_PAID = "BOUNTY_PAID", "Récompense payée"
    ACCOUNT = "ACCOUNT", "Compte"


class Notification(BaseModel):
    recipient = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="notifications"
    )
    kind = models.CharField(max_length=32, choices=NotificationKind.choices)
    title = models.CharField(max_length=200)
    body = models.CharField(
        max_length=400,
        blank=True,
        help_text="Message court et non sensible.",
    )
    url = models.CharField(max_length=300, blank=True)
    case = models.ForeignKey(
        "coordination.Case",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="notifications",
    )
    read_at = models.DateTimeField(null=True, blank=True)
    emailed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "notifications"
        ordering = ["-created_at"]
        verbose_name = "Notification"
        verbose_name_plural = "Notifications"
        indexes = [models.Index(fields=["recipient", "read_at"])]

    def __str__(self):
        return f"{self.recipient} - {self.title}"

    def mark_read(self):
        if self.read_at is None:
            self.read_at = timezone.now()
            self.save(update_fields=["read_at", "updated_at"])


class EmailTemplate(TimeStampedModel):
    """Surcharge editable des modeles d'email par l'administration."""

    code = models.CharField(max_length=48, unique=True, choices=NotificationKind.choices)
    subject = models.CharField(max_length=200)
    body = models.TextField(
        help_text="Variables disponibles : {case_id}, {title}, {status}, {link}."
    )
    is_active = models.BooleanField(default=True)

    class Meta:
        db_table = "email_templates"
        ordering = ["code"]
        verbose_name = "Modele d'email"
        verbose_name_plural = "Modeles d'email"

    def __str__(self):
        return self.code
