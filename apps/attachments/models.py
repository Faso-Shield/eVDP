"""Pieces jointes (preuves de concept) - donnees les plus sensibles de eVDP.

Regles appliquees :
  - le nom de fichier fourni par l'utilisateur n'est JAMAIS utilise comme
    chemin serveur (nom aleatoire opaque) ;
  - aucun acces direct : le telechargement passe par une vue qui verifie les
    droits sur le case et journalise l'acces ;
  - taille, extension et type MIME sont valides avant enregistrement ;
  - une empreinte SHA-256 est conservee pour l'integrite et la detection de
    doublons ;
  - un statut d'analyse antivirus est prevu (service ClamAV optionnel).
"""

import uuid

from django.conf import settings
from django.db import models

from apps.core.models import BaseModel


def attachment_upload_path(instance, filename):
    """Chemin de stockage opaque : aucune donnee utilisateur dans le chemin."""
    return f"attachments/{instance.created_at:%Y/%m}/{instance.storage_name}"


class ScanStatus(models.TextChoices):
    PENDING = "PENDING", "Analyse en attente"
    CLEAN = "CLEAN", "Sain"
    INFECTED = "INFECTED", "Infecté"
    SKIPPED = "SKIPPED", "Analyse non disponible"
    ERROR = "ERROR", "Erreur d'analyse"


class Attachment(BaseModel):
    case = models.ForeignKey(
        "coordination.Case",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="attachments",
    )
    report = models.ForeignKey(
        "reports.VulnerabilityReport",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="attachments",
    )
    message = models.ForeignKey(
        "coordination.CaseMessage",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="attachments",
    )
    uploaded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="uploaded_attachments",
    )
    original_filename = models.CharField(max_length=255)
    storage_name = models.CharField(max_length=80, unique=True, editable=False)
    file = models.FileField(upload_to=attachment_upload_path, max_length=300)
    content_type = models.CharField(max_length=120, blank=True)
    size = models.PositiveBigIntegerField(default=0)
    sha256 = models.CharField(max_length=64, db_index=True)
    scan_status = models.CharField(
        max_length=16, choices=ScanStatus.choices, default=ScanStatus.PENDING
    )
    scan_detail = models.CharField(max_length=255, blank=True)
    is_pgp_encrypted = models.BooleanField(default=False)
    description = models.CharField(max_length=255, blank=True)
    download_count = models.PositiveIntegerField(default=0, editable=False)

    class Meta:
        db_table = "attachments"
        ordering = ["-created_at"]
        verbose_name = "Pièce jointe"
        verbose_name_plural = "Pièces jointes"
        indexes = [models.Index(fields=["case", "-created_at"])]

    def __str__(self):
        return self.original_filename

    def save(self, *args, **kwargs):
        if not self.storage_name:
            suffix = ""
            if "." in self.original_filename:
                suffix = "." + self.original_filename.rsplit(".", 1)[1].lower()[:12]
            self.storage_name = f"{uuid.uuid4().hex}{suffix}"
        return super().save(*args, **kwargs)

    @property
    def is_downloadable(self):
        """Un fichier infecte n'est jamais telechargeable."""
        return self.scan_status != ScanStatus.INFECTED

    @property
    def human_size(self):
        size = float(self.size)
        for unit in ("o", "Ko", "Mo", "Go"):
            if size < 1024:
                return f"{size:.0f} {unit}" if unit == "o" else f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} To"

    def owning_case(self):
        if self.case_id:
            return self.case
        if self.message_id:
            return self.message.case
        if self.report_id:
            return getattr(self.report, "case", None)
        return None

    def is_visible_to(self, user):
        case = self.owning_case()
        if case is None:
            return bool(user and user.is_authenticated and user.is_national)
        return case.is_visible_to(user)
