"""Journal d'audit immuable.

Principe 4 : toute action sensible doit etre auditable.
Les enregistrements sont append-only : ils ne peuvent etre ni modifies ni
supprimes via l'ORM ou l'administration par un utilisateur normal.
"""

import uuid

from django.conf import settings
from django.db import models


class AuditAction(models.TextChoices):
    LOGIN = "LOGIN", "Connexion"
    LOGIN_FAILED = "LOGIN_FAILED", "Échec de connexion"
    LOGOUT = "LOGOUT", "Déconnexion"
    PASSWORD_RESET_REQUESTED = "PASSWORD_RESET_REQUESTED", "Réinitialisation demandee"
    PASSWORD_CHANGED = "PASSWORD_CHANGED", "Mot de passe modifié"
    EMAIL_VERIFIED = "EMAIL_VERIFIED", "Email vérifié"
    MFA_ENROLLED = "MFA_ENROLLED", "Double authentification activée"
    MFA_VERIFIED = "MFA_VERIFIED", "Second facteur validé"
    MFA_FAILED = "MFA_FAILED", "Second facteur refusé"
    MFA_RESET = "MFA_RESET", "Double authentification réinitialisée"
    USER_CREATED = "USER_CREATED", "Utilisateur créé"
    USER_UPDATED = "USER_UPDATED", "Utilisateur modifié"
    ROLE_CHANGED = "ROLE_CHANGED", "Rôle modifié"
    ORGANIZATION_CREATED = "ORGANIZATION_CREATED", "Organisation créée"
    ORGANIZATION_UPDATED = "ORGANIZATION_UPDATED", "Organisation modifiée"
    MEMBERSHIP_CHANGED = "MEMBERSHIP_CHANGED", "Appartenance modifiée"
    PROGRAM_CREATED = "PROGRAM_CREATED", "Programme créé"
    PROGRAM_UPDATED = "PROGRAM_UPDATED", "Programme modifié"
    REPORT_SUBMITTED = "REPORT_SUBMITTED", "Rapport soumis"
    CASE_CREATED = "CASE_CREATED", "Case créé"
    CASE_VIEWED = "CASE_VIEWED", "Case consulte"
    CASE_UPDATED = "CASE_UPDATED", "Case modifié"
    CASE_ASSIGNED = "CASE_ASSIGNED", "Case assigné"
    STATUS_CHANGED = "STATUS_CHANGED", "Statut modifié"
    MESSAGE_SENT = "MESSAGE_SENT", "Message envoyé"
    ATTACHMENT_UPLOADED = "ATTACHMENT_UPLOADED", "Pièce jointe téléversée"
    ATTACHMENT_DOWNLOADED = "ATTACHMENT_DOWNLOADED", "Pièce jointe téléchargée"
    ATTACHMENT_DELETED = "ATTACHMENT_DELETED", "Pièce jointe supprimée"
    REPORT_VALIDATED = "REPORT_VALIDATED", "Rapport validé"
    REPORT_REJECTED = "REPORT_REJECTED", "Rapport rejeté"
    REPORT_DUPLICATED = "REPORT_DUPLICATED", "Rapport marqué doublon"
    ADVISORY_CREATED = "ADVISORY_CREATED", "Advisory créé"
    ADVISORY_UPDATED = "ADVISORY_UPDATED", "Advisory modifié"
    ADVISORY_PUBLISHED = "ADVISORY_PUBLISHED", "Advisory publié"
    ADVISORY_RETRACTED = "ADVISORY_RETRACTED", "Advisory retiré"
    BOUNTY_PROPOSED = "BOUNTY_PROPOSED", "Récompense proposée"
    BOUNTY_APPROVED = "BOUNTY_APPROVED", "Récompense approuvée"
    BOUNTY_REJECTED = "BOUNTY_REJECTED", "Récompense rejetée"
    BOUNTY_PAID = "BOUNTY_PAID", "Récompense payée"
    EXPORT_GENERATED = "EXPORT_GENERATED", "Export généré"
    PERMISSION_DENIED = "PERMISSION_DENIED", "Accès refusé"
    SLA_BREACHED = "SLA_BREACHED", "SLA dépassé"
    CSAF_IMPORTED = "CSAF_IMPORTED", "Import CSAF"
    PAYOUT_PROFILE_UPDATED = "PAYOUT_PROFILE_UPDATED", "Profil de versement modifie"
    PAYOUT_METHOD_ADDED = "PAYOUT_METHOD_ADDED", "Moyen de paiement ajoute"
    PAYOUT_METHOD_UPDATED = "PAYOUT_METHOD_UPDATED", "Moyen de paiement modifie"
    PAYOUT_METHOD_REMOVED = "PAYOUT_METHOD_REMOVED", "Moyen de paiement retire"
    PAYOUT_DOCUMENT_UPLOADED = "PAYOUT_DOCUMENT_UPLOADED", "Piece d'identite televersee"
    PAYOUT_DOCUMENT_DOWNLOADED = "PAYOUT_DOCUMENT_DOWNLOADED", "Piece d'identite telechargee"
    PAYOUT_REFERENCE_VIEWED = (
        "PAYOUT_REFERENCE_VIEWED",
        "Reference de paiement consultee en clair",
    )


class AuditResult(models.TextChoices):
    SUCCESS = "SUCCESS", "Succès"
    FAILURE = "FAILURE", "Échec"
    DENIED = "DENIED", "Refusé"


class AuditLogQuerySet(models.QuerySet):
    def update(self, **kwargs):  # pragma: no cover - garde-fou
        raise NotImplementedError("Le journal d'audit est append-only.")

    def delete(self):  # pragma: no cover - garde-fou
        raise NotImplementedError("Le journal d'audit est append-only.")


class AuditLog(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="audit_entries",
    )
    actor_label = models.CharField(
        max_length=254,
        blank=True,
        help_text="Identité dénormalisée, conservée si le compte est supprimé.",
    )
    action = models.CharField(max_length=48, choices=AuditAction.choices, db_index=True)
    object_type = models.CharField(max_length=64, blank=True, db_index=True)
    object_id = models.CharField(max_length=64, blank=True, db_index=True)
    object_repr = models.CharField(max_length=255, blank=True)
    result = models.CharField(
        max_length=12, choices=AuditResult.choices, default=AuditResult.SUCCESS
    )
    ip_address = models.CharField(max_length=45, blank=True)
    user_agent = models.CharField(max_length=300, blank=True)
    metadata = models.JSONField(default=dict, blank=True)

    objects = AuditLogQuerySet.as_manager()

    class Meta:
        db_table = "audit_logs"
        ordering = ["-timestamp"]
        verbose_name = "Entree d'audit"
        verbose_name_plural = "Journal d'audit"
        indexes = [
            models.Index(fields=["object_type", "object_id"]),
            models.Index(fields=["action", "-timestamp"]),
        ]

    def __str__(self):
        return f"{self.timestamp:%Y-%m-%d %H:%M} {self.action} {self.object_repr}"

    def save(self, *args, **kwargs):
        if self.pk and AuditLog.objects.filter(pk=self.pk).exists():
            raise NotImplementedError(
                "Une entrée d'audit ne peut pas être modifiée après création."
            )
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):  # pragma: no cover - garde-fou
        raise NotImplementedError("Une entrée d'audit ne peut pas être supprimée.")
