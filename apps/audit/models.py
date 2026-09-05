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
    LOGIN_FAILED = "LOGIN_FAILED", "Echec de connexion"
    LOGOUT = "LOGOUT", "Deconnexion"
    PASSWORD_RESET_REQUESTED = "PASSWORD_RESET_REQUESTED", "Reinitialisation demandee"
    PASSWORD_CHANGED = "PASSWORD_CHANGED", "Mot de passe modifie"
    EMAIL_VERIFIED = "EMAIL_VERIFIED", "Email verifie"
    USER_CREATED = "USER_CREATED", "Utilisateur cree"
    USER_UPDATED = "USER_UPDATED", "Utilisateur modifie"
    ROLE_CHANGED = "ROLE_CHANGED", "Role modifie"
    ORGANIZATION_CREATED = "ORGANIZATION_CREATED", "Organisation creee"
    ORGANIZATION_UPDATED = "ORGANIZATION_UPDATED", "Organisation modifiee"
    MEMBERSHIP_CHANGED = "MEMBERSHIP_CHANGED", "Appartenance modifiee"
    PROGRAM_CREATED = "PROGRAM_CREATED", "Programme cree"
    PROGRAM_UPDATED = "PROGRAM_UPDATED", "Programme modifie"
    REPORT_SUBMITTED = "REPORT_SUBMITTED", "Rapport soumis"
    CASE_CREATED = "CASE_CREATED", "Case cree"
    CASE_VIEWED = "CASE_VIEWED", "Case consulte"
    CASE_UPDATED = "CASE_UPDATED", "Case modifie"
    CASE_ASSIGNED = "CASE_ASSIGNED", "Case assigne"
    STATUS_CHANGED = "STATUS_CHANGED", "Statut modifie"
    MESSAGE_SENT = "MESSAGE_SENT", "Message envoye"
    ATTACHMENT_UPLOADED = "ATTACHMENT_UPLOADED", "Piece jointe televersee"
    ATTACHMENT_DOWNLOADED = "ATTACHMENT_DOWNLOADED", "Piece jointe telechargee"
    ATTACHMENT_DELETED = "ATTACHMENT_DELETED", "Piece jointe supprimee"
    REPORT_VALIDATED = "REPORT_VALIDATED", "Rapport valide"
    REPORT_REJECTED = "REPORT_REJECTED", "Rapport rejete"
    REPORT_DUPLICATED = "REPORT_DUPLICATED", "Rapport marque doublon"
    ADVISORY_CREATED = "ADVISORY_CREATED", "Advisory cree"
    ADVISORY_UPDATED = "ADVISORY_UPDATED", "Advisory modifie"
    ADVISORY_PUBLISHED = "ADVISORY_PUBLISHED", "Advisory publie"
    ADVISORY_RETRACTED = "ADVISORY_RETRACTED", "Advisory retire"
    BOUNTY_PROPOSED = "BOUNTY_PROPOSED", "Recompense proposee"
    BOUNTY_APPROVED = "BOUNTY_APPROVED", "Recompense approuvee"
    BOUNTY_REJECTED = "BOUNTY_REJECTED", "Recompense rejetee"
    BOUNTY_PAID = "BOUNTY_PAID", "Recompense payee"
    EXPORT_GENERATED = "EXPORT_GENERATED", "Export genere"
    PERMISSION_DENIED = "PERMISSION_DENIED", "Acces refuse"
    SLA_BREACHED = "SLA_BREACHED", "SLA depasse"
    CSAF_IMPORTED = "CSAF_IMPORTED", "Import CSAF"


class AuditResult(models.TextChoices):
    SUCCESS = "SUCCESS", "Succes"
    FAILURE = "FAILURE", "Echec"
    DENIED = "DENIED", "Refuse"


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
        help_text="Identite denormalisee, conservee si le compte est supprime.",
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
                "Une entree d'audit ne peut pas etre modifiee apres creation."
            )
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):  # pragma: no cover - garde-fou
        raise NotImplementedError("Une entree d'audit ne peut pas etre supprimee.")
