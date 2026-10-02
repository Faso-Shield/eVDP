"""Modeles de base partages par toutes les applications eVDP."""

import uuid

from django.db import models
from django.utils import timezone


class UUIDPrimaryKeyModel(models.Model):
    """Cle primaire UUID : evite l'enumeration d'objets sensibles (IDOR)."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    class Meta:
        abstract = True


class TimeStampedModel(models.Model):
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class BaseModel(UUIDPrimaryKeyModel, TimeStampedModel):
    class Meta:
        abstract = True


class SequenceCounter(models.Model):
    """Compteur atomique pour les identifiants lisibles sequentiels.

    Une ligne par (prefixe, annee). Contrairement a une derivation du
    "dernier" enregistrement existant (qui ne verrouille rien en cas
    d'insertion concurrente), cette ligne est verrouillee et incrementee
    sur place : deux transactions concurrentes sont serialisees pour de
    vrai par le verrou ligne, sans collision possible.
    """

    key = models.CharField(max_length=64, unique=True)
    last_value = models.PositiveIntegerField(default=0)

    class Meta:
        db_table = "core_sequence_counters"

    def __str__(self):
        return f"{self.key} -> {self.last_value}"


class SiteSetting(TimeStampedModel):
    """Parametres editables depuis l'administration (politique, textes legaux).

    Utilise pour la politique de divulgation nationale et les blocs de texte
    institutionnels afin qu'ils ne soient pas codes en dur dans les gabarits.
    """

    key = models.SlugField(max_length=120, unique=True)
    label = models.CharField(max_length=200)
    value = models.TextField(blank=True, help_text="Contenu Markdown autorisé.")
    is_published = models.BooleanField(default=True)

    class Meta:
        db_table = "site_settings"
        ordering = ["key"]
        verbose_name = "Paramètre de site"
        verbose_name_plural = "Paramètres de site"

    def __str__(self):
        return self.label or self.key

    @classmethod
    def get_value(cls, key, default=""):
        row = cls.objects.filter(key=key, is_published=True).first()
        return row.value if row else default


class NationalPGPKey(BaseModel):
    """Cle publique PGP nationale, deposee depuis l'application.

    Une seule cle est active ; les precedentes sont conservees (rotation
    tracee). La cle privee correspondante n'est jamais transmise a eVDP :
    les messages chiffres avec cette cle se dechiffrent dans le navigateur de
    l'equipe destinataire (static/js/pgp.js).
    """

    public_key = models.TextField(verbose_name="Clé publique armurée")
    fingerprint = models.CharField(max_length=64, verbose_name="Empreinte")
    key_created_at = models.DateTimeField(verbose_name="Créée le")
    expires_at = models.DateTimeField(null=True, blank=True, verbose_name="Expire le")
    is_active = models.BooleanField(default=True, verbose_name="Active")
    published_by = models.ForeignKey(
        "accounts.User",
        null=True,
        on_delete=models.SET_NULL,
        related_name="+",
        verbose_name="Publiée par",
    )

    class Meta:
        db_table = "national_pgp_keys"
        ordering = ["-created_at"]
        verbose_name = "Clé PGP nationale"
        verbose_name_plural = "Clés PGP nationales"

    def __str__(self):
        return self.fingerprint

    @property
    def readable_fingerprint(self):
        return " ".join(
            self.fingerprint[i : i + 4] for i in range(0, len(self.fingerprint), 4)
        )


class PGPKeyDelivery(BaseModel):
    """Remise de la cle privee nationale a un membre de l'equipe nationale.

    `payload` est la cle privee chiffree dans le navigateur du gestionnaire
    par un code de remise que eVDP ne recoit jamais (apps.core.pgp). Le bloc
    est efface des la recuperation confirmee, l'annulation ou l'expiration :
    seule la trace de la remise subsiste.
    """

    national_key = models.ForeignKey(
        NationalPGPKey,
        null=True,
        on_delete=models.SET_NULL,
        related_name="deliveries",
        verbose_name="Clé nationale",
    )
    fingerprint = models.CharField(max_length=64, verbose_name="Empreinte")
    recipient = models.ForeignKey(
        "accounts.User",
        on_delete=models.CASCADE,
        related_name="pgp_key_deliveries",
        verbose_name="Destinataire",
    )
    created_by = models.ForeignKey(
        "accounts.User",
        null=True,
        on_delete=models.SET_NULL,
        related_name="+",
        verbose_name="Préparée par",
    )
    payload = models.TextField(blank=True, verbose_name="Clé privée chiffrée")
    expires_at = models.DateTimeField(verbose_name="Expire le")
    fetch_count = models.PositiveSmallIntegerField(default=0, verbose_name="Récupérations")
    retrieved_at = models.DateTimeField(null=True, blank=True, verbose_name="Récupérée le")
    revoked_at = models.DateTimeField(null=True, blank=True, verbose_name="Annulée le")

    class Meta:
        db_table = "pgp_key_deliveries"
        ordering = ["-created_at"]
        verbose_name = "Remise de clé PGP"
        verbose_name_plural = "Remises de clé PGP"

    def __str__(self):
        return f"{self.fingerprint} -> {self.recipient}"

    @property
    def readable_fingerprint(self):
        return " ".join(
            self.fingerprint[i : i + 4] for i in range(0, len(self.fingerprint), 4)
        )

    @property
    def status(self):
        if self.retrieved_at:
            return "retrieved"
        if self.revoked_at:
            return "revoked"
        if not self.payload or self.expires_at <= timezone.now():
            return "expired"
        return "pending"

    @property
    def status_label(self):
        return {
            "retrieved": "Récupérée",
            "revoked": "Annulée",
            "expired": "Expirée",
            "pending": "En attente",
        }[self.status]

    @property
    def is_open(self):
        return self.status == "pending"

    def wipe(self, **fields):
        """Efface le bloc chiffre ; les champs passes sont enregistres avec lui."""
        self.payload = ""
        for name, value in fields.items():
            setattr(self, name, value)
        self.save(update_fields=["payload", "updated_at", *fields])
