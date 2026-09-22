"""Modeles de base partages par toutes les applications eVDP."""

import uuid

from django.db import models


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
        verbose_name = "Parametre de site"
        verbose_name_plural = "Parametres de site"

    def __str__(self):
        return self.label or self.key

    @classmethod
    def get_value(cls, key, default=""):
        row = cls.objects.filter(key=key, is_published=True).first()
        return row.value if row else default
