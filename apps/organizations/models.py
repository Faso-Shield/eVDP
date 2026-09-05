"""Organisations beneficiaires (administrations, entreprises, operateurs)."""

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.utils.text import slugify

from apps.core.models import BaseModel
from apps.core.pgp import PGPError, validate_public_key


class OrganizationType(models.TextChoices):
    PUBLIC_ADMIN = "PUBLIC_ADMIN", "Administration publique"
    MINISTRY = "MINISTRY", "Ministere"
    LOCAL_AUTHORITY = "LOCAL_AUTHORITY", "Collectivite territoriale"
    PUBLIC_INSTITUTION = "PUBLIC_INSTITUTION", "Etablissement public"
    PUBLIC_COMPANY = "PUBLIC_COMPANY", "Entreprise publique"
    PRIVATE_COMPANY = "PRIVATE_COMPANY", "Entreprise privee"
    OPERATOR = "OPERATOR", "Operateur d'importance vitale"
    UNIVERSITY = "UNIVERSITY", "Universite / recherche"
    OTHER = "OTHER", "Autre"


class Sector(models.TextChoices):
    GOVERNMENT = "GOVERNMENT", "Gouvernement"
    DEFENSE = "DEFENSE", "Defense et securite"
    HEALTH = "HEALTH", "Sante"
    EDUCATION = "EDUCATION", "Education"
    FINANCE = "FINANCE", "Finance et banque"
    TELECOM = "TELECOM", "Telecommunications"
    ENERGY = "ENERGY", "Energie"
    WATER = "WATER", "Eau et assainissement"
    TRANSPORT = "TRANSPORT", "Transport"
    JUSTICE = "JUSTICE", "Justice"
    AGRICULTURE = "AGRICULTURE", "Agriculture"
    INDUSTRY = "INDUSTRY", "Industrie"
    OTHER = "OTHER", "Autre"


class OrganizationStatus(models.TextChoices):
    ACTIVE = "ACTIVE", "Active"
    PENDING = "PENDING", "En attente de validation"
    SUSPENDED = "SUSPENDED", "Suspendue"
    ARCHIVED = "ARCHIVED", "Archivee"


class Organization(BaseModel):
    name = models.CharField(max_length=200, unique=True)
    acronym = models.CharField(max_length=32, blank=True)
    slug = models.SlugField(max_length=220, unique=True, blank=True)
    organization_type = models.CharField(
        max_length=32, choices=OrganizationType.choices, default=OrganizationType.OTHER
    )
    sector = models.CharField(
        max_length=32, choices=Sector.choices, default=Sector.OTHER, db_index=True
    )
    domain = models.CharField(
        max_length=180, blank=True, help_text="Domaine principal, ex. sante.gov.bf"
    )
    official_email = models.EmailField(blank=True)
    phone = models.CharField(max_length=32, blank=True)
    website = models.URLField(blank=True)
    address = models.CharField(max_length=255, blank=True)
    region = models.CharField(max_length=80, blank=True)
    status = models.CharField(
        max_length=16,
        choices=OrganizationStatus.choices,
        default=OrganizationStatus.ACTIVE,
        db_index=True,
    )
    dsi_name = models.CharField(max_length=150, blank=True, verbose_name="Responsable DSI")
    dsi_email = models.EmailField(blank=True)
    manager_name = models.CharField(max_length=150, blank=True)
    manager_email = models.EmailField(blank=True)
    pgp_public_key = models.TextField(blank=True)
    description = models.TextField(blank=True)
    accepts_vdp = models.BooleanField(
        default=True, help_text="Accepte de recevoir des signalements via eVDP."
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="created_organizations",
    )

    class Meta:
        db_table = "organizations"
        ordering = ["name"]
        verbose_name = "Organisation"
        verbose_name_plural = "Organisations"

    def __str__(self):
        return f"{self.acronym} - {self.name}" if self.acronym else self.name

    def clean(self):
        if self.pgp_public_key:
            try:
                self.pgp_public_key = validate_public_key(self.pgp_public_key)
            except PGPError as exc:
                raise ValidationError({"pgp_public_key": str(exc)}) from exc

    def save(self, *args, **kwargs):
        if not self.slug:
            base = slugify(self.acronym or self.name)[:200] or "organisation"
            slug, index = base, 1
            while Organization.objects.filter(slug=slug).exclude(pk=self.pk).exists():
                index += 1
                slug = f"{base}-{index}"
            self.slug = slug
        return super().save(*args, **kwargs)

    @property
    def is_active(self):
        return self.status == OrganizationStatus.ACTIVE


class MembershipRole(models.TextChoices):
    MANAGER = "MANAGER", "Responsable"
    DSI = "DSI", "DSI"
    SECURITY_CONTACT = "SECURITY_CONTACT", "Contact securite"
    ANALYST = "ANALYST", "Analyste"
    OBSERVER = "OBSERVER", "Observateur"


class OrganizationMember(BaseModel):
    """Rattachement d'un utilisateur a une organisation (multi-appartenance)."""

    organization = models.ForeignKey(
        Organization, on_delete=models.CASCADE, related_name="members"
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="organization_memberships",
    )
    membership_role = models.CharField(
        max_length=24, choices=MembershipRole.choices, default=MembershipRole.OBSERVER
    )
    is_primary = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    invited_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="sent_org_invitations",
    )

    class Meta:
        db_table = "organization_members"
        unique_together = [("organization", "user")]
        ordering = ["organization__name", "user__email"]
        verbose_name = "Membre d'organisation"
        verbose_name_plural = "Membres d'organisation"

    def __str__(self):
        return f"{self.user} @ {self.organization} ({self.membership_role})"


class SecurityContact(BaseModel):
    """Point de contact securite publie dans les programmes de l'organisation."""

    organization = models.ForeignKey(
        Organization, on_delete=models.CASCADE, related_name="security_contacts"
    )
    name = models.CharField(max_length=150)
    role = models.CharField(max_length=120, blank=True)
    email = models.EmailField()
    phone = models.CharField(max_length=32, blank=True)
    pgp_public_key = models.TextField(blank=True)
    is_primary = models.BooleanField(default=False)

    class Meta:
        db_table = "organization_security_contacts"
        ordering = ["-is_primary", "name"]
        verbose_name = "Contact securite"
        verbose_name_plural = "Contacts securite"

    def __str__(self):
        return f"{self.name} <{self.email}>"

    def clean(self):
        if self.pgp_public_key:
            try:
                self.pgp_public_key = validate_public_key(self.pgp_public_key)
            except PGPError as exc:
                raise ValidationError({"pgp_public_key": str(exc)}) from exc
