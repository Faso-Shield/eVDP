"""Modele utilisateur eVDP et jetons associes."""

import uuid
from datetime import timedelta

from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils import timezone

from apps.core.models import TimeStampedModel
from apps.core.utils import random_token

from .roles import (
    NATIONAL_ROLES,
    ORGANIZATION_ROLES,
    RESEARCHER_ROLES,
    Capability,
    Role,
    capabilities_for,
)


class UserManager(BaseUserManager):
    use_in_migrations = True

    def _create_user(self, email, password, **extra):
        if not email:
            raise ValueError("Une adresse email est obligatoire.")
        email = self.normalize_email(email).lower()
        user = self.model(email=email, **extra)
        user.set_password(password)
        user.full_clean(exclude=["password"])
        user.save(using=self._db)
        return user

    def create_user(self, email, password=None, **extra):
        extra.setdefault("role", Role.SECURITY_RESEARCHER)
        extra.setdefault("is_staff", False)
        extra.setdefault("is_superuser", False)
        return self._create_user(email, password, **extra)

    def create_superuser(self, email, password=None, **extra):
        extra.setdefault("role", Role.SUPER_ADMIN)
        extra.setdefault("is_staff", True)
        extra.setdefault("is_superuser", True)
        extra.setdefault("email_verified", True)
        if extra["is_staff"] is not True or extra["is_superuser"] is not True:
            raise ValueError("Un superutilisateur doit avoir is_staff et is_superuser.")
        return self._create_user(email, password, **extra)


class User(AbstractBaseUser, PermissionsMixin, TimeStampedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True, db_index=True)
    full_name = models.CharField(max_length=150, blank=True)
    display_name = models.CharField(
        max_length=80,
        blank=True,
        help_text="Nom affiché dans l'interface (pseudonyme possible).",
    )
    phone = models.CharField(max_length=32, blank=True)
    role = models.CharField(
        max_length=32,
        choices=Role.choices,
        default=Role.PUBLIC_USER,
        db_index=True,
        help_text="Rôle RBAC. Jamais modifiable par l'utilisateur lui-même.",
    )
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    email_verified = models.BooleanField(default=False)
    mfa_enabled = models.BooleanField(
        default=False, help_text="Architecture prête ; activation par étape ultérieure."
    )
    mfa_secret = models.CharField(max_length=64, blank=True, editable=False)
    last_login_ip = models.CharField(max_length=45, blank=True)
    accepted_policy_at = models.DateTimeField(null=True, blank=True)

    objects = UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    class Meta:
        db_table = "users"
        ordering = ["email"]
        verbose_name = "Utilisateur"
        verbose_name_plural = "Utilisateurs"

    def __str__(self):
        return self.display_name or self.full_name or self.email

    def save(self, *args, **kwargs):
        self.email = self.email.lower().strip()
        if not self.display_name:
            self.display_name = (self.full_name or self.email.split("@")[0])[:80]
        return super().save(*args, **kwargs)

    # -- RBAC ---------------------------------------------------------------
    @property
    def capabilities(self):
        return capabilities_for(self.role)

    def has_capability(self, capability):
        if not self.is_active:
            return False
        if self.is_superuser:
            return True
        return capability in self.capabilities

    @property
    def is_national(self):
        return self.is_superuser or self.role in NATIONAL_ROLES

    @property
    def is_organization_user(self):
        return self.role in ORGANIZATION_ROLES

    @property
    def is_researcher(self):
        return self.role in RESEARCHER_ROLES

    @property
    def is_read_only(self):
        return self.role == Role.AUDITOR and not self.is_superuser

    def organization_ids(self):
        """Identifiants des organisations dont l'utilisateur est membre actif."""
        return list(
            self.organization_memberships.filter(is_active=True).values_list(
                "organization_id", flat=True
            )
        )

    @property
    def primary_organization(self):
        membership = (
            self.organization_memberships.filter(is_active=True)
            .select_related("organization")
            .order_by("-is_primary", "created_at")
            .first()
        )
        return membership.organization if membership else None

    def public_identity(self):
        """Identite affichable publiquement, selon le choix du chercheur."""
        profile = getattr(self, "researcher_profile", None)
        if profile is not None:
            return profile.public_identity()
        return self.display_name or "Utilisateur eVDP"


class TokenPurpose(models.TextChoices):
    EMAIL_VERIFICATION = "EMAIL_VERIFICATION", "Vérification d'email"
    PASSWORD_RESET = "PASSWORD_RESET", "Réinitialisation de mot de passe"


class UserToken(TimeStampedModel):
    """Jeton a usage unique et duree limitee (verification, reinitialisation)."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="tokens")
    purpose = models.CharField(max_length=32, choices=TokenPurpose.choices)
    token = models.CharField(max_length=64, unique=True, default=random_token)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "user_tokens"
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["purpose", "expires_at"])]

    def __str__(self):
        return f"{self.get_purpose_display()} - {self.user.email}"

    @property
    def is_valid(self):
        return self.used_at is None and self.expires_at > timezone.now()

    def consume(self):
        self.used_at = timezone.now()
        self.save(update_fields=["used_at", "updated_at"])

    @classmethod
    def issue(cls, user, purpose, ttl_hours=24):
        cls.objects.filter(user=user, purpose=purpose, used_at=None).update(
            used_at=timezone.now()
        )
        return cls.objects.create(
            user=user,
            purpose=purpose,
            token=random_token(),
            expires_at=timezone.now() + timedelta(hours=ttl_hours),
        )


class ApiKey(TimeStampedModel):
    """Cle d'API pour l'integration machine (soumission automatisee).

    Seul le hachage est conserve : la valeur en clair n'est affichee qu'une
    fois, a la creation.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="api_keys")
    label = models.CharField(max_length=120)
    prefix = models.CharField(max_length=12, db_index=True)
    key_hash = models.CharField(max_length=128, unique=True)
    is_active = models.BooleanField(default=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "api_keys"
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.label} ({self.prefix}…)"

    @property
    def is_usable(self):
        return self.is_active and (self.expires_at is None or self.expires_at > timezone.now())


__all__ = ["User", "UserManager", "UserToken", "TokenPurpose", "ApiKey", "Capability", "Role"]
