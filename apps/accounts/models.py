"""Modele utilisateur eVDP et jetons associes."""

import uuid
from datetime import timedelta

from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.core.exceptions import ValidationError
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
    email = models.EmailField(unique=True, db_index=True, verbose_name="Adresse email")
    full_name = models.CharField(max_length=150, blank=True, verbose_name="Nom complet")
    display_name = models.CharField(
        max_length=80,
        blank=True,
        verbose_name="Nom affiché",
        help_text="Nom affiché dans l'interface (pseudonyme possible).",
    )
    phone = models.CharField(max_length=32, blank=True, verbose_name="Téléphone")
    role = models.CharField(
        max_length=32,
        choices=Role.choices,
        default=Role.PUBLIC_USER,
        db_index=True,
        verbose_name="Rôle",
        help_text="Rôle RBAC. Jamais modifiable par l'utilisateur lui-même.",
    )
    is_active = models.BooleanField(default=True, verbose_name="Compte actif")
    is_staff = models.BooleanField(default=False, verbose_name="Accès à l'administration")
    email_verified = models.BooleanField(default=False, verbose_name="Adresse vérifiée")
    verification_reminded_on = models.DateField(
        null=True,
        blank=True,
        verbose_name="Dernière relance de vérification",
        help_text="Jour de la dernière relance de vérification, pour n'en "
        "envoyer qu'une par jalon.",
    )
    pgp_public_key = models.TextField(blank=True, verbose_name="Clé publique PGP")
    pgp_fingerprint = models.CharField(max_length=64, blank=True, verbose_name="Empreinte PGP")
    mfa_enabled = models.BooleanField(
        default=False,
        verbose_name="Authentificateur enregistré",
        help_text="Enrôlement TOTP effectué. L'exigence, elle, découle du "
        "rôle : voir apps.accounts.mfa.is_required.",
    )
    mfa_secret = models.CharField(max_length=64, blank=True, editable=False)
    mfa_confirmed_at = models.DateTimeField(
        null=True, blank=True, editable=False, verbose_name="Enregistré le"
    )
    mfa_last_step = models.BigIntegerField(
        null=True,
        blank=True,
        editable=False,
        help_text="Dernier pas de temps TOTP consommé, pour refuser le rejeu.",
    )
    last_login_ip = models.CharField(
        max_length=45, blank=True, verbose_name="Dernière IP de connexion"
    )
    accepted_policy_at = models.DateTimeField(
        null=True, blank=True, verbose_name="Politique acceptée le"
    )

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

    def clean(self):
        if self.mfa_enabled and self.is_researcher:
            raise ValidationError(
                {
                    "mfa_enabled": "Un compte signaleur n'est pas soumis à la "
                    "double authentification."
                }
            )

    def save(self, *args, **kwargs):
        self.email = self.email.lower().strip()
        if not self.display_name:
            self.display_name = (self.full_name or self.email.split("@")[0])[:80]
        # Une retrogradation vers un role de signaleur ne doit pas laisser un
        # secret orphelin en base : il ne servirait plus jamais, la regle
        # etant portee par le role. On le purge au lieu de le conserver.
        if self.is_researcher and (self.mfa_enabled or self.mfa_secret):
            self.mfa_enabled = False
            self.mfa_secret = ""
            self.mfa_confirmed_at = None
            self.mfa_last_step = None
            champs = kwargs.get("update_fields")
            if champs is not None:
                kwargs["update_fields"] = list(champs) + [
                    "mfa_enabled",
                    "mfa_secret",
                    "mfa_confirmed_at",
                    "mfa_last_step",
                ]
        return super().save(*args, **kwargs)

    # -- Double authentification --------------------------------------------
    @property
    def mfa_required(self):
        """Le second facteur s'applique-t-il ? Decoule du role, jamais du client."""
        from .mfa import is_required

        return is_required(self)

    @property
    def mfa_pending_enrollment(self):
        """Compte soumis au second facteur mais pas encore enrole."""
        return self.mfa_required and not (self.mfa_enabled and self.mfa_secret)

    def reset_mfa(self):
        """Revoque l'enrolement : le compte devra en refaire un a la connexion."""
        self.mfa_enabled = False
        self.mfa_secret = ""
        self.mfa_confirmed_at = None
        self.mfa_last_step = None
        self.save(
            update_fields=[
                "mfa_enabled",
                "mfa_secret",
                "mfa_confirmed_at",
                "mfa_last_step",
                "updated_at",
            ]
        )

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


class BusinessAccount(User):
    """Comptes metiers et administrateurs, vue d'administration dediee.

    Deux populations qui n'ont ni le meme cycle de vie ni les memes
    informations utiles : celle-ci est creee par un administrateur, porte un
    role donnant acces aux dossiers d'autrui et un second facteur ; l'autre
    s'inscrit seule et se juge a sa reputation. Les melanger dans une liste
    unique obligeait a lire la colonne role pour savoir a qui on avait
    affaire, et a filtrer avant toute action de masse.

    Un proxy et non une table : c'est la meme entite `User`, vue sous deux
    angles. Aucune donnee n'est dupliquee et l'authentification ignore la
    distinction. Le partage des roles entre les deux vues se fait dans
    l'administration, et non par un manager filtre par defaut, qui servirait
    aussi de `_base_manager` et masquerait des lignes a l'ORM.
    """

    class Meta:
        proxy = True
        verbose_name = "Compte metier"
        verbose_name_plural = "Comptes metiers et administrateurs"


class ReporterAccount(User):
    """Comptes signaleurs : chercheurs et utilisateurs publics.

    Population d'inscription libre, jamais soumise au second facteur. Voir
    `BusinessAccount` pour la raison de la separation.
    """

    class Meta:
        proxy = True
        verbose_name = "Compte signaleur"
        verbose_name_plural = "Comptes signaleurs"


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


__all__ = [
    "User",
    "UserManager",
    "BusinessAccount",
    "ReporterAccount",
    "UserToken",
    "TokenPurpose",
    "ApiKey",
    "Capability",
    "Role",
]
