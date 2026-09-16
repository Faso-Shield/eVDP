"""Programmes VDP et Bug Bounty.

Choix d'architecture : un seul modele `Program` porte un discriminant
`program_type` (VDP ou BUG_BOUNTY). Les deux dispositifs partagent le
perimetre, les regles, le safe harbor et le moteur de case management ; seul
le volet recompense est specifique au Bug Bounty. Ce choix evite la
duplication de deux tables quasi identiques tout en conservant la distinction
metier exigee (voir docs/bug-bounty.md).
"""

from decimal import Decimal

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import MinValueValidator
from django.db import models
from django.utils import timezone
from django.utils.text import slugify

from apps.core.models import BaseModel
from apps.core.pgp import PGPError, validate_public_key
from apps.vulnerabilities.constants import Severity


class ProgramType(models.TextChoices):
    VDP = "VDP", "Programme de divulgation (VDP)"
    BUG_BOUNTY = "BUG_BOUNTY", "Programme Bug Bounty"


class ProgramStatus(models.TextChoices):
    DRAFT = "DRAFT", "Brouillon"
    ACTIVE = "ACTIVE", "Actif"
    PAUSED = "PAUSED", "Suspendu"
    CLOSED = "CLOSED", "Clôturé"


class ConfidentialityLevel(models.TextChoices):
    PUBLIC = "PUBLIC", "Public"
    RESTRICTED = "RESTRICTED", "Restreint"
    PRIVATE = "PRIVATE", "Privé (sur invitation)"


class ProgramQuerySet(models.QuerySet):
    def active(self):
        today = timezone.localdate()
        return self.filter(status=ProgramStatus.ACTIVE).filter(
            models.Q(starts_on__isnull=True) | models.Q(starts_on__lte=today),
            models.Q(ends_on__isnull=True) | models.Q(ends_on__gte=today),
        )

    def public(self):
        return self.active().filter(confidentiality=ConfidentialityLevel.PUBLIC)

    def bug_bounty(self):
        return self.filter(program_type=ProgramType.BUG_BOUNTY)

    def vdp(self):
        return self.filter(program_type=ProgramType.VDP)

    def for_organizations(self, organization_ids):
        return self.filter(organization_id__in=organization_ids)


class Program(BaseModel):
    name = models.CharField(max_length=200)
    slug = models.SlugField(max_length=220, unique=True, blank=True)
    program_type = models.CharField(
        max_length=16, choices=ProgramType.choices, default=ProgramType.VDP, db_index=True
    )
    organization = models.ForeignKey(
        "organizations.Organization", on_delete=models.PROTECT, related_name="programs"
    )
    status = models.CharField(
        max_length=16,
        choices=ProgramStatus.choices,
        default=ProgramStatus.DRAFT,
        db_index=True,
    )
    confidentiality = models.CharField(
        max_length=16,
        choices=ConfidentialityLevel.choices,
        default=ConfidentialityLevel.PUBLIC,
    )
    summary = models.CharField(max_length=300, blank=True)
    description = models.TextField(blank=True, help_text="Markdown autorisé.")
    rules = models.TextField(blank=True, help_text="Règles de test. Markdown autorisé.")
    out_of_scope_notes = models.TextField(blank=True, help_text="Markdown autorisé.")
    safe_harbor = models.TextField(blank=True, help_text="Markdown autorisé.")
    disclosure_policy = models.TextField(blank=True, help_text="Markdown autorisé.")
    eligibility = models.TextField(
        blank=True, help_text="Conditions d'éligibilité. Markdown autorisé."
    )
    starts_on = models.DateField(null=True, blank=True)
    ends_on = models.DateField(null=True, blank=True)
    contact_email = models.EmailField(blank=True)
    pgp_public_key = models.TextField(
        blank=True,
        help_text="Contact direct de l'organisation, hors plateforme eVDP. Le "
        "formulaire de signalement eVDP propose toujours la clé nationale, "
        "jamais celle-ci : chaque dossier doit rester lisible par le CSIRT "
        "national pour le triage.",
    )
    sla_policy = models.ForeignKey(
        "coordination.SLAPolicy",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="programs",
    )
    disclosure_delay_days = models.PositiveIntegerField(
        default=90, help_text="Délai par défaut avant divulgation coordonnée."
    )
    requires_verified_email = models.BooleanField(
        default=False,
        help_text="Si activé, seul un compte authentifié à l'email vérifié "
        "peut signaler sur ce programme (incompatible avec l'anonymat).",
    )
    allows_anonymous_reports = models.BooleanField(
        default=True,
        help_text="Un VDP accepte généralement les signalements anonymes. "
        "Toujours désactivé pour un programme Bug Bounty (une récompense "
        "exige un chercheur identifié).",
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="created_programs",
    )

    objects = ProgramQuerySet.as_manager()

    class Meta:
        db_table = "programs"
        ordering = ["-created_at"]
        verbose_name = "Programme"
        verbose_name_plural = "Programmes"
        indexes = [models.Index(fields=["program_type", "status"])]

    def __str__(self):
        return self.name

    def clean(self):
        if self.starts_on and self.ends_on and self.ends_on < self.starts_on:
            raise ValidationError({"ends_on": "La date de fin doit suivre la date de début."})
        if self.pgp_public_key:
            try:
                self.pgp_public_key = validate_public_key(self.pgp_public_key)
            except PGPError as exc:
                raise ValidationError({"pgp_public_key": str(exc)}) from exc

    def save(self, *args, **kwargs):
        if not self.slug:
            base = slugify(self.name)[:200] or "programme"
            slug, index = base, 1
            while Program.objects.filter(slug=slug).exclude(pk=self.pk).exists():
                index += 1
                slug = f"{base}-{index}"
            self.slug = slug
        return super().save(*args, **kwargs)

    @property
    def is_bug_bounty(self):
        return self.program_type == ProgramType.BUG_BOUNTY

    @property
    def is_open(self):
        today = timezone.localdate()
        if self.status != ProgramStatus.ACTIVE:
            return False
        if self.starts_on and self.starts_on > today:
            return False
        if self.ends_on and self.ends_on < today:
            return False
        return True

    @property
    def is_public(self):
        return self.confidentiality == ConfidentialityLevel.PUBLIC and self.is_open

    def in_scope_targets(self):
        return self.scopes.filter(in_scope=True, is_active=True)

    def out_of_scope_targets(self):
        return self.scopes.filter(in_scope=False)

    def reward_range(self):
        """Bornes de recompense affichables (None si programme sans recompense)."""
        policy = getattr(self, "reward_policy", None)
        if not policy or not policy.is_active:
            return None
        # Un palier a 0/0 est un emplacement par defaut pas encore rempli
        # (voir ensure_reward_policy_consistency) : ne compte pas comme une
        # recompense reellement publiee.
        tiers = [
            t for t in policy.tiers.all() if not (t.min_amount == 0 and t.max_amount == 0)
        ]
        if not tiers:
            return None
        return {
            "currency": policy.currency,
            "min": min(t.min_amount for t in tiers),
            "max": max(t.max_amount for t in tiers),
        }

    def ensure_reward_policy_consistency(self):
        """Fait correspondre l'existence/l'activation de la RewardPolicy au
        program_type courant, apres une eventuelle modification.

        Doit etre appele APRES la sauvegarde du Program (le program_type
        doit deja etre a jour en base). Un programme qui devient Bug Bounty
        recoit une politique active ; un programme qui cesse de l'etre voit
        la sienne desactivee (jamais supprimee : l'historique des paliers
        et des recompenses deja versees ne doit pas disparaitre).
        """
        policy = getattr(self, "reward_policy", None)
        if self.program_type == ProgramType.BUG_BOUNTY:
            if policy is None:
                policy = RewardPolicy.objects.create(program=self)
                # Un palier par sevérité, montant a zero : evite a l'operateur
                # de devoir ajouter chaque ligne manuellement avant de pouvoir
                # simplement saisir les montants.
                RewardTier.objects.bulk_create(
                    RewardTier(policy=policy, severity=severity, min_amount=0, max_amount=0)
                    for severity in Severity.values
                )
            elif not policy.is_active:
                policy.is_active = True
                policy.save(update_fields=["is_active", "updated_at"])
        elif policy is not None and policy.is_active:
            policy.is_active = False
            policy.save(update_fields=["is_active", "updated_at"])


class ScopeTargetType(models.TextChoices):
    DOMAIN = "DOMAIN", "Domaine / sous-domaine"
    URL = "URL", "URL"
    IP_RANGE = "IP_RANGE", "IP ou plage CIDR"
    MOBILE_APP = "MOBILE_APP", "Application mobile"
    API = "API", "API"
    SOURCE_CODE = "SOURCE_CODE", "Code source"
    OTHER = "OTHER", "Autre"


class ScopePriority(models.TextChoices):
    P1 = "P1", "P1 - Critique"
    P2 = "P2", "P2 - Élevée"
    P3 = "P3", "P3 - Moyenne"
    P4 = "P4", "P4 - Faible"


class ProgramScope(BaseModel):
    """Cible incluse ou exclue du perimetre d'un programme."""

    program = models.ForeignKey(Program, on_delete=models.CASCADE, related_name="scopes")
    in_scope = models.BooleanField(default=True, db_index=True)
    target_type = models.CharField(
        max_length=16, choices=ScopeTargetType.choices, default=ScopeTargetType.DOMAIN
    )
    identifier = models.CharField(
        max_length=255, help_text="Ex. *.gov.bf, api.exemple.bf, 10.0.0.0/24"
    )
    application = models.CharField(max_length=180, blank=True)
    platform = models.CharField(max_length=120, blank=True)
    environment = models.CharField(
        max_length=60, blank=True, help_text="Production, préproduction, test…"
    )
    description = models.TextField(blank=True)
    priority = models.CharField(
        max_length=4, choices=ScopePriority.choices, default=ScopePriority.P3
    )
    is_active = models.BooleanField(default=True)

    class Meta:
        db_table = "program_scopes"
        ordering = ["-in_scope", "priority", "identifier"]
        verbose_name = "Périmètre"
        verbose_name_plural = "Périmètres"
        indexes = [models.Index(fields=["program", "in_scope"])]

    def __str__(self):
        marker = "IN" if self.in_scope else "OUT"
        return f"[{marker}] {self.identifier}"


class RuleKind(models.TextChoices):
    TESTING = "TESTING", "Règle de test"
    REPORTING = "REPORTING", "Règle de signalement"
    PROHIBITED = "PROHIBITED", "Interdiction"
    LEGAL = "LEGAL", "Cadre juridique"


class ProgramRule(BaseModel):
    program = models.ForeignKey(Program, on_delete=models.CASCADE, related_name="rule_items")
    kind = models.CharField(max_length=16, choices=RuleKind.choices, default=RuleKind.TESTING)
    title = models.CharField(max_length=200)
    body = models.TextField(blank=True)
    position = models.PositiveSmallIntegerField(default=0)

    class Meta:
        db_table = "program_rules"
        ordering = ["kind", "position", "title"]
        verbose_name = "Règle de programme"
        verbose_name_plural = "Règles de programme"

    def __str__(self):
        return self.title


class RewardPolicy(BaseModel):
    """Matrice de recompenses d'un programme Bug Bounty.

    Les montants ne sont jamais codes en dur : ils sont saisis ici et
    modifiables depuis l'administration.
    """

    program = models.OneToOneField(
        Program, on_delete=models.CASCADE, related_name="reward_policy"
    )
    currency = models.CharField(max_length=8, default="XOF")
    is_active = models.BooleanField(default=True)
    notes = models.TextField(blank=True)
    total_budget = models.DecimalField(max_digits=14, decimal_places=2, null=True, blank=True)

    class Meta:
        db_table = "reward_policies"
        verbose_name = "Politique de récompense"
        verbose_name_plural = "Politiques de récompense"

    def __str__(self):
        return f"Récompenses - {self.program.name}"

    def clean(self):
        if self.program_id and self.program.program_type != ProgramType.BUG_BOUNTY:
            raise ValidationError(
                "Une politique de récompense ne peut être attachée qu'à un "
                "programme Bug Bounty."
            )

    def tier_for(self, severity):
        return self.tiers.filter(severity=severity).first()

    def suggested_amount(self, severity):
        """Montant propose par defaut : borne haute du palier."""
        tier = self.tier_for(severity)
        return tier.max_amount if tier else Decimal("0")

    def budget_consumed(self):
        from apps.bounty.models import Bounty, BountyStatus

        total = Bounty.objects.filter(
            program=self.program,
            status__in=[BountyStatus.APPROVED, BountyStatus.PAID],
        ).aggregate(total=models.Sum("approved_amount"))["total"]
        return total or Decimal("0")


class RewardTier(BaseModel):
    policy = models.ForeignKey(RewardPolicy, on_delete=models.CASCADE, related_name="tiers")
    severity = models.CharField(max_length=16, choices=Severity.choices)
    min_amount = models.DecimalField(
        max_digits=12, decimal_places=2, validators=[MinValueValidator(Decimal("0"))]
    )
    max_amount = models.DecimalField(
        max_digits=12, decimal_places=2, validators=[MinValueValidator(Decimal("0"))]
    )
    description = models.CharField(max_length=255, blank=True)

    class Meta:
        db_table = "reward_tiers"
        unique_together = [("policy", "severity")]
        ordering = ["-max_amount"]
        verbose_name = "Palier de récompense"
        verbose_name_plural = "Paliers de récompense"

    def __str__(self):
        return f"{self.severity}: {self.min_amount} - {self.max_amount}"

    def clean(self):
        if self.max_amount < self.min_amount:
            raise ValidationError(
                {"max_amount": "Le montant maximum doit être supérieur au minimum."}
            )

    def contains(self, amount):
        return self.min_amount <= amount <= self.max_amount
