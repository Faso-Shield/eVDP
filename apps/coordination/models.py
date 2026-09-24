"""Case management : coeur de la coordination eVDP."""

from datetime import timedelta

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.urls import reverse
from django.utils import timezone

from apps.core.models import BaseModel, TimeStampedModel
from apps.core.utils import hash_text, next_sequence
from apps.vulnerabilities.constants import Severity, VulnerabilityType

from .constants import (
    Confidentiality,
    ParticipantRole,
    SLAKind,
    SLAState,
    TimelineEventType,
    WorkflowType,
)
from .workflow import (
    DISMISSED_STATES,
    ORG_VISIBLE_STATES,
    TERMINAL_STATES,
    CaseBountyStatus,
    CaseStatus,
    kanban_column_for,
)


class SLAPolicy(TimeStampedModel):
    """Delais contractuels configurables, exprimes en heures ou en jours."""

    name = models.CharField(max_length=120, unique=True)
    is_default = models.BooleanField(default=False)
    acknowledgement_hours = models.PositiveIntegerField(default=72)
    triage_days = models.PositiveIntegerField(
        default=5, help_text="Recevabilité et qualification (étapes 2 et 3)."
    )
    validation_days = models.PositiveIntegerField(
        default=2, help_text="Validation de la qualification (étape 4)."
    )
    vendor_response_days = models.PositiveIntegerField(
        default=5, help_text="Plan de remédiation de l'organisation (étape 6)."
    )
    remediation_days_critical = models.PositiveIntegerField(default=30)
    remediation_days_high = models.PositiveIntegerField(default=60)
    remediation_days_medium = models.PositiveIntegerField(default=90)
    remediation_days_low = models.PositiveIntegerField(default=90)
    verification_days = models.PositiveIntegerField(
        default=5, help_text="Contre-vérification du correctif (étape 8)."
    )
    disclosure_delay_days = models.PositiveIntegerField(default=90)
    warning_ratio = models.PositiveSmallIntegerField(
        default=75, help_text="Pourcentage du délai à partir duquel une alerte est levée."
    )

    class Meta:
        db_table = "sla_policies"
        ordering = ["-is_default", "name"]
        verbose_name = "Politique SLA"
        verbose_name_plural = "Politiques SLA"

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        if self.is_default:
            SLAPolicy.objects.exclude(pk=self.pk).update(is_default=False)

    @classmethod
    def get_default(cls):
        return cls.objects.filter(is_default=True).first() or cls.objects.first()

    def remediation_days_for(self, severity):
        return {
            Severity.CRITICAL: self.remediation_days_critical,
            Severity.HIGH: self.remediation_days_high,
            Severity.MEDIUM: self.remediation_days_medium,
            Severity.LOW: self.remediation_days_low,
        }.get(severity, self.remediation_days_low)


class CaseQuerySet(models.QuerySet):
    def open(self):
        return self.exclude(status__in=TERMINAL_STATES)

    def visible_to(self, user):
        """Filtre d'isolation : chaque utilisateur ne voit que son perimetre.

        Principe 3 (moindre privilege) applique au niveau du queryset, afin
        qu'aucune vue ne puisse accidentellement exposer un case hors scope.
        """
        if not user or not user.is_authenticated:
            return self.none()
        if user.can_view_all_cases:
            return self
        filters = models.Q(reporter=user)
        if user.is_organization_user:
            # Une organisation ne voit un dossier qu'a partir de l'etape 5
            # (ORG_VISIBLE_STATES), une fois le CSIRT l'ayant explicitement
            # engagee -- jamais pendant le triage, pour proteger le declarant
            # d'une reaction prematuree. La regle vaut aussi pour un membre
            # ajoute nominativement comme participant.
            org_scope = models.Q(participants__user=user, participants__is_active=True)
            org_ids = user.organization_ids()
            if org_ids:
                org_scope |= models.Q(organization_id__in=org_ids)
            filters |= org_scope & models.Q(status__in=ORG_VISIBLE_STATES)
        else:
            filters |= models.Q(participants__user=user, participants__is_active=True)
        return self.filter(filters).distinct()

    def sla_breached(self):
        return self.filter(sla_events__state=SLAState.BREACHED).distinct()

    def by_severity(self, severity):
        return self.filter(severity=severity)


class Case(BaseModel):
    """Dossier de traitement d'une vulnerabilite (EVDP-AAAA-NNNNNN)."""

    case_id = models.CharField(max_length=32, unique=True, editable=False, db_index=True)
    report = models.OneToOneField(
        "reports.VulnerabilityReport",
        on_delete=models.PROTECT,
        related_name="case",
    )
    workflow = models.CharField(
        max_length=16, choices=WorkflowType.choices, default=WorkflowType.VDP
    )
    program = models.ForeignKey(
        "programs.Program",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="cases",
    )
    scope = models.ForeignKey(
        "programs.ProgramScope",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="cases",
        help_text=(
            "Actif du périmètre concerné, retenu au triage. Détermine la "
            "grille de récompense lorsqu'elle varie par actif."
        ),
    )
    title = models.CharField(max_length=200)
    reporter = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="reported_cases",
    )
    organization = models.ForeignKey(
        "organizations.Organization",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="cases",
    )
    product = models.CharField(max_length=200, blank=True)
    vulnerability_type = models.CharField(
        max_length=24, choices=VulnerabilityType.choices, default=VulnerabilityType.OTHER
    )
    severity = models.CharField(
        max_length=16, choices=Severity.choices, default=Severity.MEDIUM, db_index=True
    )
    cvss_score = models.DecimalField(max_digits=3, decimal_places=1, null=True, blank=True)
    cvss_vector = models.CharField(max_length=120, blank=True)
    cwe = models.ForeignKey(
        "vulnerabilities.CWE",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="cases",
    )
    cve = models.ForeignKey(
        "vulnerabilities.CVE",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="cases",
    )
    status = models.CharField(
        max_length=24,
        choices=CaseStatus.choices,
        default=CaseStatus.SUBMITTED,
        db_index=True,
    )
    status_before_exception = models.CharField(
        max_length=24,
        choices=CaseStatus.choices,
        blank=True,
        help_text="Étape d'origine à laquelle revient une sortie d'exception.",
    )
    bounty_status = models.CharField(
        max_length=24,
        choices=CaseBountyStatus.choices,
        default=CaseBountyStatus.UNDETERMINED,
        db_index=True,
        help_text="Branche prime, indépendante du statut du dossier.",
    )
    # -- Pre-requis des etapes (workflow v2) ---------------------------------
    admissibility_scope_ok = models.BooleanField("Périmètre vérifié", default=False)
    admissibility_organization_ok = models.BooleanField(
        "Organisation identifiée", default=False
    )
    admissibility_attachment_ok = models.BooleanField("Pièce jointe lisible", default=False)
    cvss_set_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="qualified_cases",
        help_text="Analyste auteur de la qualification (règle des quatre yeux).",
    )
    vendor_summary = models.TextField(
        "Version « organisation » du rapport",
        blank=True,
        help_text="Transmise à l'organisation ; l'identité du déclarant y est "
        "protégée selon le mode qu'il a choisi.",
    )
    remediation_plan = models.TextField("Plan de remédiation", blank=True)
    remediation_due_date = models.DateField("Date cible du correctif", null=True, blank=True)
    fix_description = models.TextField("Description du correctif", blank=True)
    fix_version = models.CharField(
        "Version ou date de déploiement du correctif", max_length=120, blank=True
    )
    fix_verification_notes = models.TextField(
        "Compte rendu de contre-vérification", blank=True
    )
    escalated_at = models.DateTimeField(null=True, blank=True)
    assignee = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="assigned_cases",
    )
    duplicate_of = models.ForeignKey(
        "self",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="duplicates",
    )
    priority_score = models.PositiveSmallIntegerField(default=0, db_index=True)
    tags = models.JSONField(default=list, blank=True)
    acknowledged_at = models.DateTimeField(null=True, blank=True)
    validated_at = models.DateTimeField(null=True, blank=True)
    remediated_at = models.DateTimeField(null=True, blank=True)
    disclosure_date = models.DateField(null=True, blank=True)
    closed_at = models.DateTimeField(null=True, blank=True)
    is_published = models.BooleanField(default=False)

    objects = CaseQuerySet.as_manager()

    class Meta:
        db_table = "cases"
        ordering = ["-created_at"]
        verbose_name = "Case"
        verbose_name_plural = "Cases"
        indexes = [
            models.Index(fields=["status", "severity"]),
            models.Index(fields=["organization", "status"]),
            models.Index(fields=["-priority_score", "-created_at"]),
        ]

    def __str__(self):
        return f"{self.case_id} - {self.title}"

    def save(self, *args, **kwargs):
        if not self.case_id:
            self.case_id = next_sequence(Case, "case_id", settings.EVDP["CASE_PREFIX"])
        return super().save(*args, **kwargs)

    def get_absolute_url(self):
        return reverse("coordination:case_detail", args=[self.case_id])

    # -- Etat ---------------------------------------------------------------
    @property
    def is_open(self):
        return self.status not in TERMINAL_STATES

    @property
    def is_dismissed(self):
        return self.status in DISMISSED_STATES

    @property
    def kanban_column(self):
        return kanban_column_for(self.status)

    @property
    def is_bug_bounty(self):
        return self.workflow == WorkflowType.BUG_BOUNTY

    @property
    def admissibility_complete(self):
        return (
            self.admissibility_scope_ok
            and self.admissibility_organization_ok
            and self.admissibility_attachment_ok
        )

    def current_advisory(self):
        """Advisory de travail du dossier (le plus recent non retire)."""
        from apps.disclosures.models import AdvisoryStatus

        return (
            self.advisories.exclude(status=AdvisoryStatus.RETRACTED)
            .order_by("-created_at")
            .first()
        )

    def sla_badge(self):
        """Couleur d'echeance de l'etape courante : green, orange ou red.

        Orange a partir du seuil d'alerte de la politique (75 % par defaut),
        rouge a echeance. None si aucune echeance n'est en cours.
        """
        now = timezone.now()
        events = [
            e
            for e in self.sla_events.all()
            if e.state in (SLAState.PENDING, SLAState.APPROACHING, SLAState.BREACHED)
        ]
        if not events:
            return None
        if any(e.state == SLAState.BREACHED or e.due_at <= now for e in events):
            return "red"
        if any(
            e.state == SLAState.APPROACHING or now >= e.warning_threshold() for e in events
        ):
            return "orange"
        return "green"

    def compute_priority(self):
        """Score de priorite 0-100 : severite, workflow, anciennete, SLA."""
        base = {
            Severity.CRITICAL: 80,
            Severity.HIGH: 60,
            Severity.MEDIUM: 35,
            Severity.LOW: 15,
            Severity.INFO: 5,
        }.get(self.severity, 10)
        if self.organization and self.organization.sector in ("DEFENSE", "GOVERNMENT"):
            base += 5
        age_days = (timezone.now() - self.created_at).days if self.created_at else 0
        base += min(age_days // 7, 10)
        if self.sla_events.filter(state=SLAState.BREACHED).exists():
            base += 10
        return max(0, min(base, 100))

    def refresh_priority(self):
        score = self.compute_priority()
        if score != self.priority_score:
            self.priority_score = score
            self.save(update_fields=["priority_score", "updated_at"])
        return score

    # -- Acces --------------------------------------------------------------
    def participant_user_ids(self):
        return set(self.participants.filter(is_active=True).values_list("user_id", flat=True))

    def is_participant(self, user):
        if not user or not user.is_authenticated:
            return False
        return (
            self.reporter_id == user.id
            or self.assignee_id == user.id
            or self.participants.filter(user=user, is_active=True).exists()
        )

    def is_visible_to(self, user):
        """Verification unitaire cote objet (complement du queryset)."""
        if not user or not user.is_authenticated:
            return False
        if user.can_view_all_cases:
            return True
        if self.reporter_id == user.pk:
            return True
        if user.is_organization_user:
            if self.status not in ORG_VISIBLE_STATES:
                return False
            if self.organization_id and self.organization_id in set(user.organization_ids()):
                return True
            return self.participants.filter(user=user, is_active=True).exists()
        return self.is_participant(user)


class CaseStatusHistory(BaseModel):
    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name="status_history")
    from_status = models.CharField(max_length=24, choices=CaseStatus.choices, blank=True)
    to_status = models.CharField(max_length=24, choices=CaseStatus.choices)
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="case_status_changes",
    )
    comment = models.TextField(blank=True)

    class Meta:
        db_table = "case_status_history"
        ordering = ["-created_at"]
        verbose_name = "Historique de statut"
        verbose_name_plural = "Historique des statuts"

    def __str__(self):
        return f"{self.case.case_id}: {self.from_status} -> {self.to_status}"


class CaseAssignment(BaseModel):
    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name="assignments")
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="case_assignments"
    )
    assigned_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="case_assignments_made",
    )
    is_active = models.BooleanField(default=True)
    note = models.CharField(max_length=255, blank=True)

    class Meta:
        db_table = "case_assignments"
        ordering = ["-created_at"]
        verbose_name = "Assignation"
        verbose_name_plural = "Assignations"

    def __str__(self):
        return f"{self.case.case_id} -> {self.user}"


class CaseParticipant(BaseModel):
    """Liste blanche d'acces a un case et a sa messagerie privee."""

    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name="participants")
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="case_participations"
    )
    participant_role = models.CharField(
        max_length=16, choices=ParticipantRole.choices, default=ParticipantRole.OBSERVER
    )
    is_active = models.BooleanField(default=True)
    added_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="case_participants_added",
    )

    class Meta:
        db_table = "case_participants"
        unique_together = [("case", "user")]
        ordering = ["participant_role", "created_at"]
        verbose_name = "Participant"
        verbose_name_plural = "Participants"

    def __str__(self):
        return f"{self.user} ({self.participant_role}) sur {self.case.case_id}"


class CaseMessage(BaseModel):
    """Message de la messagerie securisee attachee au case."""

    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name="messages")
    author = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="case_messages",
    )
    body = models.TextField(help_text="Markdown autorisé.")
    confidentiality = models.CharField(
        max_length=16,
        choices=Confidentiality.choices,
        default=Confidentiality.PARTICIPANTS,
        db_index=True,
    )
    is_system = models.BooleanField(default=False)
    content_hash = models.CharField(
        max_length=64,
        blank=True,
        editable=False,
        help_text="SHA-256 du contenu : preuve d'intégrité du fil de discussion.",
    )
    is_pgp_encrypted = models.BooleanField(default=False)

    class Meta:
        db_table = "case_messages"
        ordering = ["created_at"]
        verbose_name = "Message de case"
        verbose_name_plural = "Messages de case"
        indexes = [models.Index(fields=["case", "created_at"])]

    def __str__(self):
        return f"Message {self.pk} - {self.case.case_id}"

    def save(self, *args, **kwargs):
        if not self.content_hash:
            self.content_hash = hash_text(self.body)
        return super().save(*args, **kwargs)

    def is_visible_to(self, user):
        """Canaux etanches : voir `channels_visible_to`."""
        if not user or not user.is_authenticated or not self.case.is_visible_to(user):
            return False
        return self.confidentiality in channels_visible_to(user, self.case)

    def integrity_ok(self):
        return self.content_hash == hash_text(self.body)


def channels_visible_to(user, case):
    """Canaux de messagerie lisibles par `user` sur `case`.

    * declarant : le canal chercheur uniquement ;
    * organisation : le canal CSIRT <-> organisation uniquement ;
    * CSIRT : les deux canaux externes et les notes internes ;
    * coordination nationale : en plus, le canal restreint ;
    * auditeur et Super admin : aucun contenu (metadonnees seulement).
    """
    from apps.accounts.roles import Capability, Role

    if not user or not user.is_authenticated:
        return set()
    if user.is_read_only or not (
        user.can_view_all_cases or user.is_organization_user or case.reporter_id == user.pk
    ):
        return set()
    if user.can_view_all_cases:
        channels = {
            Confidentiality.PARTICIPANTS,
            Confidentiality.ORGANIZATION,
            Confidentiality.INTERNAL,
        }
        if user.role == Role.NATIONAL_COORDINATOR:
            channels.add(Confidentiality.RESTRICTED)
        return channels
    if case.reporter_id == user.pk:
        return {Confidentiality.PARTICIPANTS}
    if user.has_capability(Capability.VIEW_ORG_CASES):
        return {Confidentiality.ORGANIZATION}
    return set()


def channels_writable_by(user, case):
    """Canaux dans lesquels `user` peut ecrire sur `case`."""
    from apps.accounts.roles import Capability

    channels = channels_visible_to(user, case)
    if not user.has_capability(Capability.POST_INTERNAL_MESSAGE):
        channels -= {Confidentiality.INTERNAL, Confidentiality.RESTRICTED}
    return channels


class CaseTimelineEvent(BaseModel):
    """Evenement de la chronologie du case (affichage graphique + advisory)."""

    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name="timeline")
    event_type = models.CharField(
        max_length=32, choices=TimelineEventType.choices, default=TimelineEventType.NOTE
    )
    label = models.CharField(max_length=255)
    occurred_at = models.DateTimeField(default=timezone.now, db_index=True)
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="timeline_events",
    )
    is_public = models.BooleanField(
        default=False,
        help_text="Seuls les événements publics peuvent alimenter un advisory.",
    )
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        db_table = "case_timeline_events"
        ordering = ["occurred_at", "created_at"]
        verbose_name = "Evenement de chronologie"
        verbose_name_plural = "Chronologie"

    def __str__(self):
        return f"{self.occurred_at:%Y-%m-%d} {self.label}"


class SLAEvent(BaseModel):
    """Echeance SLA suivie automatiquement par Celery Beat."""

    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name="sla_events")
    kind = models.CharField(max_length=24, choices=SLAKind.choices)
    policy = models.ForeignKey(
        SLAPolicy, null=True, blank=True, on_delete=models.SET_NULL, related_name="events"
    )
    due_at = models.DateTimeField(db_index=True)
    state = models.CharField(
        max_length=16, choices=SLAState.choices, default=SLAState.PENDING, db_index=True
    )
    satisfied_at = models.DateTimeField(null=True, blank=True)
    warned_at = models.DateTimeField(null=True, blank=True)
    breached_at = models.DateTimeField(null=True, blank=True)
    suspended_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "sla_events"
        unique_together = [("case", "kind")]
        ordering = ["due_at"]
        verbose_name = "Echeance SLA"
        verbose_name_plural = "Echeances SLA"

    def __str__(self):
        return f"{self.case.case_id} {self.kind} ({self.state})"

    @property
    def is_overdue(self):
        return self.state == SLAState.PENDING and self.due_at < timezone.now()

    @property
    def remaining(self):
        return self.due_at - timezone.now()

    def mark_met(self):
        if self.state in (SLAState.PENDING, SLAState.APPROACHING):
            self.state = SLAState.MET
            self.satisfied_at = timezone.now()
            self.save(update_fields=["state", "satisfied_at", "updated_at"])

    def warning_threshold(self):
        policy = self.policy or SLAPolicy.get_default()
        ratio = (policy.warning_ratio if policy else 75) / 100
        total = self.due_at - self.created_at
        return self.created_at + timedelta(seconds=total.total_seconds() * ratio)


class CaseTrackingToken(BaseModel):
    """Jeton de suivi pour un declarant sans compte (avec ou sans email).

    Permet de consulter un statut simplifie du dossier en lecture seule, sans
    authentification. Seul le hash est conserve (meme principe que les cles
    d'API) : une fuite de la base ne permet pas de rejouer les jetons.
    """

    case = models.OneToOneField(Case, on_delete=models.CASCADE, related_name="tracking_token")
    token_hash = models.CharField(max_length=64, unique=True, db_index=True)
    expires_at = models.DateTimeField()
    last_accessed_at = models.DateTimeField(null=True, blank=True)
    access_count = models.PositiveIntegerField(default=0)

    class Meta:
        db_table = "case_tracking_tokens"
        verbose_name = "Jeton de suivi"
        verbose_name_plural = "Jetons de suivi"

    def __str__(self):
        return f"Suivi {self.case.case_id}"

    @property
    def is_valid(self):
        return timezone.now() < self.expires_at

    def record_access(self):
        self.last_accessed_at = timezone.now()
        self.access_count = models.F("access_count") + 1
        self.save(update_fields=["last_accessed_at", "access_count", "updated_at"])


def validate_no_self_duplicate(case):
    if case.duplicate_of_id and case.duplicate_of_id == case.id:
        raise ValidationError("Un case ne peut pas être le doublon de lui-même.")
