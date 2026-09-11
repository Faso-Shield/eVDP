"""Serialiseurs de l'API v1.

Regle anti mass-assignment : chaque serialiseur declare explicitement ses
champs et marque en lecture seule tout ce qui releve du workflow, du RBAC ou
de l'identite. Aucun champ sensible n'est modifiable par le client.
"""

from django.core.exceptions import ValidationError as DjangoValidationError
from drf_spectacular.utils import OpenApiTypes, extend_schema_field
from rest_framework import serializers

from apps.bounty.models import Bounty
from apps.coordination.models import Case, CaseMessage
from apps.disclosures.models import Advisory
from apps.organizations.models import Organization
from apps.programs.models import Program, ProgramScope, RewardTier
from apps.reports.models import VulnerabilityReport
from apps.researchers.models import ResearcherProfile
from apps.vulnerabilities.cvss import CVSSError, base_score


class OrganizationSerializer(serializers.ModelSerializer):
    organization_type_label = serializers.CharField(
        source="get_organization_type_display", read_only=True
    )

    class Meta:
        model = Organization
        fields = [
            "id",
            "name",
            "acronym",
            "slug",
            "organization_type",
            "organization_type_label",
            "sector",
            "domain",
            "website",
            "status",
            "accepts_vdp",
        ]
        read_only_fields = fields


class ProgramScopeSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProgramScope
        fields = [
            "id",
            "in_scope",
            "target_type",
            "identifier",
            "application",
            "platform",
            "environment",
            "priority",
            "description",
            "is_active",
        ]


class RewardTierSerializer(serializers.ModelSerializer):
    """Palier de recompense. `scope` vide signifie : grille par defaut."""

    scope = serializers.CharField(
        source="scope.identifier", read_only=True, default=None
    )

    class Meta:
        model = RewardTier
        fields = ["severity", "scope", "min_amount", "max_amount", "description"]


class ProgramSerializer(serializers.ModelSerializer):
    organization = OrganizationSerializer(read_only=True)
    scopes = ProgramScopeSerializer(many=True, read_only=True)
    reward_tiers = serializers.SerializerMethodField()

    class Meta:
        model = Program
        fields = [
            "id",
            "name",
            "slug",
            "program_type",
            "organization",
            "status",
            "confidentiality",
            "summary",
            "description",
            "rules",
            "out_of_scope_notes",
            "safe_harbor",
            "disclosure_policy",
            "eligibility",
            "starts_on",
            "ends_on",
            "contact_email",
            "disclosure_delay_days",
            "scopes",
            "reward_tiers",
            "created_at",
        ]
        read_only_fields = ["id", "slug", "created_at", "organization"]

    @extend_schema_field(RewardTierSerializer(many=True))
    def get_reward_tiers(self, obj):
        policy = getattr(obj, "reward_policy", None)
        if not policy or not policy.is_active:
            return []
        return RewardTierSerializer(
            policy.tiers.select_related("scope"), many=True
        ).data


class ProgramWriteSerializer(serializers.ModelSerializer):
    class Meta:
        model = Program
        fields = [
            "name",
            "program_type",
            "organization",
            "status",
            "confidentiality",
            "summary",
            "description",
            "rules",
            "out_of_scope_notes",
            "safe_harbor",
            "disclosure_policy",
            "eligibility",
            "starts_on",
            "ends_on",
            "contact_email",
            "disclosure_delay_days",
            # Deux conditions de participation, exposees comme dans le
            # formulaire : sans elles, un Bug Bounty cree par l'API resterait
            # sur le defaut `allows_anonymous_reports=True`, que son propre
            # invariant refuse. Le client n'aurait aucun moyen de corriger.
            "requires_verified_email",
            "allows_anonymous_reports",
        ]

    def validate(self, attrs):
        """Fait passer l'ecriture API par Program.clean().

        Un ModelSerializer ne declenche pas la validation du modele : seul le
        formulaire d'administration y passait. L'API creait donc des
        programmes que le formulaire refuse : dates inversees, ou Bug
        Bounty configure pour l'anonymat.

        `slug` est exclu : il est engendre par `Program.save()` et vaut ""
        jusque-la, ce que son unicite refuserait.
        """
        instance = self.instance or Program()
        for champ, valeur in attrs.items():
            setattr(instance, champ, valeur)
        try:
            instance.full_clean(exclude=["slug"])
        except DjangoValidationError as exc:
            raise serializers.ValidationError(exc.message_dict) from exc
        return attrs


class ReportSubmissionSerializer(serializers.ModelSerializer):
    """Soumission d'un rapport via l'API.

    `reporter`, `status`, `source` et tous les champs de traitement sont
    imposes par le serveur : ils ne figurent pas dans `fields`.
    """

    class Meta:
        model = VulnerabilityReport
        fields = [
            "title",
            "product",
            "affected_organization",
            "affected_organization_name",
            "program",
            "target_url",
            "vulnerability_type",
            "cwe",
            "cvss_vector",
            "reported_severity",
            "description",
            "steps_to_reproduce",
            "impact",
            "proof_of_concept",
            "recommendations",
            "affected_version",
            "fixed_version",
            "environment",
            "external_reference",
            "requests_cve",
            "wants_credit",
            "is_anonymous",
            "pgp_payload",
        ]

    def validate_cvss_vector(self, value):
        if not value:
            return ""
        try:
            base_score(value)
        except CVSSError as exc:
            raise serializers.ValidationError(str(exc)) from exc
        return value

    def validate_description(self, value):
        if len(value.strip()) < 30:
            raise serializers.ValidationError(
                "La description doit comporter au moins 30 caracteres."
            )
        return value

    def validate(self, attrs):
        program = attrs.get("program")
        if program is not None and not program.is_open:
            raise serializers.ValidationError(
                {"program": "Ce programme n'accepte plus de soumissions."}
            )
        if not any(
            [
                attrs.get("affected_organization"),
                attrs.get("affected_organization_name"),
                program,
            ]
        ):
            raise serializers.ValidationError(
                "Precisez l'organisation affectee ou un programme."
            )
        return attrs


class CaseListSerializer(serializers.ModelSerializer):
    organization = serializers.CharField(
        source="organization.name", default=None, read_only=True
    )
    status_label = serializers.CharField(source="get_status_display", read_only=True)
    severity_label = serializers.CharField(source="get_severity_display", read_only=True)

    class Meta:
        model = Case
        fields = [
            "id",
            "case_id",
            "title",
            "workflow",
            "status",
            "status_label",
            "severity",
            "severity_label",
            "cvss_score",
            "organization",
            "priority_score",
            "disclosure_date",
            "created_at",
            "updated_at",
        ]
        read_only_fields = fields


class CaseDetailSerializer(CaseListSerializer):
    report = serializers.SerializerMethodField()
    cwe = serializers.CharField(source="cwe.code", default=None, read_only=True)
    cve = serializers.CharField(source="cve.cve_id", default=None, read_only=True)
    timeline = serializers.SerializerMethodField()
    assignee = serializers.CharField(
        source="assignee.display_name", default=None, read_only=True
    )

    class Meta(CaseListSerializer.Meta):
        fields = CaseListSerializer.Meta.fields + [
            "product",
            "vulnerability_type",
            "cvss_vector",
            "cwe",
            "cve",
            "assignee",
            "tags",
            "report",
            "timeline",
            "acknowledged_at",
            "validated_at",
            "remediated_at",
            "closed_at",
        ]
        read_only_fields = fields

    @extend_schema_field(OpenApiTypes.OBJECT)
    def get_report(self, obj):
        report = obj.report
        return {
            "title": report.title,
            "description": report.description,
            "steps_to_reproduce": report.steps_to_reproduce,
            "impact": report.impact,
            "proof_of_concept": report.proof_of_concept,
            "recommendations": report.recommendations,
            "target_url": report.target_url,
            "affected_version": report.affected_version,
            "fixed_version": report.fixed_version,
            "environment": report.environment,
            "is_pgp_encrypted": report.is_pgp_encrypted,
            "reporter": report.reporter_display,
        }

    @extend_schema_field(serializers.ListField(child=serializers.DictField()))
    def get_timeline(self, obj):
        return [
            {
                "occurred_at": event.occurred_at,
                "event_type": event.event_type,
                "label": event.label,
            }
            for event in obj.timeline.all()
        ]


class CaseUpdateSerializer(serializers.ModelSerializer):
    """Champs modifiables par un analyste habilite (liste restreinte)."""

    class Meta:
        model = Case
        fields = ["severity", "cvss_vector", "cwe", "cve", "tags", "product"]

    def validate_cvss_vector(self, value):
        if not value:
            return ""
        try:
            base_score(value)
        except CVSSError as exc:
            raise serializers.ValidationError(str(exc)) from exc
        return value


class CaseMessageSerializer(serializers.ModelSerializer):
    author = serializers.CharField(source="author.display_name", default=None, read_only=True)

    class Meta:
        model = CaseMessage
        fields = [
            "id",
            "author",
            "body",
            "confidentiality",
            "is_system",
            "content_hash",
            "created_at",
        ]
        read_only_fields = ["id", "author", "is_system", "content_hash", "created_at"]


class AttachmentSerializer(serializers.Serializer):
    id = serializers.UUIDField(read_only=True)
    original_filename = serializers.CharField(read_only=True)
    size = serializers.IntegerField(read_only=True)
    sha256 = serializers.CharField(read_only=True)
    scan_status = serializers.CharField(read_only=True)
    created_at = serializers.DateTimeField(read_only=True)


class AdvisorySerializer(serializers.ModelSerializer):
    organization = serializers.CharField(
        source="organization.name", default=None, read_only=True
    )
    cwe = serializers.CharField(source="cwe.code", default=None, read_only=True)
    cve = serializers.CharField(source="cve.cve_id", default=None, read_only=True)
    timeline = serializers.SerializerMethodField()

    class Meta:
        model = Advisory
        fields = [
            "id",
            "advisory_id",
            "title",
            "summary",
            "organization",
            "product",
            "affected_versions",
            "fixed_versions",
            "description",
            "impact",
            "solution",
            "workaround",
            "severity",
            "cvss_score",
            "cvss_vector",
            "cwe",
            "cve",
            "credit",
            "published_at",
            "timeline",
        ]
        read_only_fields = fields

    @extend_schema_field(serializers.ListField(child=serializers.DictField()))
    def get_timeline(self, obj):
        return [
            {"date": entry.happened_on, "label": entry.label} for entry in obj.timeline.all()
        ]


class ResearcherSerializer(serializers.ModelSerializer):
    identity = serializers.SerializerMethodField()

    class Meta:
        model = ResearcherProfile
        fields = [
            "id",
            "slug",
            "identity",
            "country",
            "affiliation",
            "reputation",
            "reports_submitted",
            "reports_validated",
            "critical_reports",
        ]
        read_only_fields = fields

    @extend_schema_field(OpenApiTypes.STR)
    def get_identity(self, obj):
        return obj.public_identity()


class BountySerializer(serializers.ModelSerializer):
    case_id = serializers.CharField(source="case.case_id", read_only=True)

    class Meta:
        model = Bounty
        fields = [
            "id",
            "case_id",
            "severity",
            "proposed_amount",
            "approved_amount",
            "currency",
            "status",
            "created_at",
            "decided_at",
        ]
        read_only_fields = fields
