"""API REST v1 de eVDP.

Toutes les listes partent d'un queryset filtre par le perimetre de
l'utilisateur : aucune vue ne renvoie de donnee hors habilitation.
"""

from django.core.exceptions import PermissionDenied
from django.shortcuts import get_object_or_404
from drf_spectacular.utils import OpenApiResponse, extend_schema
from rest_framework import mixins, status, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import NotFound
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response

from apps.accounts.permissions import HasCapability, ReadOnlyForAuditors
from apps.accounts.roles import Capability
from apps.attachments.services import store_attachment
from apps.audit.models import AuditAction
from apps.audit.services import log_action
from apps.bounty.models import Bounty
from apps.coordination.constants import Confidentiality
from apps.coordination.models import Case
from apps.coordination.selectors import search_cases, visible_cases
from apps.coordination.services import post_message, transition_case, visible_messages
from apps.coordination.workflow import TransitionNotAllowed
from apps.disclosures.models import Advisory
from apps.organizations.models import Organization, OrganizationStatus
from apps.programs.models import Program
from apps.reports.services import submit_report
from apps.researchers.models import IdentityMode, ResearcherProfile
from apps.vulnerabilities.constants import ReportSource

from .serializers import (
    AdvisorySerializer,
    AttachmentSerializer,
    BountySerializer,
    CaseDetailSerializer,
    CaseListSerializer,
    CaseMessageSerializer,
    CaseUpdateSerializer,
    OrganizationSerializer,
    ProgramSerializer,
    ProgramWriteSerializer,
    ReportSubmissionSerializer,
    ResearcherSerializer,
)


class ReportViewSet(
    mixins.CreateModelMixin,
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    mixins.UpdateModelMixin,
    viewsets.GenericViewSet,
):
    """Soumission et suivi des rapports (exposes via leur Case)."""

    permission_classes = [IsAuthenticated, ReadOnlyForAuditors]
    lookup_field = "case_id"
    lookup_value_regex = r"[A-Za-z0-9\-]+"
    throttle_scope = "report-submission"
    filterset_fields = ["status", "severity", "workflow"]
    search_fields = ["case_id", "title", "product"]
    ordering_fields = ["created_at", "priority_score", "severity"]

    def get_queryset(self):
        return visible_cases(self.request.user)

    def get_serializer_class(self):
        if self.action == "create":
            return ReportSubmissionSerializer
        if self.action in ("update", "partial_update"):
            return CaseUpdateSerializer
        if self.action == "retrieve":
            return CaseDetailSerializer
        return CaseListSerializer

    def get_throttles(self):
        if self.action != "create":
            self.throttle_scope = "authenticated"
        return super().get_throttles()

    @extend_schema(
        request=ReportSubmissionSerializer,
        responses={201: CaseDetailSerializer},
        description="Soumet un rapport de vulnerabilite et cree le Case associe.",
    )
    def create(self, request, *args, **kwargs):
        serializer = ReportSubmissionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        report = serializer.save(reporter=request.user)
        case = submit_report(
            report, request=request, source=ReportSource.API, reporter=request.user
        )
        return Response(CaseDetailSerializer(case).data, status=status.HTTP_201_CREATED)

    def get_object(self):
        case = get_object_or_404(
            Case.objects.select_related("report"),
            case_id=self.kwargs["case_id"].upper(),
        )
        if not case.is_visible_to(self.request.user):
            raise NotFound("Ressource introuvable.")
        return case

    def perform_update(self, serializer):
        if not self.request.user.has_capability(Capability.SET_SEVERITY):
            raise PermissionDenied("Capacite requise pour modifier ce dossier.")
        case = serializer.save()
        log_action(
            AuditAction.CASE_UPDATED,
            actor=self.request.user,
            obj=case,
            request=self.request,
            via="api",
        )

    @extend_schema(
        request=CaseMessageSerializer,
        responses={200: CaseMessageSerializer(many=True), 201: CaseMessageSerializer},
    )
    @action(detail=True, methods=["get", "post"], url_path="messages")
    def messages(self, request, case_id=None):
        case = self.get_object()
        if request.method == "GET":
            queryset = visible_messages(case, request.user)
            return Response(CaseMessageSerializer(queryset, many=True).data)

        serializer = CaseMessageSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            message = post_message(
                case,
                request.user,
                serializer.validated_data["body"],
                confidentiality=serializer.validated_data.get(
                    "confidentiality", Confidentiality.PARTICIPANTS
                ),
                request=request,
            )
        except PermissionDenied as exc:
            # Ne pas confirmer l'existence d'un fil auquel l'appelant n'a pas droit.
            raise NotFound("Ressource introuvable.") from exc
        return Response(CaseMessageSerializer(message).data, status=status.HTTP_201_CREATED)

    @extend_schema(
        request={
            "multipart/form-data": {
                "type": "object",
                "properties": {
                    "file": {"type": "string", "format": "binary"},
                    "description": {"type": "string"},
                },
            }
        },
        responses={201: AttachmentSerializer},
    )
    @action(
        detail=True,
        methods=["get", "post"],
        url_path="attachments",
        parser_classes=[MultiPartParser, FormParser],
    )
    def attachments(self, request, case_id=None):
        case = self.get_object()
        if request.method == "GET":
            return Response(AttachmentSerializer(case.attachments.all(), many=True).data)
        uploaded = request.FILES.get("file")
        if uploaded is None:
            return Response(
                {"file": ["Fichier manquant."]}, status=status.HTTP_400_BAD_REQUEST
            )
        attachment = store_attachment(
            uploaded,
            request.user,
            case=case,
            description=request.data.get("description", ""),
            request=request,
        )
        return Response(AttachmentSerializer(attachment).data, status=status.HTTP_201_CREATED)

    @extend_schema(
        request={
            "application/json": {
                "type": "object",
                "properties": {
                    "target_status": {"type": "string"},
                    "comment": {"type": "string"},
                },
            }
        },
        responses={
            200: CaseDetailSerializer,
            400: OpenApiResponse(description="Transition interdite"),
        },
    )
    @action(detail=True, methods=["post"], url_path="transition")
    def transition(self, request, case_id=None):
        case = self.get_object()
        target = request.data.get("target_status", "")
        try:
            transition_case(
                case,
                target,
                request.user,
                comment=request.data.get("comment", ""),
                request=request,
            )
        except TransitionNotAllowed as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        return Response(CaseDetailSerializer(case).data)


class ProgramViewSet(viewsets.ModelViewSet):
    serializer_class = ProgramSerializer
    lookup_field = "slug"
    filterset_fields = ["program_type", "status"]
    search_fields = ["name", "summary"]

    def get_permissions(self):
        if self.action in ("list", "retrieve"):
            return [AllowAny()]
        return [IsAuthenticated(), HasCapability(), ReadOnlyForAuditors()]

    @property
    def required_capabilities(self):
        return [Capability.MANAGE_PROGRAM, Capability.MANAGE_ALL_ORGANIZATIONS]

    def get_throttles(self):
        self.throttle_scope = (
            "anon-read" if not self.request.user.is_authenticated else "authenticated"
        )
        return super().get_throttles()

    def get_serializer_class(self):
        if self.action in ("create", "update", "partial_update"):
            return ProgramWriteSerializer
        return ProgramSerializer

    def get_queryset(self):
        user = self.request.user
        base = Program.objects.select_related("organization").prefetch_related("scopes")
        if not user.is_authenticated:
            return base.public()
        if user.is_national:
            return base
        return base.public() | base.for_organizations(user.organization_ids())

    def perform_create(self, serializer):
        program = serializer.save(created_by=self.request.user)
        log_action(
            AuditAction.PROGRAM_CREATED,
            actor=self.request.user,
            obj=program,
            request=self.request,
            via="api",
        )


class AdvisoryViewSet(
    mixins.ListModelMixin, mixins.RetrieveModelMixin, viewsets.GenericViewSet
):
    """Advisories publies : lecture publique."""

    serializer_class = AdvisorySerializer
    permission_classes = [AllowAny]
    lookup_field = "advisory_id"
    lookup_value_regex = r"[A-Za-z0-9\-]+"
    filterset_fields = ["severity"]
    search_fields = ["title", "summary", "product"]
    throttle_scope = "anon-read"

    def get_queryset(self):
        return (
            Advisory.objects.visible_to(self.request.user)
            .select_related("organization", "cwe", "cve")
            .prefetch_related("timeline")
        )

    def get_object(self):
        return get_object_or_404(
            self.get_queryset(), advisory_id=self.kwargs["advisory_id"].upper()
        )


class OrganizationViewSet(
    mixins.ListModelMixin, mixins.RetrieveModelMixin, viewsets.GenericViewSet
):
    serializer_class = OrganizationSerializer
    permission_classes = [AllowAny]
    lookup_field = "slug"
    search_fields = ["name", "acronym"]
    filterset_fields = ["sector", "organization_type"]
    throttle_scope = "anon-read"

    def get_queryset(self):
        user = self.request.user
        if user.is_authenticated and user.is_national:
            return Organization.objects.all()
        return Organization.objects.filter(status=OrganizationStatus.ACTIVE)


class ResearcherViewSet(
    mixins.ListModelMixin, mixins.RetrieveModelMixin, viewsets.GenericViewSet
):
    """Annuaire des chercheurs : seuls les profils publics sont exposes."""

    serializer_class = ResearcherSerializer
    permission_classes = [AllowAny]
    lookup_field = "slug"
    throttle_scope = "anon-read"

    def get_queryset(self):
        return (
            ResearcherProfile.objects.filter(is_public_profile=True)
            .exclude(identity_mode=IdentityMode.PRIVATE)
            .select_related("user")
        )


class BountyViewSet(mixins.ListModelMixin, mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    serializer_class = BountySerializer
    permission_classes = [IsAuthenticated]
    throttle_scope = "authenticated"
    filterset_fields = ["status", "severity"]

    def get_queryset(self):
        user = self.request.user
        queryset = Bounty.objects.select_related("case")
        # Generation du schema OpenAPI : aucun utilisateur authentifie.
        if not user.is_authenticated:
            return queryset.none()
        if user.is_national:
            return queryset
        case_ids = Case.objects.visible_to(user).values_list("id", flat=True)
        return queryset.filter(case_id__in=case_ids)


class SearchView(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]
    throttle_scope = "authenticated"

    @extend_schema(responses={200: CaseListSerializer(many=True)})
    def list(self, request):
        query = (request.query_params.get("q") or "").strip()
        cases = search_cases(request.user, query=query)[:50] if query else []
        return Response(CaseListSerializer(cases, many=True).data)
