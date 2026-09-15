"""Points d'entree CSAF : import de documents, export d'advisories publies."""

from django.core.exceptions import ValidationError
from django.http import Http404
from django.shortcuts import get_object_or_404
from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.accounts.permissions import HasCapability
from apps.accounts.roles import Capability
from apps.audit.models import AuditAction
from apps.audit.services import log_action
from apps.disclosures.models import Advisory
from apps.organizations.models import Organization
from apps.programs.models import Program

from .services import export_advisory_to_csaf, import_csaf

MAX_DOCUMENT_BYTES = 2 * 1024 * 1024


class CsafImportView(APIView):
    """POST /api/v1/import/csaf/ - import d'un document CSAF 2.0."""

    permission_classes = [IsAuthenticated, HasCapability]
    required_capability = Capability.IMPORT_CSAF
    throttle_scope = "authenticated"

    @extend_schema(
        request={"application/json": {"type": "object"}},
        responses={201: {"type": "object"}},
        description="Importe un document CSAF 2.0 et cree les cases correspondants.",
    )
    def post(self, request):
        payload = request.data
        document = payload.get("document_json", payload)

        if len(str(document)) > MAX_DOCUMENT_BYTES:
            return Response(
                {"detail": "Document CSAF trop volumineux."},
                status=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            )

        organization = None
        program = None
        if payload.get("organization_slug"):
            organization = Organization.objects.filter(
                slug=payload["organization_slug"]
            ).first()
        if payload.get("program_slug"):
            program = Program.objects.filter(slug=payload["program_slug"]).first()

        try:
            cases = import_csaf(
                document,
                request.user,
                organization=organization,
                program=program,
                request=request,
            )
        except ValidationError as exc:
            return Response({"detail": exc.messages}, status=status.HTTP_400_BAD_REQUEST)

        log_action(
            AuditAction.CSAF_IMPORTED,
            actor=request.user,
            request=request,
            object_type="CSAF",
            cases=[case.case_id for case in cases],
        )
        return Response(
            {
                "imported": len(cases),
                "cases": [case.case_id for case in cases],
            },
            status=status.HTTP_201_CREATED,
        )


class CsafExportView(APIView):
    """GET /api/v1/export/csaf/{advisory_id}/ - export CSAF 2.0.

    Lecture publique, comme la fiche advisory elle-meme : le queryset ne
    contient que des advisories effectivement publies. Un identifiant inconnu,
    en brouillon ou retire renvoie 404 - jamais 403.
    """

    permission_classes = [AllowAny]
    renderer_classes = [JSONRenderer]
    throttle_scope = "anon-read"

    @extend_schema(
        responses={200: {"type": "object"}},
        description=(
            "Exporte un advisory publie au format CSAF 2.0. Seuls les champs "
            "publics de l'advisory sont exposes."
        ),
    )
    def get(self, request, advisory_id):
        advisory = get_object_or_404(
            Advisory.objects.published().select_related("organization", "cwe", "cve"),
            advisory_id=advisory_id.upper(),
        )
        try:
            document = export_advisory_to_csaf(advisory)
        except ValidationError as exc:
            # Garde-fou : le queryset ne devrait jamais laisser passer un
            # advisory non publiable. On ne renseigne pas l'appelant davantage.
            raise Http404("Advisory introuvable.") from exc

        log_action(
            AuditAction.EXPORT_GENERATED,
            actor=request.user if request.user.is_authenticated else None,
            obj=advisory,
            request=request,
            export_format="csaf-2.0",
        )
        response = Response(document)
        response["Content-Disposition"] = f'attachment; filename="{advisory.advisory_id}.json"'
        return response
