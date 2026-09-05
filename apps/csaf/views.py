"""Point d'entree d'import CSAF."""

from django.core.exceptions import ValidationError
from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.accounts.permissions import HasCapability
from apps.accounts.roles import Capability
from apps.audit.models import AuditAction
from apps.audit.services import log_action
from apps.organizations.models import Organization
from apps.programs.models import Program

from .services import import_csaf

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
