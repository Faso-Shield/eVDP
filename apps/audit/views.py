"""Consultation du journal d'audit (roles habilites uniquement)."""

from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.shortcuts import render

from apps.accounts.permissions import require_roles
from apps.accounts.roles import Capability, Role

from .models import AuditAction, AuditLog

#: Objets metier : leur trace releve du journal d'audit complet, pas des
#: logs techniques ouverts au super admin.
CASE_CONTENT_OBJECTS = (
    "Case",
    "VulnerabilityReport",
    "Attachment",
    "CaseMessage",
    "Bounty",
    "BountyPayment",
    "WalletEntry",
    "Advisory",
)


@login_required
@require_roles(Role.SUPER_ADMIN, Role.NATIONAL_COORDINATOR, Role.AUDITOR)
def audit_list(request):
    entries = AuditLog.objects.select_related("actor")
    if not request.user.has_capability(Capability.VIEW_AUDIT_LOG):
        # Super admin : logs techniques seulement (comptes, organisations,
        # programmes, configuration), jamais la trace des dossiers.
        entries = entries.exclude(object_type__in=CASE_CONTENT_OBJECTS)
    action = request.GET.get("action", "").strip()
    actor = request.GET.get("actor", "").strip()
    obj = request.GET.get("object", "").strip()
    if action:
        entries = entries.filter(action=action)
    if actor:
        entries = entries.filter(actor_label__icontains=actor)
    if obj:
        entries = entries.filter(object_repr__icontains=obj)
    page = Paginator(entries, 50).get_page(request.GET.get("page"))
    return render(
        request,
        "audit/list.html",
        {"page_obj": page, "actions": AuditAction.choices, "filters": request.GET},
    )
