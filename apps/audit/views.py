"""Consultation du journal d'audit (roles habilites uniquement)."""

from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.shortcuts import render

from apps.accounts.permissions import require_capability
from apps.accounts.roles import Capability

from .models import AuditAction, AuditLog


@login_required
@require_capability(Capability.VIEW_AUDIT_LOG)
def audit_list(request):
    entries = AuditLog.objects.select_related("actor")
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
