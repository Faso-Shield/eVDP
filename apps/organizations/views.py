"""Vues des organisations."""

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect, render

from apps.accounts.permissions import require_capability, require_not_read_only
from apps.accounts.roles import Capability
from apps.audit.models import AuditAction
from apps.audit.services import log_action
from apps.coordination import selectors

from .forms import OrganizationForm
from .models import Organization, OrganizationStatus


def organization_list(request):
    """Annuaire public des organisations participantes."""
    queryset = Organization.objects.filter(
        status=OrganizationStatus.ACTIVE, accepts_vdp=True
    ).order_by("name")
    query = (request.GET.get("q") or "").strip()
    if query:
        queryset = queryset.filter(name__icontains=query)
    page = Paginator(queryset, 24).get_page(request.GET.get("page"))
    return render(request, "organizations/list.html", {"page_obj": page, "query": query})


def organization_detail(request, slug):
    organization = get_object_or_404(Organization, slug=slug)
    if organization.status != OrganizationStatus.ACTIVE and not (
        request.user.is_authenticated and request.user.is_national
    ):
        raise Http404("Organisation introuvable.")
    return render(
        request,
        "organizations/detail.html",
        {
            "organization": organization,
            "programs": organization.programs.filter(status="ACTIVE"),
            "advisories": organization.advisories.filter(status="PUBLISHED")[:10],
        },
    )


@login_required
@require_capability(Capability.MANAGE_ORGANIZATION, Capability.MANAGE_ALL_ORGANIZATIONS)
def organization_manage_list(request):
    if request.user.has_capability(Capability.MANAGE_ALL_ORGANIZATIONS):
        queryset = Organization.objects.all()
    else:
        queryset = Organization.objects.filter(id__in=request.user.organization_ids())
    return render(
        request,
        "organizations/manage_list.html",
        {"organizations": queryset.order_by("name")},
    )


@login_required
@require_not_read_only
@require_capability(Capability.MANAGE_ALL_ORGANIZATIONS)
def organization_create(request):
    if request.method == "POST":
        form = OrganizationForm(request.POST)
        if form.is_valid():
            organization = form.save(commit=False)
            organization.created_by = request.user
            organization.save()
            log_action(
                AuditAction.ORGANIZATION_CREATED,
                actor=request.user,
                obj=organization,
                request=request,
            )
            messages.success(request, "Organisation creee.")
            return redirect("organizations:manage", slug=organization.slug)
    else:
        form = OrganizationForm()
    return render(request, "organizations/form.html", {"form": form, "creating": True})


@login_required
@require_not_read_only
@require_capability(Capability.MANAGE_ORGANIZATION, Capability.MANAGE_ALL_ORGANIZATIONS)
def organization_manage(request, slug):
    organization = get_object_or_404(Organization, slug=slug)
    if not request.user.has_capability(Capability.MANAGE_ALL_ORGANIZATIONS):
        if organization.id not in set(request.user.organization_ids()):
            raise Http404("Organisation introuvable.")

    if request.method == "POST":
        form = OrganizationForm(request.POST, instance=organization)
        if form.is_valid():
            form.save()
            log_action(
                AuditAction.ORGANIZATION_UPDATED,
                actor=request.user,
                obj=organization,
                request=request,
            )
            messages.success(request, "Organisation mise a jour.")
            return redirect("organizations:manage", slug=organization.slug)
    else:
        form = OrganizationForm(instance=organization)

    return render(
        request,
        "organizations/manage.html",
        {
            "organization": organization,
            "form": form,
            "members": organization.members.select_related("user").filter(is_active=True),
            "contacts": organization.security_contacts.all(),
            "programs": organization.programs.all(),
            "cases": selectors.visible_cases(request.user).filter(organization=organization)[
                :15
            ],
        },
    )
