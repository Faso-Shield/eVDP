"""Vues des organisations."""

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse

from apps.accounts.permissions import require_capability, require_not_read_only
from apps.accounts.roles import Capability, Role
from apps.audit.models import AuditAction
from apps.audit.services import log_action
from apps.coordination import selectors
from apps.dashboard.maps import can_view_map, is_national_scope

from .forms import OrganizationForm, OrganizationMemberForm
from .models import Organization, OrganizationMember, OrganizationStatus


def _map_url(user, organization):
    """Lien vers l'organisation sur la carte, pour qui peut ouvrir la carte.

    Meme garde que dashboard.views.map_view : un lien qui menerait a un refus
    n'est pas propose. Un DSI n'a de lien que vers ses propres organisations :
    sa carte ne montre qu'elles.
    """
    if not can_view_map(user):
        return None
    if not is_national_scope(user) and organization.id not in set(user.organization_ids()):
        return None
    return f"{reverse('dashboard:map')}?org={organization.id}"


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
            messages.success(request, "Organisation créée.")
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
            messages.success(request, "Organisation mise à jour.")
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
            "member_form": OrganizationMemberForm(),
            "map_url": _map_url(request.user, organization),
        },
    )


@login_required
@require_not_read_only
@require_capability(Capability.MANAGE_ORGANIZATION, Capability.MANAGE_ALL_ORGANIZATIONS)
def organization_member_add(request, slug):
    organization = get_object_or_404(Organization, slug=slug)
    if not request.user.has_capability(Capability.MANAGE_ALL_ORGANIZATIONS):
        if organization.id not in set(request.user.organization_ids()):
            raise Http404("Organisation introuvable.")

    if request.method == "POST":
        form = OrganizationMemberForm(request.POST)
        if form.is_valid():
            invited = form.user is None
            if invited:
                from apps.accounts.models import User

                target_user = User.objects.create_user(
                    email=form.cleaned_data["email"],
                    password=None,
                    full_name=form.cleaned_data["full_name"],
                    role=Role.ORGANIZATION_MANAGER,
                )
                log_action(
                    AuditAction.USER_CREATED,
                    actor=request.user,
                    obj=target_user,
                    request=request,
                    role=target_user.role,
                    invited_for_organization=organization.slug,
                )
            else:
                target_user = form.user

            member, created = OrganizationMember.objects.get_or_create(
                organization=organization,
                user=target_user,
                defaults={
                    "membership_role": form.cleaned_data["membership_role"],
                    "is_primary": form.cleaned_data["is_primary"],
                    "invited_by": request.user,
                },
            )
            if created:
                log_action(
                    AuditAction.MEMBERSHIP_CHANGED,
                    actor=request.user,
                    obj=organization,
                    request=request,
                    member_email=target_user.email,
                    membership_role=member.membership_role,
                )
                if invited:
                    from apps.accounts.views import send_password_setup_link

                    send_password_setup_link(
                        target_user,
                        title=f"Invitation à rejoindre {organization.name} sur eVDP",
                        body=(
                            f"{request.user.display_name or request.user.email} vous a "
                            f"rattaché à {organization.name} sur eVDP. Choisissez votre "
                            "mot de passe pour activer votre compte."
                        ),
                    )
                    messages.success(
                        request,
                        f"Invitation envoyée à {target_user.email} — un lien pour "
                        "choisir son mot de passe lui a été transmis.",
                    )
                else:
                    messages.success(
                        request, f"{target_user.email} ajouté comme membre de l'organisation."
                    )
            else:
                messages.warning(request, "Cet utilisateur est déjà membre de l'organisation.")
        else:
            for error_list in form.errors.values():
                for error in error_list:
                    messages.error(request, error)

    return redirect("organizations:manage", slug=organization.slug)
