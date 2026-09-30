"""Gestion des comptes dans l'application (capacite MANAGE_USERS).

Reprend les regles de l'administration Django (apps.accounts.admin) pour les
comptes qui n'ont pas acces a celle-ci : creation sans mot de passe avec lien
d'activation, rattachement obligatoire a l'organisation pour un compte DSI ou
responsable, changement de role et d'etat audites, reinitialisation du
second facteur.

Garde-fous : un compte qui n'est pas superutilisateur ne voit ni ne touche un
super-administrateur (404, envoi de lien compris) ; personne ne change son
propre role ni ne desactive son propre compte.
"""

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db.models import Q
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from apps.accounts.permissions import require_capability, require_not_read_only
from apps.audit.models import AuditAction
from apps.audit.services import log_action

from .admin import membership_role_for
from .forms import ManagedUserCreateForm, ManagedUserEditForm, UserFilterForm
from .models import User
from .roles import BUSINESS_ROLES, RESEARCHER_ROLES, Capability, Role
from .views import send_password_setup_link


def _managed_users(actor):
    users = User.objects.all()
    if not actor.is_superuser:
        users = users.exclude(role=Role.SUPER_ADMIN).exclude(is_superuser=True)
    return users


def _get_managed(actor, pk):
    return get_object_or_404(_managed_users(actor), pk=pk)


def _send_setup_link(user):
    send_password_setup_link(
        user,
        title="Votre compte eVDP",
        body=(
            "Un compte eVDP a été créé pour vous. Choisissez votre mot de passe "
            "pour l'activer ; un second facteur vous sera demandé ensuite."
        ),
    )


@login_required
@require_capability(Capability.MANAGE_USERS)
def user_manage_list(request):
    form = UserFilterForm(request.GET or None)
    users = _managed_users(request.user).order_by("email")
    if form.is_valid():
        query = form.cleaned_data.get("q")
        if query:
            users = users.filter(
                Q(email__icontains=query)
                | Q(full_name__icontains=query)
                | Q(display_name__icontains=query)
            )
        population = form.cleaned_data.get("population")
        if population == "metier":
            users = users.filter(role__in=BUSINESS_ROLES)
        elif population == "signaleurs":
            users = users.filter(role__in=RESEARCHER_ROLES)
        if form.cleaned_data.get("active") in ("0", "1"):
            users = users.filter(is_active=form.cleaned_data["active"] == "1")
    page = Paginator(users, 30).get_page(request.GET.get("page"))
    return render(request, "accounts/manage_list.html", {"form": form, "page_obj": page})


@login_required
@require_not_read_only
@require_capability(Capability.MANAGE_USERS)
def user_manage_create(request):
    form = ManagedUserCreateForm(request.POST or None, actor=request.user)
    if request.method == "POST" and form.is_valid():
        from apps.organizations.models import OrganizationMember

        data = form.cleaned_data
        user = User.objects.create_user(
            email=data["email"], password=None, full_name=data["full_name"], role=data["role"]
        )
        log_action(
            AuditAction.USER_CREATED,
            actor=request.user,
            obj=user,
            request=request,
            role=user.role,
        )
        organization = data.get("organization")
        if organization is not None:
            member = OrganizationMember.objects.create(
                organization=organization,
                user=user,
                membership_role=membership_role_for(user.role),
                is_primary=True,
                invited_by=request.user,
            )
            log_action(
                AuditAction.MEMBERSHIP_CHANGED,
                actor=request.user,
                obj=organization,
                request=request,
                member_email=user.email,
                membership_role=member.membership_role,
            )
        _send_setup_link(user)
        messages.success(
            request,
            f"Compte créé : un lien pour choisir le mot de passe a été envoyé à {user.email}.",
        )
        return redirect("accounts:user_manage_detail", pk=user.pk)
    return render(request, "accounts/manage_create.html", {"form": form})


@login_required
@require_capability(Capability.MANAGE_USERS)
def user_manage_detail(request, pk):
    target = _get_managed(request.user, pk)
    if request.method == "POST" and not getattr(request.user, "is_read_only", False):
        form = ManagedUserEditForm(request.POST, actor=request.user, target=target)
        if form.is_valid():
            _apply_changes(request, target, form.cleaned_data)
            return redirect("accounts:user_manage_detail", pk=target.pk)
    else:
        form = ManagedUserEditForm(
            initial={"role": target.role, "is_active": target.is_active},
            actor=request.user,
            target=target,
        )
    return render(
        request,
        "accounts/manage_detail.html",
        {
            "target": target,
            "form": form,
            "memberships": target.organization_memberships.select_related("organization"),
            "is_business": target.role in BUSINESS_ROLES,
        },
    )


def _apply_changes(request, target, data):
    changed = []
    if data["role"] != target.role:
        target.role = data["role"]
        changed.append("role")
    if data["is_active"] != target.is_active:
        target.is_active = data["is_active"]
        changed.append("is_active")
    if not changed:
        messages.info(request, "Aucune modification.")
        return
    target.save(update_fields=[*changed, "updated_at"])
    if "role" in changed:
        log_action(
            AuditAction.ROLE_CHANGED,
            actor=request.user,
            obj=target,
            request=request,
            new_role=target.role,
        )
    if "is_active" in changed:
        log_action(
            AuditAction.USER_UPDATED,
            actor=request.user,
            obj=target,
            request=request,
            is_active=target.is_active,
        )
    messages.success(request, "Compte mis à jour.")


@login_required
@require_POST
@require_not_read_only
@require_capability(Capability.MANAGE_USERS)
def user_manage_resend_link(request, pk):
    target = _get_managed(request.user, pk)
    if not target.is_active:
        messages.error(request, "Compte désactivé : réactivez-le d'abord.")
    else:
        _send_setup_link(target)
        log_action(
            AuditAction.USER_UPDATED,
            actor=request.user,
            obj=target,
            request=request,
            setup_link_sent=True,
        )
        messages.success(request, f"Lien envoyé à {target.email}.")
    return redirect("accounts:user_manage_detail", pk=target.pk)


@login_required
@require_POST
@require_not_read_only
@require_capability(Capability.MANAGE_USERS)
def user_manage_reset_mfa(request, pk):
    target = _get_managed(request.user, pk)
    if target.mfa_enabled or target.mfa_secret:
        target.reset_mfa()
        log_action(AuditAction.MFA_RESET, actor=request.user, obj=target, request=request)
        messages.success(
            request, "Second facteur réinitialisé : un nouvel enrôlement sera demandé."
        )
    return redirect("accounts:user_manage_detail", pk=target.pk)
