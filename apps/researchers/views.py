"""Annuaire public des chercheurs (respectant le choix d'identite)."""

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.paginator import Paginator
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from apps.accounts.permissions import require_not_read_only, require_roles
from apps.accounts.roles import RESEARCHER_ROLES

from .forms import PayoutMethodForm, PayoutProfileForm
from .models import IdentityMode, PayoutMethod, ResearcherProfile
from .services import (
    add_payout_method,
    get_or_create_payout_profile,
    remove_payout_method,
    set_primary_payout_method,
    update_payout_method,
    update_payout_profile,
)


def researcher_list(request):
    """Annuaire : uniquement les profils explicitement rendus publics."""
    queryset = (
        ResearcherProfile.objects.filter(is_public_profile=True)
        .exclude(identity_mode=IdentityMode.PRIVATE)
        .select_related("user")
        .order_by("-reputation", "-reports_validated")
    )
    page = Paginator(queryset, 24).get_page(request.GET.get("page"))
    return render(request, "researchers/list.html", {"page_obj": page})


def researcher_detail(request, slug):
    profile = get_object_or_404(ResearcherProfile.objects.select_related("user"), slug=slug)
    viewer = request.user
    is_self = viewer.is_authenticated and viewer.pk == profile.user_id
    if not profile.is_public_profile and not (
        is_self or (viewer.is_authenticated and viewer.is_national)
    ):
        raise Http404("Profil introuvable.")
    if profile.identity_mode == IdentityMode.PRIVATE and not (
        is_self or (viewer.is_authenticated and viewer.is_national)
    ):
        raise Http404("Profil introuvable.")
    return render(
        request,
        "researchers/detail.html",
        {"profile": profile, "is_self": is_self},
    )


# ---------------------------------------------------------------------------
# Portefeuille de versement (libre-service, reserve aux roles chercheur)
# ---------------------------------------------------------------------------
def _get_own_method(request, method_id):
    """Recupere un moyen de paiement en verifiant qu'il appartient a
    l'appelant. Un identifiant hors perimetre renvoie 404, jamais 403 : la
    plateforme ne confirme jamais l'existence d'une ressource d'autrui."""
    method = get_object_or_404(PayoutMethod.objects.select_related("profile"), pk=method_id)
    if method.profile.user_id != request.user.id:
        raise Http404("Moyen de paiement introuvable.")
    return method


@login_required
@require_roles(*RESEARCHER_ROLES)
def wallet_home(request):
    """Portefeuille : informations personnelles et moyens de paiement."""
    profile = get_or_create_payout_profile(request.user)

    if request.method == "POST" and request.POST.get("form") == "profile":
        if getattr(request.user, "is_read_only", False):
            raise PermissionDenied("Role en lecture seule.")
        profile_form = PayoutProfileForm(request.POST, instance=profile)
        if profile_form.is_valid():
            profile = profile_form.save(commit=False)
            update_payout_profile(profile, request.user, request=request)
            messages.success(request, "Informations personnelles enregistrées.")
            return redirect("wallet:home")
    else:
        profile_form = PayoutProfileForm(instance=profile)

    return render(
        request,
        "researchers/wallet.html",
        {
            "profile": profile,
            "profile_form": profile_form,
            "methods": profile.methods.filter(is_active=True),
            "method_form": PayoutMethodForm(),
            "max_methods": settings.EVDP["MAX_PAYOUT_METHODS"],
        },
    )


@login_required
@require_not_read_only
@require_roles(*RESEARCHER_ROLES)
@require_POST
def payout_method_add(request):
    profile = get_or_create_payout_profile(request.user)
    form = PayoutMethodForm(request.POST)
    if form.is_valid():
        try:
            add_payout_method(profile, request.user, form.save(commit=False), request=request)
        except (PermissionDenied, ValidationError) as exc:
            messages.error(request, "; ".join(getattr(exc, "messages", [str(exc)])))
        else:
            messages.success(request, "Moyen de paiement ajouté.")
    else:
        messages.error(request, form.errors.as_text())
    return redirect("wallet:home")


@login_required
@require_not_read_only
@require_roles(*RESEARCHER_ROLES)
def payout_method_edit(request, method_id):
    method = _get_own_method(request, method_id)
    if request.method == "POST":
        form = PayoutMethodForm(request.POST, instance=method)
        if form.is_valid():
            update_payout_method(form.save(commit=False), request.user, request=request)
            messages.success(request, "Moyen de paiement mis à jour.")
            return redirect("wallet:home")
    else:
        form = PayoutMethodForm(instance=method)
    return render(
        request,
        "researchers/wallet_method_form.html",
        {"form": form, "method": method},
    )


@login_required
@require_not_read_only
@require_roles(*RESEARCHER_ROLES)
@require_POST
def payout_method_set_primary(request, method_id):
    method = _get_own_method(request, method_id)
    try:
        set_primary_payout_method(method, request.user, request=request)
        messages.success(request, "Moyen de paiement principal mis à jour.")
    except (PermissionDenied, ValidationError) as exc:
        messages.error(request, "; ".join(getattr(exc, "messages", [str(exc)])))
    return redirect("wallet:home")


@login_required
@require_not_read_only
@require_roles(*RESEARCHER_ROLES)
@require_POST
def payout_method_remove(request, method_id):
    method = _get_own_method(request, method_id)
    remove_payout_method(method, request.user, request=request)
    messages.success(request, "Moyen de paiement retiré.")
    return redirect("wallet:home")
