"""Annuaire public des chercheurs (respectant le choix d'identite)."""

from django.core.paginator import Paginator
from django.http import Http404
from django.shortcuts import get_object_or_404, render

from .models import IdentityMode, ResearcherProfile


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
