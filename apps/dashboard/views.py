"""Tableaux de bord : chercheur, organisation/DSI, CSIRT, national."""

import json

from django.contrib.auth.decorators import login_required
from django.db.models import Count, Sum
from django.shortcuts import redirect, render

from apps.accounts.permissions import require_capability
from apps.accounts.roles import Capability
from apps.bounty.models import Bounty, BountyStatus
from apps.coordination import selectors
from apps.coordination.models import Case
from apps.disclosures.models import Advisory
from apps.organizations.models import Organization
from apps.programs.models import Program
from apps.researchers.models import ResearcherProfile
from apps.researchers.services import get_or_create_profile


def _max_value(points):
    """Valeur maximale d'une serie, utilisee pour dimensionner les graphiques."""
    return max((point["value"] for point in points), default=1) or 1


@login_required
def home(request):
    """Aiguillage vers le tableau de bord correspondant au role."""
    user = request.user
    if user.has_capability(Capability.VIEW_NATIONAL_DASHBOARD):
        return redirect("dashboard:national")
    if user.has_capability(Capability.VIEW_CSIRT_DASHBOARD):
        return redirect("dashboard:csirt")
    if user.is_organization_user:
        return redirect("dashboard:organization")
    return redirect("dashboard:researcher")


@login_required
def researcher_dashboard(request):
    """Espace du chercheur : rapports, recompenses, reputation."""
    user = request.user
    profile = get_or_create_profile(user) if user.is_researcher else None
    cases = Case.objects.filter(reporter=user).select_related("organization", "program")
    bounties = Bounty.objects.filter(researcher=user).select_related("case")

    rewards_total = (
        bounties.filter(status=BountyStatus.PAID).aggregate(total=Sum("approved_amount"))[
            "total"
        ]
        or 0
    )
    rewards_pending = bounties.exclude(
        status__in=[BountyStatus.PAID, BountyStatus.REJECTED, BountyStatus.CANCELLED]
    ).count()

    return render(
        request,
        "dashboard/researcher.html",
        {
            "profile": profile,
            "cases": cases.order_by("-created_at")[:15],
            "case_count": cases.count(),
            "stats": selectors.case_statistics(user),
            "bounties": bounties.order_by("-created_at")[:10],
            "rewards_total": rewards_total,
            "rewards_pending": rewards_pending,
            "programs": Program.objects.public()[:6],
            "advisories": Advisory.objects.published().filter(case__reporter=user)[:5],
        },
    )


@login_required
def organization_dashboard(request):
    """Espace d'une organisation / DSI : uniquement ses vulnerabilites."""
    user = request.user
    org_ids = user.organization_ids()
    organizations = Organization.objects.filter(id__in=org_ids)
    cases = Case.objects.visible_to(user).select_related("organization", "assignee")

    return render(
        request,
        "dashboard/organization.html",
        {
            "organizations": organizations,
            "stats": selectors.case_statistics(user),
            "cases": cases.order_by("-priority_score", "-created_at")[:20],
            "overdue": selectors.overdue_cases(user, limit=10),
            "programs": Program.objects.for_organizations(org_ids).order_by("-created_at"),
            "advisories": Advisory.objects.published().filter(organization_id__in=org_ids)[
                :10
            ],
            "members": sum(
                org.members.filter(is_active=True).count() for org in organizations
            ),
        },
    )


@login_required
@require_capability(Capability.VIEW_CSIRT_DASHBOARD)
def csirt_dashboard(request):
    """Tableau de bord operationnel CSIRT / ANSSI."""
    user = request.user
    stats = selectors.case_statistics(user)
    charts = {
        "per_month": selectors.cases_per_month(user),
        "severity": selectors.severity_distribution(user),
        "sector": selectors.sector_distribution(user),
        "types": selectors.vulnerability_type_distribution(user),
        "cwe": selectors.top_cwes(user),
    }
    return render(
        request,
        "dashboard/csirt.html",
        {
            "stats": stats,
            "charts": charts,
            "max_month": _max_value(charts["per_month"]),
            "charts_json": json.dumps(charts),
            "top_organizations": selectors.top_organizations(user),
            "overdue": selectors.overdue_cases(user),
            "average_remediation": selectors.average_remediation_days(user),
            "recent": selectors.visible_cases(user).order_by("-created_at")[:12],
            "active_researchers": ResearcherProfile.objects.filter(
                reports_submitted__gt=0
            ).count(),
            "advisories_published": Advisory.objects.published().count(),
        },
    )


@login_required
@require_capability(Capability.VIEW_NATIONAL_DASHBOARD)
def national_dashboard(request):
    """Vue de posture nationale.

    Les indicateurs sont agreges : aucune information permettant d'identifier
    une infrastructure sensible n'est affichee ici.
    """
    user = request.user
    stats = selectors.case_statistics(user)
    charts = {
        "per_month": selectors.cases_per_month(user, months=24),
        "severity": selectors.severity_distribution(user),
        "sector": selectors.sector_distribution(user),
        "types": selectors.vulnerability_type_distribution(user),
    }
    rewards = Bounty.objects.filter(status=BountyStatus.PAID).aggregate(
        total=Sum("approved_amount"), count=Count("id")
    )
    return render(
        request,
        "dashboard/national.html",
        {
            "stats": stats,
            "charts": charts,
            "max_month": _max_value(charts["per_month"]),
            "charts_json": json.dumps(charts),
            "organizations_total": Organization.objects.count(),
            "organizations_affected": selectors.visible_cases(user)
            .exclude(organization__isnull=True)
            .values("organization")
            .distinct()
            .count(),
            "top_organizations": selectors.top_organizations(user),
            "researchers_total": ResearcherProfile.objects.count(),
            "programs_vdp": Program.objects.vdp().count(),
            "programs_bounty": Program.objects.bug_bounty().count(),
            "advisories_published": Advisory.objects.published().count(),
            "cve_count": selectors.visible_cases(user).exclude(cve__isnull=True).count(),
            "rewards_total": rewards["total"] or 0,
            "rewards_count": rewards["count"] or 0,
            "average_remediation": selectors.average_remediation_days(user),
            "overdue": selectors.overdue_cases(user, limit=10),
        },
    )


@login_required
def search(request):
    """Recherche globale, limitee au perimetre visible de l'utilisateur."""
    query = (request.GET.get("q") or "").strip()
    cases = []
    advisories = []
    programs = []
    if query:
        cases = list(selectors.search_cases(request.user, query=query)[:25])
        advisories = list(
            Advisory.objects.visible_to(request.user).filter(title__icontains=query)[:10]
        )
        programs = list(Program.objects.public().filter(name__icontains=query)[:10])
    return render(
        request,
        "dashboard/search.html",
        {
            "query": query,
            "cases": cases,
            "advisories": advisories,
            "programs": programs,
            "total": len(cases) + len(advisories) + len(programs),
        },
    )
