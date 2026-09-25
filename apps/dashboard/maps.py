"""Cartographie : organisations du Burkina Faso et signalements afferents.

Les signalements proviennent exclusivement de `selectors.visible_cases` :
la carte n'ouvre aucun perimetre que la liste des dossiers n'ouvre pas
deja. Un dossier sans organisation n'a pas de place sur la carte.

Les agregats sont calcules en Python sur une seule requete `values()`
plutot que par organisation : quelques milliers de dossiers tiennent
largement en memoire, et N requetes par chargement de carte non.
"""

from django.conf import settings
from django.db.models import Q
from django.urls import reverse

from apps.accounts.roles import Capability
from apps.coordination import selectors
from apps.coordination.constants import SLAState
from apps.coordination.workflow import TERMINAL_STATES
from apps.organizations import geo
from apps.organizations.models import Organization, OrganizationStatus, Sector
from apps.vulnerabilities.constants import Severity

SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]

# Poids d'un dossier dans la carte de chaleur, selon sa severite.
HEAT_WEIGHT = {
    Severity.CRITICAL: 1.0,
    Severity.HIGH: 0.75,
    Severity.MEDIUM: 0.5,
    Severity.LOW: 0.3,
    Severity.INFO: 0.15,
}

RECENT_CASES = 3


def can_view_map(user):
    return user.has_capability(Capability.VIEW_MAP) or user.has_capability(
        Capability.VIEW_ORG_MAP
    )


def is_national_scope(user):
    """Carte nationale, ou reduite aux organisations du compte (DSI...)."""
    return user.has_capability(Capability.VIEW_MAP)


def _dominant(by_severity):
    """Severite la plus grave presente, ou None sans dossier."""
    for severity in SEVERITY_ORDER:
        if by_severity.get(severity):
            return str(severity)
    return None


def _empty_counts():
    return {str(severity): 0 for severity in SEVERITY_ORDER}


def filter_options():
    return {
        "sectors": [{"value": value, "label": label} for value, label in Sector.choices],
        "regions": [region[0] for region in geo.REGIONS],
        "severities": [
            {"value": str(severity), "label": severity.label} for severity in SEVERITY_ORDER
        ],
    }


def build_map_data(
    user,
    *,
    query="",
    sector="",
    region="",
    severity="",
    scope="open",
    reported_only=False,
):
    """Donnees de la carte pour `user`, filtrees.

    `scope` vaut "open" (dossiers non clos, par defaut) ou "all".
    """
    national = is_national_scope(user)
    own_org_ids = None if national else user.organization_ids()

    cases = selectors.visible_cases(user).exclude(organization__isnull=True)
    if not national:
        # visible_cases le garantit deja ; le filtre explicite garde la carte
        # sure si ce perimetre venait a s'elargir.
        cases = cases.filter(organization_id__in=own_org_ids)
    if scope != "all":
        cases = cases.exclude(status__in=TERMINAL_STATES)
    if severity:
        cases = cases.filter(severity=severity)

    breached = set(
        cases.filter(sla_events__state=SLAState.BREACHED).values_list("id", flat=True)
    )
    # Le titre d'un dossier n'est montre qu'a qui traite les dossiers : la
    # vue nationale reste agregee, comme le tableau de bord national.
    show_cases = user.has_capability(Capability.VIEW_ALL_CASES) or user.has_capability(
        Capability.VIEW_ORG_CASES
    )

    per_org = {}
    rows = cases.order_by("-priority_score", "-created_at").values(
        "id", "organization_id", "case_id", "title", "severity", "status", "created_at"
    )
    for row in rows:
        bucket = per_org.setdefault(
            row["organization_id"],
            {
                "counts": _empty_counts(),
                "total": 0,
                "open": 0,
                "breached": 0,
                "recent": [],
                "last": None,
            },
        )
        bucket["total"] += 1
        bucket["counts"][row["severity"]] = bucket["counts"].get(row["severity"], 0) + 1
        if row["status"] not in TERMINAL_STATES:
            bucket["open"] += 1
        if row["id"] in breached:
            bucket["breached"] += 1
        if bucket["last"] is None or row["created_at"] > bucket["last"]:
            bucket["last"] = row["created_at"]
        if show_cases and len(bucket["recent"]) < RECENT_CASES:
            bucket["recent"].append(
                {
                    "case_id": row["case_id"],
                    "title": row["title"],
                    "severity": row["severity"],
                    "url": reverse("coordination:case_detail", args=[row["case_id"]]),
                }
            )

    organizations = Organization.objects.filter(status=OrganizationStatus.ACTIVE)
    if not national:
        organizations = organizations.filter(id__in=own_org_ids)
    if sector:
        organizations = organizations.filter(sector=sector)
    if query:
        query = query.strip()
        organizations = organizations.filter(
            Q(name__icontains=query) | Q(acronym__icontains=query) | Q(domain__icontains=query)
        )
    wanted_region = geo.region_label(region) if region else ""
    sector_labels = dict(Sector.choices)
    case_list_url = reverse("coordination:case_list")

    markers = []
    unlocated = 0
    regions = {}
    for org in organizations.order_by("name"):
        region_name = geo.region_label(org.region)
        if wanted_region and region_name != wanted_region:
            continue
        stats = per_org.get(org.id)
        if reported_only and not stats:
            continue
        position = geo.locate(org)
        if position is None:
            if stats:
                unlocated += 1
            continue
        lat, lon, precise = position
        stats = stats or {
            "counts": _empty_counts(),
            "total": 0,
            "open": 0,
            "breached": 0,
            "recent": [],
            "last": None,
        }
        dominant = _dominant(stats["counts"])
        markers.append(
            {
                "id": str(org.id),
                "name": org.name,
                "acronym": org.acronym,
                "sector": sector_labels.get(org.sector, ""),
                "region": region_name or "Non renseignée",
                "lat": lat,
                "lon": lon,
                "precise": precise,
                "total": stats["total"],
                "open": stats["open"],
                "sla_breached": stats["breached"],
                "by_severity": stats["counts"],
                "dominant": dominant,
                "heat": round(
                    sum(
                        HEAT_WEIGHT[s] * stats["counts"].get(str(s), 0) for s in SEVERITY_ORDER
                    ),
                    2,
                ),
                "last_report": stats["last"].date().isoformat() if stats["last"] else None,
                "recent": stats["recent"],
                "cases_url": f"{case_list_url}?organization={org.id}" if show_cases else None,
                "detail_url": reverse("organizations:detail", args=[org.slug]),
            }
        )

        region_ref = geo.find_region(org.region)
        if region_ref:
            agg = regions.setdefault(
                region_ref["name"],
                {
                    "name": region_ref["name"],
                    "capital": region_ref["capital"],
                    "lat": region_ref["lat"],
                    "lon": region_ref["lon"],
                    "organizations": 0,
                    "total": 0,
                    "open": 0,
                    "sla_breached": 0,
                    "by_severity": _empty_counts(),
                },
            )
            agg["organizations"] += 1
            agg["total"] += stats["total"]
            agg["open"] += stats["open"]
            agg["sla_breached"] += stats["breached"]
            for key, value in stats["counts"].items():
                agg["by_severity"][key] = agg["by_severity"].get(key, 0) + value

    for agg in regions.values():
        agg["dominant"] = _dominant(agg["by_severity"])

    totals = _empty_counts()
    for marker in markers:
        for key, value in marker["by_severity"].items():
            totals[key] += value

    return {
        "center": list(geo.DEFAULT_CENTER),
        "bounds": [[geo.LAT_MIN, geo.LON_MIN], [geo.LAT_MAX, geo.LON_MAX]],
        "scope": "national" if national else "organization",
        "tiles": settings.MAP_TILE_URL,
        "attribution": settings.MAP_ATTRIBUTION,
        "organizations": markers,
        "regions": sorted(regions.values(), key=lambda r: -r["total"]),
        "totals": {
            "organizations": len(markers),
            "reported": sum(1 for m in markers if m["total"]),
            "cases": sum(m["total"] for m in markers),
            "open": sum(m["open"] for m in markers),
            "sla_breached": sum(m["sla_breached"] for m in markers),
            "by_severity": totals,
            "unlocated": unlocated,
        },
    }
