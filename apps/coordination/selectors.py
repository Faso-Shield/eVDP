"""Selecteurs de lecture : requetes filtrees et statistiques.

Toutes les requetes partent de `Case.objects.visible_to(user)` afin que
l'isolation des donnees soit garantie en un seul endroit.
"""

from datetime import timedelta

from django.db.models import Avg, Count, F, Q
from django.db.models.functions import TruncMonth
from django.utils import timezone

from apps.vulnerabilities.constants import Severity

from .constants import SLAState
from .models import Case
from .workflow import DISMISSED_STATES, KANBAN_COLUMNS, TERMINAL_STATES, CaseStatus


def visible_cases(user):
    return Case.objects.visible_to(user).select_related(
        "organization", "assignee", "reporter", "program", "cwe", "cve"
    )


def search_cases(
    user,
    query=None,
    status=None,
    severity=None,
    organization=None,
    workflow=None,
    assignee=None,
    program=None,
):
    """Recherche globale sur le perimetre autorise de l'utilisateur."""
    queryset = visible_cases(user)
    if query:
        query = query.strip()
        queryset = queryset.filter(
            Q(case_id__icontains=query)
            | Q(title__icontains=query)
            | Q(product__icontains=query)
            | Q(cve__cve_id__icontains=query)
            | Q(cwe__code__icontains=query)
            | Q(organization__name__icontains=query)
            | Q(organization__acronym__icontains=query)
            | Q(program__name__icontains=query)
        )
    if status:
        queryset = queryset.filter(status=status)
    if severity:
        queryset = queryset.filter(severity=severity)
    if organization:
        queryset = queryset.filter(organization=organization)
    if workflow:
        queryset = queryset.filter(workflow=workflow)
    if assignee:
        queryset = queryset.filter(assignee=assignee)
    if program:
        queryset = queryset.filter(program=program)
    return queryset


#: Etat SLA -> couleur de badge (vert, orange a 75 % du delai, rouge a echeance).
SLA_COLORS = {"ok": "sla-ok", "warning": "sla-warning", "breached": "sla-breached"}


def sla_color(case, now=None):
    """Couleur d'echeance de l'etape en cours d'un dossier (ou "")."""
    now = now or timezone.now()
    events = [
        event
        for event in case.sla_events.all()
        if event.state in (SLAState.PENDING, SLAState.APPROACHING, SLAState.BREACHED)
    ]
    if not events:
        return ""
    worst = "ok"
    for event in events:
        if event.state == SLAState.BREACHED or event.due_at <= now:
            return SLA_COLORS["breached"]
        policy = event.policy
        ratio = (policy.warning_ratio if policy else 75) / 100
        total = (event.due_at - event.created_at).total_seconds()
        elapsed = (now - event.created_at).total_seconds()
        if event.state == SLAState.APPROACHING or (total > 0 and elapsed / total >= ratio):
            worst = "warning"
    return SLA_COLORS[worst]


def kanban_board(user, limit_per_column=40):
    """Regroupe les cases visibles par colonne Kanban.

    La colonne « Clos » montre les dossiers termines (clos, rejetes,
    doublons) que l'utilisateur voit en archives, les plus recemment
    clotures d'abord ; au-dela de la limite, la liste complete prend le
    relais (`truncated`).
    """
    queryset = visible_cases(user).prefetch_related("sla_events__policy")
    board = []
    for key, label, states in KANBAN_COLUMNS:
        column = queryset.filter(status__in=states)
        if key == "CLOSED":
            column = column.order_by(F("closed_at").desc(nulls_last=True), "-updated_at")
        count = column.count()
        board.append(
            {
                "key": key,
                "label": label,
                "cases": list(column[:limit_per_column]),
                "count": count,
                "truncated": count > limit_per_column,
            }
        )
    return board


def case_statistics(user):
    """Indicateurs cles du perimetre visible."""
    queryset = visible_cases(user)
    severities = dict(
        queryset.values_list("severity")
        .annotate(total=Count("id"))
        .values_list("severity", "total")
    )
    total = queryset.count()
    validated = queryset.filter(status__in=CaseStatus.validated_states()).count()
    return {
        "total": total,
        "new": queryset.filter(status=CaseStatus.SUBMITTED).count(),
        "in_triage": queryset.filter(
            status__in=[
                CaseStatus.ACKNOWLEDGED,
                CaseStatus.IN_ANALYSIS,
                CaseStatus.VALIDATION_PENDING,
                CaseStatus.NEEDS_INFORMATION,
                CaseStatus.REJECTION_PENDING,
            ]
        ).count(),
        "validated": validated,
        "in_remediation": queryset.filter(
            status__in=[
                CaseStatus.VENDOR_NOTIFIED,
                CaseStatus.REMEDIATION_IN_PROGRESS,
                CaseStatus.FIX_AVAILABLE,
            ]
        ).count(),
        "critical": severities.get(Severity.CRITICAL, 0),
        "high": severities.get(Severity.HIGH, 0),
        "medium": severities.get(Severity.MEDIUM, 0),
        "low": severities.get(Severity.LOW, 0),
        "info": severities.get(Severity.INFO, 0),
        "duplicates": queryset.filter(status=CaseStatus.DUPLICATE).count(),
        "rejected": queryset.filter(status=CaseStatus.REJECTED).count(),
        "closed": queryset.filter(status__in=TERMINAL_STATES).count(),
        "open": queryset.exclude(status__in=TERMINAL_STATES).count(),
        "published": queryset.filter(is_published=True).count(),
        "sla_breached": queryset.filter(sla_events__state=SLAState.BREACHED)
        .distinct()
        .count(),
        "validation_rate": round(validated * 100 / total, 1) if total else 0,
    }


def cases_per_month(user, months=12):
    """Serie mensuelle du nombre de signalements."""
    since = timezone.now() - timedelta(days=31 * months)
    rows = (
        visible_cases(user)
        .filter(created_at__gte=since)
        .annotate(month=TruncMonth("created_at"))
        .values("month")
        .annotate(total=Count("id"))
        .order_by("month")
    )
    return [
        {"label": row["month"].strftime("%m/%Y"), "value": row["total"]}
        for row in rows
        if row["month"]
    ]


def severity_distribution(user):
    rows = (
        visible_cases(user).values("severity").annotate(total=Count("id")).order_by("-total")
    )
    labels = dict(Severity.choices)
    return [
        {
            "key": row["severity"],
            "label": labels.get(row["severity"], row["severity"]),
            "value": row["total"],
        }
        for row in rows
    ]


def sector_distribution(user):
    rows = (
        visible_cases(user)
        .exclude(organization__isnull=True)
        .values("organization__sector")
        .annotate(total=Count("id"))
        .order_by("-total")[:10]
    )
    from apps.organizations.models import Sector

    labels = dict(Sector.choices)
    return [
        {
            "label": labels.get(row["organization__sector"], "Autre"),
            "value": row["total"],
        }
        for row in rows
    ]


def top_organizations(user, limit=10):
    return list(
        visible_cases(user)
        .exclude(organization__isnull=True)
        .values("organization__name", "organization__acronym")
        .annotate(total=Count("id"))
        .order_by("-total")[:limit]
    )


def top_cwes(user, limit=10):
    return list(
        visible_cases(user)
        .exclude(cwe__isnull=True)
        .values("cwe__code", "cwe__name")
        .annotate(total=Count("id"))
        .order_by("-total")[:limit]
    )


def average_remediation_days(user):
    """Delai moyen entre validation et remediation, en jours."""
    rows = (
        visible_cases(user)
        .filter(validated_at__isnull=False, remediated_at__isnull=False)
        .annotate(delta=F("remediated_at") - F("validated_at"))
        .aggregate(average=Avg("delta"))
    )
    average = rows["average"]
    if average is None:
        return None
    return round(average.total_seconds() / 86400, 1)


def vulnerability_type_distribution(user, limit=10):
    from apps.vulnerabilities.constants import VulnerabilityType

    labels = dict(VulnerabilityType.choices)
    rows = (
        visible_cases(user)
        .values("vulnerability_type")
        .annotate(total=Count("id"))
        .order_by("-total")[:limit]
    )
    return [
        {"label": labels.get(row["vulnerability_type"], "Autre"), "value": row["total"]}
        for row in rows
    ]


def overdue_cases(user, limit=20):
    return list(
        visible_cases(user)
        .filter(sla_events__state=SLAState.BREACHED)
        .distinct()
        .order_by("-priority_score")[:limit]
    )


def dismissed_count(user):
    return visible_cases(user).filter(status__in=DISMISSED_STATES).count()
