"""Exports PDF / CSV / Excel.

Les exports respectent strictement les permissions : ils reutilisent le
queryset filtre `Case.objects.visible_to(user)` et sont audites.
"""

import csv
from io import BytesIO

from django.contrib.auth.decorators import login_required
from django.db.models import Count
from django.http import Http404, HttpResponse
from django.shortcuts import get_object_or_404
from django.utils import timezone
from openpyxl import Workbook
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from apps.accounts.permissions import require_capability
from apps.accounts.roles import Capability
from apps.accounts.verification import accounts_losing_access, grace_deadline
from apps.audit.models import AuditAction
from apps.audit.services import log_action
from apps.coordination.models import Case
from apps.coordination.selectors import visible_cases
from apps.core.markdown_utils import strip_markdown

COLUMNS = [
    ("case_id", "Identifiant"),
    ("title", "Titre"),
    ("status", "Statut"),
    ("severity", "Severite"),
    ("cvss_score", "CVSS"),
    ("organization", "Organisation"),
    ("workflow", "Workflow"),
    ("created_at", "Cree le"),
    ("disclosure_date", "Divulgation"),
]


def _rows(queryset):
    for case in queryset:
        yield [
            case.case_id,
            case.title,
            case.get_status_display(),
            case.get_severity_display(),
            str(case.cvss_score or ""),
            case.organization.name if case.organization_id else "",
            case.get_workflow_display(),
            timezone.localtime(case.created_at).strftime("%d/%m/%Y %H:%M"),
            case.disclosure_date.strftime("%d/%m/%Y") if case.disclosure_date else "",
        ]


@login_required
@require_capability(Capability.EXPORT_DATA)
def export_cases_csv(request):
    queryset = visible_cases(request.user).order_by("-created_at")[:5000]
    response = HttpResponse(content_type="text/csv; charset=utf-8")
    response["Content-Disposition"] = (
        f'attachment; filename="evdp-cases-{timezone.now():%Y%m%d}.csv"'
    )
    response.write("﻿")  # BOM pour Excel
    writer = csv.writer(response, delimiter=";")
    writer.writerow([label for _key, label in COLUMNS])
    for row in _rows(queryset):
        writer.writerow(row)
    log_action(
        AuditAction.EXPORT_GENERATED,
        actor=request.user,
        request=request,
        object_type="Case",
        format="csv",
        count=queryset.count(),
    )
    return response


@login_required
@require_capability(Capability.EXPORT_DATA)
def export_cases_xlsx(request):
    queryset = visible_cases(request.user).order_by("-created_at")[:5000]
    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "Cases eVDP"
    sheet.append([label for _key, label in COLUMNS])
    for row in _rows(queryset):
        sheet.append(row)
    for index, _column in enumerate(COLUMNS, start=1):
        sheet.column_dimensions[sheet.cell(row=1, column=index).column_letter].width = 22

    buffer = BytesIO()
    workbook.save(buffer)
    buffer.seek(0)
    response = HttpResponse(
        buffer.read(),
        content_type=("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
    )
    response["Content-Disposition"] = (
        f'attachment; filename="evdp-cases-{timezone.now():%Y%m%d}.xlsx"'
    )
    log_action(
        AuditAction.EXPORT_GENERATED,
        actor=request.user,
        request=request,
        object_type="Case",
        format="xlsx",
    )
    return response


@login_required
@require_capability(Capability.EXPORT_DATA)
def export_case_pdf(request, case_id):
    """Fiche PDF complete d'un dossier (perimetre autorise uniquement)."""
    case = get_object_or_404(
        Case.objects.select_related("report", "organization", "assignee"),
        case_id=case_id.upper(),
    )
    if not case.is_visible_to(request.user):
        raise Http404("Dossier introuvable.")

    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title=f"eVDP {case.case_id}",
    )
    styles = getSampleStyleSheet()
    heading = ParagraphStyle(
        "EvdpHeading", parent=styles["Heading2"], textColor=colors.HexColor("#0b3b6f")
    )
    body = ParagraphStyle("EvdpBody", parent=styles["BodyText"], leading=14)

    story = [
        Paragraph(f"eVDP - Dossier {case.case_id}", styles["Title"]),
        Paragraph(
            "Document interne - Diffusion restreinte aux personnes habilitees.",
            styles["Italic"],
        ),
        Spacer(1, 8),
    ]

    summary = [
        ["Titre", case.title],
        ["Statut", case.get_status_display()],
        ["Severite", case.get_severity_display()],
        ["CVSS", f"{case.cvss_score or '-'} ({case.cvss_vector or 'non renseigne'})"],
        ["Organisation", case.organization.name if case.organization_id else "-"],
        ["CWE", case.cwe.code if case.cwe_id else "-"],
        ["CVE", case.cve.cve_id if case.cve_id else "-"],
        ["Analyste", str(case.assignee) if case.assignee_id else "-"],
        ["Declarant", case.report.reporter_display],
        ["Cree le", timezone.localtime(case.created_at).strftime("%d/%m/%Y %H:%M")],
        [
            "Divulgation",
            case.disclosure_date.strftime("%d/%m/%Y") if case.disclosure_date else "-",
        ],
    ]
    table = Table(summary, colWidths=[45 * mm, 120 * mm])
    table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c9d4e3")),
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eef3f9")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
            ]
        )
    )
    story += [table, Spacer(1, 12)]

    sections = [
        ("Description", case.report.description),
        ("Etapes de reproduction", case.report.steps_to_reproduce),
        ("Impact", case.report.impact),
        ("Recommandations", case.report.recommendations),
    ]
    for title, content in sections:
        if not content:
            continue
        story.append(Paragraph(title, heading))
        story.append(Paragraph(strip_markdown(content)[:6000], body))
        story.append(Spacer(1, 8))

    story.append(Paragraph("Chronologie", heading))
    timeline_rows = [["Date", "Evenement"]] + [
        [
            timezone.localtime(event.occurred_at).strftime("%d/%m/%Y %H:%M"),
            event.label,
        ]
        for event in case.timeline.all()
    ]
    timeline_table = Table(timeline_rows, colWidths=[40 * mm, 125 * mm])
    timeline_table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c9d4e3")),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0b3b6f")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
            ]
        )
    )
    story += [timeline_table, Spacer(1, 12)]

    story.append(Paragraph("Historique des statuts", heading))
    history_rows = [["Date", "De", "Vers", "Acteur"]] + [
        [
            timezone.localtime(entry.created_at).strftime("%d/%m/%Y %H:%M"),
            entry.from_status,
            entry.to_status,
            str(entry.actor) if entry.actor_id else "systeme",
        ]
        for entry in case.status_history.all()[:40]
    ]
    history_table = Table(history_rows, colWidths=[35 * mm, 40 * mm, 40 * mm, 50 * mm])
    history_table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c9d4e3")),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0b3b6f")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ]
        )
    )
    story.append(history_table)

    document.build(story)
    buffer.seek(0)

    log_action(
        AuditAction.EXPORT_GENERATED,
        actor=request.user,
        obj=case,
        request=request,
        format="pdf",
    )
    response = HttpResponse(buffer.read(), content_type="application/pdf")
    response["Content-Disposition"] = f'attachment; filename="{case.case_id}.pdf"'
    return response


COMPTES_COLUMNS = [
    "Email",
    "Nom complet",
    "Role",
    "Compte cree le",
    "Derniere connexion",
    "Derniere relance",
    "Fin du sursis",
    "Signalements deposes",
]


@login_required
@require_capability(Capability.EXPORT_DATA)
def export_unverified_accounts_csv(request):
    """Comptes sur le point de perdre l'acces aux programmes Bug Bounty.

    La relance par email ne suffit pas : une adresse morte ou erronee ne
    verra jamais passer le rappel, et c'est justement le cas des comptes qui
    n'ont jamais verifie la leur. Cet export permet au CSIRT de reprendre
    contact autrement avant, ou apres, l'expiration du sursis.

    Le parametre `jours` elargit la fenetre au-dela du J-1 par defaut.
    """
    try:
        jours = int(request.GET.get("jours", 1))
    except (TypeError, ValueError):
        jours = 1
    jours = max(0, min(jours, 90))

    comptes = (
        accounts_losing_access(jours)
        .annotate(signalements=Count("submitted_reports"))
        .order_by("created_at")
    )

    response = HttpResponse(content_type="text/csv; charset=utf-8")
    response["Content-Disposition"] = (
        f'attachment; filename="evdp-comptes-non-verifies-{timezone.now():%Y%m%d}.csv"'
    )
    response.write("﻿")  # BOM pour Excel
    writer = csv.writer(response, delimiter=";")
    writer.writerow(COMPTES_COLUMNS)
    for compte in comptes:
        echeance = grace_deadline(compte)
        writer.writerow(
            [
                compte.email,
                compte.full_name,
                compte.get_role_display(),
                timezone.localtime(compte.created_at).strftime("%d/%m/%Y"),
                timezone.localtime(compte.last_login).strftime("%d/%m/%Y %H:%M")
                if compte.last_login
                else "Jamais",
                compte.verification_reminded_on.strftime("%d/%m/%Y")
                if compte.verification_reminded_on
                else "Aucune",
                echeance.strftime("%d/%m/%Y") if echeance else "",
                compte.signalements,
            ]
        )

    log_action(
        AuditAction.EXPORT_GENERATED,
        actor=request.user,
        request=request,
        object_type="User",
        format="csv",
        count=comptes.count(),
        jours=jours,
    )
    return response
