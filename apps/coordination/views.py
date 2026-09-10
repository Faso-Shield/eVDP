"""Vues de traitement des cases (liste, Kanban, detail, actions)."""

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.paginator import Paginator
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect, render

from apps.accounts.permissions import require_capability, require_not_read_only
from apps.accounts.roles import Capability
from apps.attachments.services import store_attachment
from apps.audit.models import AuditAction
from apps.audit.services import log_action
from apps.reports.forms import AttachmentUploadForm
from apps.vulnerabilities.cvss import CVSSError, describe

from . import selectors
from .forms import (
    AssignmentForm,
    CaseFilterForm,
    CaseMessageForm,
    CveLinkForm,
    DisclosureScheduleForm,
    DuplicateForm,
    StatusTransitionForm,
    TriageForm,
)
from .models import Case
from .services import (
    assign_case,
    mark_duplicate,
    post_message,
    schedule_disclosure,
    set_severity,
    transition_case,
    visible_messages,
)
from .workflow import TransitionNotAllowed, allowed_targets


def _get_case(request, case_id):
    """Recupere un case en verifiant l'habilitation.

    Un utilisateur non autorise recoit un 404 : la plateforme ne confirme
    jamais l'existence d'un dossier hors de son perimetre.
    """
    case = get_object_or_404(
        Case.objects.select_related(
            "report", "organization", "assignee", "reporter", "program", "cwe", "cve"
        ),
        case_id=case_id.upper(),
    )
    if not case.is_visible_to(request.user):
        log_action(
            AuditAction.CASE_VIEWED,
            actor=request.user,
            obj=case,
            result="DENIED",
            request=request,
        )
        raise Http404("Dossier introuvable.")
    return case


@login_required
def case_list(request):
    form = CaseFilterForm(request.GET or None)
    filters = {}
    if form.is_valid():
        filters = {
            "query": form.cleaned_data.get("q"),
            "status": form.cleaned_data.get("status"),
            "severity": form.cleaned_data.get("severity"),
            "organization": form.cleaned_data.get("organization"),
        }
    queryset = selectors.search_cases(request.user, **filters).order_by(
        "-priority_score", "-created_at"
    )
    page = Paginator(queryset, 25).get_page(request.GET.get("page"))
    return render(
        request,
        "coordination/case_list.html",
        {"page_obj": page, "form": form, "stats": selectors.case_statistics(request.user)},
    )


@login_required
def kanban(request):
    return render(
        request,
        "coordination/kanban.html",
        {"board": selectors.kanban_board(request.user)},
    )


@login_required
def case_detail(request, case_id):
    case = _get_case(request, case_id)
    log_action(AuditAction.CASE_VIEWED, actor=request.user, obj=case, request=request)

    cvss_breakdown = []
    if case.cvss_vector:
        try:
            cvss_breakdown = describe(case.cvss_vector)
        except CVSSError:
            cvss_breakdown = []

    is_reporter = case.reporter_id == request.user.id
    can_manage = request.user.has_capability(Capability.CHANGE_CASE_STATUS)

    context = {
        "case": case,
        "report": case.report,
        "messages_list": visible_messages(case, request.user),
        "timeline": case.timeline.select_related("actor"),
        "attachments": case.attachments.select_related("uploaded_by"),
        "sla_events": case.sla_events.all(),
        "status_history": case.status_history.select_related("actor")[:30],
        "participants": case.participants.select_related("user").filter(is_active=True),
        "message_form": CaseMessageForm(user=request.user),
        "upload_form": AttachmentUploadForm(),
        "status_form": (
            StatusTransitionForm(case=case, user=request.user) if can_manage else None
        ),
        "triage_form": (
            TriageForm(
                case=case,
                initial={
                    "severity": case.severity,
                    "cvss_vector": case.cvss_vector,
                    "cwe": case.cwe_id,
                    "organization": case.organization_id,
                    "scope": case.scope_id,
                    "tags": ", ".join(case.tags or []),
                },
            )
            if request.user.has_capability(Capability.TRIAGE_CASE)
            else None
        ),
        "assignment_form": (
            AssignmentForm(initial={"assignee": case.assignee_id})
            if request.user.has_capability(Capability.ASSIGN_CASE)
            else None
        ),
        "duplicate_form": (
            DuplicateForm() if request.user.has_capability(Capability.TRIAGE_CASE) else None
        ),
        "disclosure_form": (
            DisclosureScheduleForm(initial={"disclosure_date": case.disclosure_date})
            if can_manage
            else None
        ),
        "cve_form": CveLinkForm() if can_manage else None,
        "cvss_breakdown": cvss_breakdown,
        "allowed_targets": allowed_targets(case.status, case.workflow),
        "is_reporter": is_reporter,
        "can_manage": can_manage,
        "bounty": getattr(case, "bounty", None),
        "advisories": case.advisories.all(),
        # Le case original d'un doublon n'est jamais expose au declarant.
        "show_duplicate_origin": case.duplicate_of_id is not None and request.user.is_national,
    }
    return render(request, "coordination/case_detail.html", context)


@login_required
@require_not_read_only
def post_case_message(request, case_id):
    case = _get_case(request, case_id)
    form = CaseMessageForm(request.POST, user=request.user)
    if form.is_valid():
        try:
            post_message(
                case,
                request.user,
                form.cleaned_data["body"],
                confidentiality=form.cleaned_data["confidentiality"],
                request=request,
            )
            messages.success(request, "Message publie.")
        except (PermissionDenied, ValidationError) as exc:
            messages.error(request, str(exc))
    else:
        messages.error(request, "Message invalide.")
    return redirect("coordination:case_detail", case_id=case.case_id)


@login_required
@require_not_read_only
@require_capability(Capability.CHANGE_CASE_STATUS)
def change_status(request, case_id):
    case = _get_case(request, case_id)
    form = StatusTransitionForm(request.POST, case=case, user=request.user)
    if form.is_valid():
        try:
            transition_case(
                case,
                form.cleaned_data["target_status"],
                request.user,
                comment=form.cleaned_data.get("comment", ""),
                request=request,
            )
            messages.success(request, f"Statut mis a jour : {case.get_status_display()}.")
        except TransitionNotAllowed as exc:
            messages.error(request, str(exc))
    else:
        messages.error(request, "Transition invalide.")
    return redirect("coordination:case_detail", case_id=case.case_id)


@login_required
@require_not_read_only
@require_capability(Capability.TRIAGE_CASE)
def triage(request, case_id):
    case = _get_case(request, case_id)
    form = TriageForm(request.POST, case=case)
    if form.is_valid():
        try:
            set_severity(
                case,
                request.user,
                severity=form.cleaned_data["severity"],
                cvss_vector=form.cleaned_data.get("cvss_vector", ""),
                request=request,
            )
        except (PermissionDenied, ValidationError) as exc:
            messages.error(request, str(exc))
            return redirect("coordination:case_detail", case_id=case.case_id)

        updates = []
        if form.cleaned_data.get("cwe"):
            case.cwe = form.cleaned_data["cwe"]
            updates.append("cwe")
        if form.cleaned_data.get("organization"):
            case.organization = form.cleaned_data["organization"]
            updates.append("organization")
        if "scope" in form.fields:
            # Affecte sans condition : le triage doit aussi pouvoir retirer
            # l'actif retenu, ce qu'un test de verite empecherait.
            case.scope = form.cleaned_data.get("scope")
            updates.append("scope")
        tags = form.cleaned_data.get("tags")
        if tags is not None:
            case.tags = tags
            updates.append("tags")
        if updates:
            case.save(update_fields=updates + ["updated_at"])
            log_action(
                AuditAction.CASE_UPDATED,
                actor=request.user,
                obj=case,
                request=request,
                fields=updates,
            )
        messages.success(request, "Qualification enregistree.")
    else:
        messages.error(request, "Qualification invalide : " + form.errors.as_text())
    return redirect("coordination:case_detail", case_id=case.case_id)


@login_required
@require_not_read_only
@require_capability(Capability.ASSIGN_CASE)
def assign(request, case_id):
    case = _get_case(request, case_id)
    form = AssignmentForm(request.POST)
    if form.is_valid():
        assign_case(
            case,
            form.cleaned_data.get("assignee"),
            request.user,
            note=form.cleaned_data.get("note", ""),
            request=request,
        )
        messages.success(request, "Assignation mise a jour.")
    else:
        messages.error(request, "Assignation invalide.")
    return redirect("coordination:case_detail", case_id=case.case_id)


@login_required
@require_not_read_only
@require_capability(Capability.TRIAGE_CASE)
def mark_as_duplicate(request, case_id):
    case = _get_case(request, case_id)
    form = DuplicateForm(request.POST)
    if form.is_valid():
        try:
            mark_duplicate(
                case,
                form.cleaned_data["original_case_id"],
                request.user,
                comment=form.cleaned_data.get("comment", ""),
                request=request,
            )
            messages.success(request, "Dossier marque comme doublon.")
        except (PermissionDenied, ValidationError, TransitionNotAllowed) as exc:
            messages.error(request, str(exc))
    else:
        messages.error(request, form.errors.as_text())
    return redirect("coordination:case_detail", case_id=case.case_id)


@login_required
@require_not_read_only
@require_capability(Capability.CHANGE_CASE_STATUS)
def set_disclosure_date(request, case_id):
    case = _get_case(request, case_id)
    form = DisclosureScheduleForm(request.POST)
    if form.is_valid():
        schedule_disclosure(
            case, request.user, form.cleaned_data["disclosure_date"], request=request
        )
        messages.success(request, "Date de divulgation planifiee.")
    else:
        messages.error(request, "Date invalide.")
    return redirect("coordination:case_detail", case_id=case.case_id)


@login_required
@require_not_read_only
@require_capability(Capability.CHANGE_CASE_STATUS)
def link_cve(request, case_id):
    case = _get_case(request, case_id)
    form = CveLinkForm(request.POST)
    if form.is_valid():
        case.cve = form.cleaned_data["cve_id"]
        case.save(update_fields=["cve", "updated_at"])
        log_action(
            AuditAction.CASE_UPDATED,
            actor=request.user,
            obj=case,
            request=request,
            cve=case.cve_id,
        )
        messages.success(request, f"CVE {case.cve_id} associe au dossier.")
    else:
        messages.error(request, form.errors.as_text())
    return redirect("coordination:case_detail", case_id=case.case_id)


@login_required
@require_not_read_only
def upload_attachment(request, case_id):
    case = _get_case(request, case_id)
    form = AttachmentUploadForm(request.POST, request.FILES)
    if form.is_valid():
        try:
            store_attachment(
                form.cleaned_data["file"],
                request.user,
                case=case,
                description=form.cleaned_data.get("description", ""),
                request=request,
            )
            messages.success(request, "Piece jointe enregistree.")
        except (PermissionDenied, ValidationError) as exc:
            messages.error(request, "; ".join(getattr(exc, "messages", [str(exc)])))
    else:
        messages.error(request, "Fichier invalide.")
    return redirect("coordination:case_detail", case_id=case.case_id)
