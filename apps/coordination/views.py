"""Vues de traitement des cases (liste, Kanban, detail, actions)."""

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.paginator import Paginator
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from apps.accounts.permissions import deny, require_capability, require_not_read_only
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
    QualificationForm,
    TriageForm,
    WorkflowActionForm,
)
from .models import Case
from .services import (
    QUALIFICATION_EDITABLE_STATES,
    assign_case,
    perform_action,
    post_message,
    schedule_disclosure,
    set_severity,
    visible_messages,
)
from .visibility import case_view, has_content_access
from .workflow import (
    ADMISSIBILITY_CHECKLIST,
    MAIN_PATH,
    PUBLIC_STATUS_STEPS,
    SECONDARY,
    OutOfScope,
    TransitionNotAllowed,
    author_of,
    available_actions,
    bounty_action,
    get_action,
    primary_action,
    reporter_can_reply,
    step_number,
)


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


def user_can_click(case, action, user):
    """L'utilisateur est-il le proprietaire de ce bouton ?"""
    from .workflow import is_step_owner

    if getattr(user, "is_read_only", False):
        return False
    if action.reporter_only:
        return case.reporter_id == user.pk
    return user.has_capability(action.capability) and is_step_owner(case, action, user)


def action_panel(case, action, user):
    """Etat d'affichage d'un bouton de workflow (principal ou prime)."""
    if action is None:
        return None
    owner = user_can_click(case, action, user)
    blocked_by_four_eyes = bool(
        owner and action.four_eyes and author_of(case, action) == user.pk
    )
    missing = action.missing(case) if owner else []
    return {
        "action": action,
        "owner": owner,
        "missing": missing,
        "four_eyes_blocked": blocked_by_four_eyes,
        "enabled": owner and not missing and not blocked_by_four_eyes,
        "form": WorkflowActionForm(action=action) if owner else None,
    }


def secondary_panels(case, user):
    panels = []
    for action in available_actions(case, kind=SECONDARY):
        if not user_can_click(case, action, user):
            continue
        if action.key == "request_information" and not reporter_can_reply(case):
            # Declarant anonyme : l'action n'est pas proposee du tout (le
            # moteur la refuse de toute facon, voir _pre_request_information).
            continue
        panels.append(action_panel(case, action, user))
    return panels


def _stepper(case):
    current = step_number(case.status)
    if current is None and case.return_status:
        current = step_number(case.return_status)
    return [
        {
            "status": status,
            "label": status.label,
            "index": index,
            "done": current is not None and index < current,
            "current": index == current,
        }
        for index, status in enumerate(MAIN_PATH)
    ]


def _public_steps(current_key):
    keys = [key for key, _label in PUBLIC_STATUS_STEPS]
    current = keys.index(current_key) if current_key in keys else None
    return [
        {
            "label": label,
            "done": current is not None and index < current,
            "current": index == current,
        }
        for index, (_key, label) in enumerate(PUBLIC_STATUS_STEPS)
    ]


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
@require_capability(Capability.VIEW_ALL_CASES, Capability.VIEW_ORG_CASES)
def kanban(request):
    """Tableau de triage : l'outil de ceux qui traitent les dossiers d'autrui.

    La vue n'exigeait que d'etre connecte. Un signaleur y accedait donc, pour
    y trouver un tableau reduit a ses propres rapports, que son espace lui
    presente deja mieux.
    """
    return render(
        request,
        "coordination/kanban.html",
        {"board": selectors.kanban_board(request.user)},
    )


@login_required
def case_detail(request, case_id):
    case = _get_case(request, case_id)
    log_action(AuditAction.CASE_VIEWED, actor=request.user, obj=case, request=request)
    user = request.user
    view = case_view(case, user)

    cvss_breakdown = []
    if case.cvss_vector and view["cvss"] in ("read", "write"):
        try:
            cvss_breakdown = describe(case.cvss_vector)
        except CVSSError:
            cvss_breakdown = []

    editable = (
        case.status in QUALIFICATION_EDITABLE_STATES
        and not user.is_read_only
        and view["content"]
    )
    triage_initial = {
        "severity": case.severity,
        "cvss_vector": case.cvss_vector,
        "cwe": case.cwe_id,
        "organization": case.organization_id,
        "scope": case.scope_id,
        "tags": ", ".join(case.tags or []),
    }
    triage_form = None
    if editable and user.has_capability(Capability.SET_SEVERITY):
        triage_form = QualificationForm(case=case, initial=triage_initial)
    elif editable and user.has_capability(Capability.TRIAGE_CASE):
        triage_form = TriageForm(case=case, initial=triage_initial)

    can_arbitrate = user.has_capability(Capability.ARBITRATE_CASE)
    can_coordinate = user.has_capability(Capability.COORDINATE_VENDOR)
    primary = primary_action(case)
    bounty_step = bounty_action(case)

    context = {
        "case": case,
        "report": case.report,
        "view": view,
        "messages_list": visible_messages(case, user),
        "timeline": case.timeline.select_related("actor") if view["tracking"] else [],
        "attachments": (
            case.attachments.select_related("uploaded_by") if view["attachments_listed"] else []
        ),
        "sla_events": case.sla_events.all() if view["tracking"] else [],
        "status_history": (
            case.status_history.select_related("actor")[:30] if view["tracking"] else []
        ),
        "participants": (
            case.participants.select_related("user").filter(is_active=True)
            if view["tracking"]
            else []
        ),
        "message_form": (
            CaseMessageForm(user=user, case=case) if view["writable_channels"] else None
        ),
        "upload_form": (
            AttachmentUploadForm() if view["content"] and not user.is_read_only else None
        ),
        "primary_panel": action_panel(case, primary, user),
        "bounty_panel": action_panel(case, bounty_step, user),
        "secondary_panels": secondary_panels(case, user),
        "stepper": _stepper(case),
        "reporter_is_anonymous": not reporter_can_reply(case),
        "public_steps": _public_steps(view["status_key"]),
        "admissibility_checklist": ADMISSIBILITY_CHECKLIST,
        "triage_form": triage_form,
        "assignment_form": (
            AssignmentForm(initial={"assignee": case.assignee_id})
            if user.has_capability(Capability.ASSIGN_CASE) and not user.is_read_only
            else None
        ),
        "disclosure_form": (
            DisclosureScheduleForm(initial={"disclosure_date": case.disclosure_date})
            if (can_arbitrate or can_coordinate) and not user.is_read_only
            else None
        ),
        "cve_form": (
            CveLinkForm()
            if user.has_capability(Capability.DRAFT_ADVISORY) and not user.is_read_only
            else None
        ),
        "cvss_breakdown": cvss_breakdown,
        "can_draft_advisory": user.has_capability(Capability.DRAFT_ADVISORY),
        "bounty": getattr(case, "bounty", None) if view["wallet"] else None,
        "advisories": case.advisories.all() if view["advisory"] else [],
        # Le case original d'un doublon n'est jamais expose au declarant.
        "show_duplicate_origin": case.duplicate_of_id is not None and user.sees_all_cases,
    }
    return render(request, "coordination/case_detail.html", context)


@require_POST
@login_required
def workflow_action(request, case_id, action_key):
    """Bouton de workflow : un seul point d'entree pour toutes les actions."""
    case = _get_case(request, case_id)
    try:
        action = get_action(action_key)
    except TransitionNotAllowed as exc:
        raise Http404("Action inconnue.") from exc
    if getattr(request.user, "is_read_only", False):
        deny(request, "Role en lecture seule.", obj=case)

    form = WorkflowActionForm(request.POST, action=action)
    if not form.is_valid():
        messages.error(request, "Saisie invalide : " + form.errors.as_text())
        return redirect("coordination:case_detail", case_id=case.case_id)
    try:
        perform_action(case, action.key, request.user, data=form.workflow_data(), request=request)
    except OutOfScope as exc:
        raise Http404("Dossier introuvable.") from exc
    except TransitionNotAllowed as exc:
        messages.error(request, str(exc))
    except (PermissionDenied, ValidationError) as exc:
        messages.error(request, "; ".join(getattr(exc, "messages", [str(exc)])))
    else:
        messages.success(request, f"« {action.label} » effectué.")
    if not case.is_visible_to(request.user):
        # Un rejet confirme ou une etape franchie peut sortir le dossier du
        # perimetre de l'acteur : retour a la liste plutot qu'un 404.
        return redirect("coordination:case_list")
    return redirect("coordination:case_detail", case_id=case.case_id)


@require_POST
@login_required
@require_not_read_only
@require_capability(Capability.TRIAGE_CASE, Capability.SET_SEVERITY)
def triage(request, case_id):
    case = _get_case(request, case_id)
    if not has_content_access(case, request.user):
        deny(request, "Réservé au responsable de l'étape en cours.", obj=case)
    if case.status not in QUALIFICATION_EDITABLE_STATES:
        messages.error(request, "La qualification n'est plus modifiable à cette étape.")
        return redirect("coordination:case_detail", case_id=case.case_id)
    analyst = request.user.has_capability(Capability.SET_SEVERITY)
    form_class = QualificationForm if analyst else TriageForm
    form = form_class(request.POST, case=case)
    if not form.is_valid():
        messages.error(request, "Qualification invalide : " + form.errors.as_text())
        return redirect("coordination:case_detail", case_id=case.case_id)

    if analyst:
        try:
            set_severity(
                case,
                request.user,
                severity=form.cleaned_data["severity"],
                cvss_vector=form.cleaned_data.get("cvss_vector", ""),
                request=request,
            )
        except (PermissionDenied, ValidationError) as exc:
            messages.error(request, "; ".join(getattr(exc, "messages", [str(exc)])))
            return redirect("coordination:case_detail", case_id=case.case_id)

    updates = []
    if analyst and form.cleaned_data.get("cwe"):
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
    messages.success(request, "Qualification enregistrée." if analyst else "Rattachement enregistré.")
    return redirect("coordination:case_detail", case_id=case.case_id)


@require_POST
@login_required
@require_not_read_only
def post_case_message(request, case_id):
    case = _get_case(request, case_id)
    form = CaseMessageForm(request.POST, user=request.user, case=case)
    if form.is_valid():
        try:
            post_message(
                case,
                request.user,
                form.cleaned_data["body"],
                confidentiality=form.cleaned_data["confidentiality"],
                request=request,
            )
            messages.success(request, "Message publié.")
        except (PermissionDenied, ValidationError) as exc:
            messages.error(request, "; ".join(getattr(exc, "messages", [str(exc)])))
    else:
        messages.error(request, "Message invalide.")
    return redirect("coordination:case_detail", case_id=case.case_id)


@require_POST
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
        messages.success(request, "Assignation mise à jour.")
    else:
        messages.error(request, "Assignation invalide.")
    return redirect("coordination:case_detail", case_id=case.case_id)


@require_POST
@login_required
@require_not_read_only
@require_capability(Capability.ARBITRATE_CASE, Capability.COORDINATE_VENDOR)
def set_disclosure_date(request, case_id):
    case = _get_case(request, case_id)
    form = DisclosureScheduleForm(request.POST)
    if form.is_valid():
        schedule_disclosure(
            case, request.user, form.cleaned_data["disclosure_date"], request=request
        )
        messages.success(request, "Date de divulgation planifiée.")
    else:
        messages.error(request, "Date invalide.")
    return redirect("coordination:case_detail", case_id=case.case_id)


@require_POST
@login_required
@require_not_read_only
@require_capability(Capability.DRAFT_ADVISORY)
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


@require_POST
@login_required
@require_not_read_only
def upload_attachment(request, case_id):
    case = _get_case(request, case_id)
    if not has_content_access(case, request.user):
        deny(request, "Réservé au responsable de l'étape en cours.", obj=case)
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
            messages.success(request, "Pièce jointe enregistrée.")
        except (PermissionDenied, ValidationError) as exc:
            messages.error(request, "; ".join(getattr(exc, "messages", [str(exc)])))
    else:
        messages.error(request, "Fichier invalide.")
    return redirect("coordination:case_detail", case_id=case.case_id)
