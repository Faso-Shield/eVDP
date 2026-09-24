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
    AdmissibilityForm,
    AssignmentForm,
    CaseFilterForm,
    CaseMessageForm,
    CveLinkForm,
    DisclosureScheduleForm,
    DuplicateForm,
    EscalationForm,
    FixForm,
    FixVerificationForm,
    RemediationPlanForm,
    TriageForm,
    VendorSummaryForm,
    WorkflowActionForm,
)
from .models import Case
from .services import (
    QUALIFICATION_OPEN_STATES,
    assign_case,
    build_vendor_summary,
    escalate_case,
    post_message,
    propose_duplicate,
    record_admissibility,
    record_fix,
    record_fix_verification,
    record_remediation_plan,
    record_vendor_summary,
    schedule_disclosure,
    set_severity,
    transition_case,
    visible_messages,
)
from .workflow import (
    ESCALATION_STATES,
    TransitionNotAllowed,
    button_for,
    public_status_bucket,
    secondary_actions_for,
)
from .workflow import CaseStatus as S

#: Donnees d'etape : statut courant -> (cle, formulaire, capacite, titre).
STEP_FORMS = {
    S.ACKNOWLEDGED: (
        "admissibility",
        AdmissibilityForm,
        Capability.TRIAGE_CASE,
        "Checklist de recevabilité",
    ),
    S.VALIDATED: (
        "vendor_summary",
        VendorSummaryForm,
        Capability.NOTIFY_VENDOR,
        "Version « organisation » du rapport",
    ),
    S.VENDOR_NOTIFIED: (
        "remediation_plan",
        RemediationPlanForm,
        Capability.MANAGE_REMEDIATION,
        "Plan de remédiation",
    ),
    S.REMEDIATION_IN_PROGRESS: (
        "fix",
        FixForm,
        Capability.MANAGE_REMEDIATION,
        "Correctif",
    ),
    S.FIX_AVAILABLE: (
        "fix_verification",
        FixVerificationForm,
        Capability.VERIFY_FIX,
        "Contre-vérification du correctif",
    ),
}
STEP_FORMS_BY_KEY = {value[0]: (status, *value[1:]) for status, value in STEP_FORMS.items()}


def _step_form_for(case, user, data=None):
    entry = STEP_FORMS.get(case.status)
    if entry is None or user.is_read_only or not user.has_capability(entry[2]):
        return None
    key, form_class, _cap, title = entry
    initial = {}
    if key == "vendor_summary" and not case.vendor_summary:
        initial["vendor_summary"] = build_vendor_summary(case)
    form = (
        form_class(data, instance=case, initial=initial)
        if data is not None
        else form_class(instance=case, initial=initial)
    )
    return {"key": key, "form": form, "title": title}


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


def _viewer_profile(case, user):
    """Profil d'affichage selon la matrice de visibilite de la spec v2."""
    if case.reporter_id == user.pk and not user.can_view_all_cases:
        return "reporter"
    if user.is_read_only:
        return "auditor"
    if user.is_organization_user and not user.can_view_all_cases:
        return "organization"
    return "csirt"


@login_required
def case_detail(request, case_id):
    case = _get_case(request, case_id)
    log_action(AuditAction.CASE_VIEWED, actor=request.user, obj=case, request=request)
    user = request.user
    profile = _viewer_profile(case, user)

    cvss_breakdown = []
    if case.cvss_vector and profile in ("csirt", "auditor"):
        try:
            cvss_breakdown = describe(case.cvss_vector)
        except CVSSError:
            cvss_breakdown = []

    can_write = not user.is_read_only
    can_qualify = (
        can_write
        and user.has_capability(Capability.SET_SEVERITY)
        and case.status in QUALIFICATION_OPEN_STATES
    )
    can_draft_advisory = user.has_capability(Capability.DRAFT_ADVISORY) and case.status in (
        S.FIX_VERIFIED,
    )
    message_form = CaseMessageForm(user=user, case=case)
    advisory = (
        case.current_advisory() if profile in ("csirt", "organization", "auditor") else None
    )
    advisory_issues = []
    if advisory is not None and profile == "csirt":
        from apps.disclosures.services import sanitization_issues

        advisory_issues = sanitization_issues(advisory)

    context = {
        "case": case,
        "report": case.report,
        "profile": profile,
        "show_content": profile != "auditor",
        "researcher_status": public_status_bucket(case.status)[1],
        "messages_list": visible_messages(case, user),
        # Declarant et organisation : jalons publics seulement.
        "timeline": (
            case.timeline.select_related("actor")
            if profile in ("csirt", "auditor")
            else case.timeline.filter(is_public=True)
        ),
        "attachments": case.attachments.select_related("uploaded_by"),
        "sla_events": case.sla_events.all() if profile != "reporter" else [],
        "sla_badge": case.sla_badge() if profile != "reporter" else None,
        "status_history": (
            case.status_history.select_related("actor")[:30] if profile != "reporter" else []
        ),
        "participants": (
            case.participants.select_related("user").filter(is_active=True)
            if profile in ("csirt", "auditor")
            else []
        ),
        "message_form": (
            message_form if message_form.fields["confidentiality"].choices else None
        ),
        "upload_form": AttachmentUploadForm() if can_write and profile != "auditor" else None,
        # Un bouton, un role (spec v2).
        "button": button_for(case, user),
        "action_form": WorkflowActionForm(),
        "secondary_actions": secondary_actions_for(case, user),
        "step": _step_form_for(case, user),
        "triage_form": (
            TriageForm(
                case=case,
                initial={
                    "severity": case.severity,
                    "vulnerability_type": case.vulnerability_type,
                    "cvss_vector": case.cvss_vector,
                    "cwe": case.cwe_id,
                    "organization": case.organization_id,
                    "scope": case.scope_id,
                    "tags": ", ".join(case.tags or []),
                },
            )
            if can_qualify
            else None
        ),
        "assignment_form": (
            AssignmentForm(initial={"assignee": case.assignee_id})
            if can_write and user.has_capability(Capability.ASSIGN_CASE)
            else None
        ),
        "duplicate_form": (
            DuplicateForm()
            if can_write
            and user.has_capability(Capability.PROPOSE_REJECTION)
            and any(a.action == "propose_duplicate" for a in secondary_actions_for(case, user))
            else None
        ),
        "escalation_form": (
            EscalationForm()
            if can_write
            and user.has_capability(Capability.ESCALATE_CASE)
            and case.status in ESCALATION_STATES
            else None
        ),
        "disclosure_form": (
            DisclosureScheduleForm(initial={"disclosure_date": case.disclosure_date})
            if can_write and user.has_capability(Capability.CHANGE_CASE_STATUS)
            else None
        ),
        "cve_form": (
            CveLinkForm()
            if can_write and user.has_capability(Capability.CHANGE_CASE_STATUS)
            else None
        ),
        "cvss_breakdown": cvss_breakdown,
        "is_reporter": profile == "reporter",
        "can_draft_advisory": can_draft_advisory and advisory is None,
        "advisory": advisory,
        "advisory_issues": advisory_issues,
        # Spec v2 : la DSI ne voit ni la prime ni le Wallet.
        "bounty": getattr(case, "bounty", None) if profile in ("csirt", "reporter") else None,
        "show_bounty_branch": profile == "csirt",
        "can_propose_bounty": (
            can_write
            and user.has_capability(Capability.PROPOSE_BOUNTY)
            and case.bounty_status == "BOUNTY_ELIGIBLE"
        ),
        "can_declare_not_eligible": (
            can_write
            and user.has_capability(Capability.APPROVE_BOUNTY)
            and case.bounty_status in ("UNDETERMINED", "BOUNTY_ELIGIBLE")
            and case.validated_at is not None
        ),
        # Le case original d'un doublon n'est jamais expose au declarant.
        "show_duplicate_origin": case.duplicate_of_id is not None and user.can_view_all_cases,
    }
    return render(request, "coordination/case_detail.html", context)


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
            messages.error(request, str(exc))
    else:
        messages.error(request, "Message invalide.")
    return redirect("coordination:case_detail", case_id=case.case_id)


@login_required
@require_not_read_only
def workflow_action(request, case_id):
    """Applique l'action demandee. L'interface guide, le serveur decide :
    tout passe par check_transition() (perimetre, capacite, pre-requis,
    quatre yeux, commentaire), et chaque refus est audite."""
    case = _get_case(request, case_id)
    if request.method != "POST":
        return redirect("coordination:case_detail", case_id=case.case_id)
    form = WorkflowActionForm(request.POST)
    if form.is_valid():
        try:
            transition_case(
                case,
                form.cleaned_data["action"],
                request.user,
                comment=form.cleaned_data.get("comment", ""),
                request=request,
            )
            messages.success(request, f"Dossier : {case.get_status_display()}.")
        except TransitionNotAllowed as exc:
            if exc.code == "not_found":
                raise Http404("Dossier introuvable.") from exc
            messages.error(request, str(exc))
        except (PermissionDenied, ValidationError) as exc:
            messages.error(request, "; ".join(getattr(exc, "messages", [str(exc)])))
    else:
        messages.error(request, "Action invalide.")
    return redirect("coordination:case_detail", case_id=case.case_id)


#: Compatibilite des anciennes URL : un changement de statut libre n'existe plus.
change_status = workflow_action


@login_required
@require_not_read_only
def save_step(request, case_id, step):
    """Enregistre les donnees de l'etape courante (pre-requis du bouton)."""
    case = _get_case(request, case_id)
    entry = STEP_FORMS_BY_KEY.get(step)
    if entry is None or request.method != "POST":
        raise Http404("Étape inconnue.")
    status, form_class, capability, _title = entry
    if case.status != status or not request.user.has_capability(capability):
        from apps.accounts.permissions import deny

        deny(request, f"Étape {step} : non propriétaire ou hors étape.", obj=case)
    form = form_class(request.POST, instance=Case.objects.get(pk=case.pk))
    if not form.is_valid():
        messages.error(request, form.errors.as_text())
        return redirect("coordination:case_detail", case_id=case.case_id)
    data = form.cleaned_data
    try:
        if step == "admissibility":
            record_admissibility(
                case,
                request.user,
                data["admissibility_scope_ok"],
                data["admissibility_organization_ok"],
                data["admissibility_attachment_ok"],
                request=request,
            )
        elif step == "vendor_summary":
            record_vendor_summary(case, request.user, data["vendor_summary"], request=request)
        elif step == "remediation_plan":
            record_remediation_plan(
                case,
                request.user,
                data["remediation_plan"],
                data["remediation_due_date"],
                request=request,
            )
        elif step == "fix":
            record_fix(
                case,
                request.user,
                data["fix_description"],
                data["fix_version"],
                request=request,
            )
        elif step == "fix_verification":
            record_fix_verification(
                case, request.user, data["fix_verification_notes"], request=request
            )
        messages.success(request, "Étape enregistrée.")
    except (PermissionDenied, ValidationError) as exc:
        messages.error(request, "; ".join(getattr(exc, "messages", [str(exc)])))
    return redirect("coordination:case_detail", case_id=case.case_id)


@login_required
@require_not_read_only
@require_capability(Capability.ESCALATE_CASE)
def escalate(request, case_id):
    case = _get_case(request, case_id)
    form = EscalationForm(request.POST)
    if form.is_valid():
        try:
            escalate_case(case, request.user, form.cleaned_data["comment"], request=request)
            messages.success(request, "Dossier escaladé.")
        except (PermissionDenied, ValidationError) as exc:
            messages.error(request, "; ".join(getattr(exc, "messages", [str(exc)])))
    else:
        messages.error(request, form.errors.as_text())
    return redirect("coordination:case_detail", case_id=case.case_id)


@login_required
@require_not_read_only
@require_capability(Capability.SET_SEVERITY)
def triage(request, case_id):
    """Qualification (etape 3) : seul l'analyste CSIRT saisit le CVSS."""
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
        if form.cleaned_data.get("vulnerability_type"):
            case.vulnerability_type = form.cleaned_data["vulnerability_type"]
            updates.append("vulnerability_type")
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
        messages.success(request, "Qualification enregistrée.")
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
        messages.success(request, "Assignation mise à jour.")
    else:
        messages.error(request, "Assignation invalide.")
    return redirect("coordination:case_detail", case_id=case.case_id)


@login_required
@require_not_read_only
@require_capability(Capability.PROPOSE_REJECTION)
def mark_as_duplicate(request, case_id):
    """Marquer comme doublon = proposer ; le Coordinateur confirme."""
    case = _get_case(request, case_id)
    form = DuplicateForm(request.POST)
    if form.is_valid():
        try:
            propose_duplicate(
                case,
                form.cleaned_data["original_case_id"],
                request.user,
                comment=form.cleaned_data.get("comment", ""),
                request=request,
            )
            messages.success(request, "Doublon proposé au Coordinateur.")
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
        messages.success(request, "Date de divulgation planifiée.")
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
            messages.success(request, "Pièce jointe enregistrée.")
        except (PermissionDenied, ValidationError) as exc:
            messages.error(request, "; ".join(getattr(exc, "messages", [str(exc)])))
    else:
        messages.error(request, "Fichier invalide.")
    return redirect("coordination:case_detail", case_id=case.case_id)
