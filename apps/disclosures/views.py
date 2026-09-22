"""Publication et consultation des advisories."""

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.paginator import Paginator
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from apps.accounts.permissions import require_capability, require_not_read_only
from apps.accounts.roles import Capability
from apps.coordination.models import Case
from apps.vulnerabilities.constants import Severity

from .forms import AdvisoryForm, AdvisoryTimelineFormSet
from .models import Advisory, AdvisoryStatus
from .services import (
    create_advisory,
    create_advisory_from_case,
    publish_advisory,
    retract_advisory,
    transition_advisory,
    update_advisory,
)


def advisory_list(request):
    """Liste publique des advisories publies."""
    queryset = Advisory.objects.published().select_related("organization", "cve", "cwe")
    severity = request.GET.get("severity", "").upper()
    query = (request.GET.get("q") or "").strip()
    if severity in Severity.values:
        queryset = queryset.filter(severity=severity)
    if query:
        queryset = queryset.filter(title__icontains=query)
    page = Paginator(queryset, 15).get_page(request.GET.get("page"))
    return render(
        request,
        "disclosures/list.html",
        {
            "page_obj": page,
            "severities": Severity.choices,
            "selected_severity": severity,
            "query": query,
        },
    )


def advisory_detail(request, advisory_id):
    """Fiche publique d'un advisory.

    Cette vue n'expose QUE les champs de l'advisory : aucune donnee du case
    prive (PoC, messages, pieces jointes, URL cible) n'est accessible ici.
    """
    advisory = get_object_or_404(
        Advisory.objects.select_related("organization", "cve", "cwe"),
        advisory_id=advisory_id.upper(),
    )
    can_preview = request.user.is_authenticated and request.user.has_capability(
        Capability.DRAFT_ADVISORY
    )
    if not advisory.is_published and not can_preview:
        raise Http404("Advisory introuvable.")
    return render(
        request,
        "disclosures/detail.html",
        {
            "advisory": advisory,
            "timeline": advisory.timeline.all(),
            "references": advisory.external_references.all(),
            "is_preview": not advisory.is_published,
        },
    )


@login_required
@require_capability(Capability.DRAFT_ADVISORY)
def advisory_manage_list(request):
    queryset = Advisory.objects.select_related("organization", "case").order_by("-created_at")
    page = Paginator(queryset, 25).get_page(request.GET.get("page"))
    return render(request, "disclosures/manage_list.html", {"page_obj": page})


@login_required
@require_not_read_only
@require_capability(Capability.DRAFT_ADVISORY)
def advisory_create(request, case_id=None):
    """Cree un brouillon d'advisory a partir d'un case valide."""
    case = None
    if case_id:
        case = get_object_or_404(Case, case_id=case_id.upper())
        if not case.is_visible_to(request.user):
            raise Http404("Dossier introuvable.")

    if request.method == "POST":
        form = AdvisoryForm(request.POST)
        if form.is_valid():
            advisory = create_advisory(
                form.save(commit=False), request.user, case=case, request=request
            )
            messages.success(request, f"Advisory {advisory.advisory_id} cree.")
            return redirect("disclosures:manage", advisory_id=advisory.advisory_id)
    elif case is not None:
        try:
            advisory = create_advisory_from_case(case, request.user, request=request)
        except PermissionDenied as exc:
            messages.error(request, str(exc))
            return redirect("coordination:case_detail", case_id=case.case_id)
        messages.success(
            request,
            f"Brouillon {advisory.advisory_id} genere a partir du dossier "
            f"{case.case_id}. Completez le resume public avant publication.",
        )
        return redirect("disclosures:manage", advisory_id=advisory.advisory_id)
    else:
        form = AdvisoryForm()
    return render(request, "disclosures/form.html", {"form": form, "case": case})


@login_required
@require_not_read_only
@require_capability(Capability.DRAFT_ADVISORY)
def advisory_manage(request, advisory_id):
    advisory = get_object_or_404(Advisory, advisory_id=advisory_id.upper())

    if request.method == "POST":
        form = AdvisoryForm(request.POST, instance=advisory)
        formset = AdvisoryTimelineFormSet(request.POST, instance=advisory)
        if form.is_valid() and formset.is_valid():
            update_advisory(form.save(commit=False), request.user, request=request)
            formset.save()
            messages.success(request, "Advisory mis a jour.")
            return redirect("disclosures:manage", advisory_id=advisory.advisory_id)
    else:
        form = AdvisoryForm(instance=advisory)
        formset = AdvisoryTimelineFormSet(instance=advisory)

    return render(
        request,
        "disclosures/manage.html",
        {
            "advisory": advisory,
            "form": form,
            "formset": formset,
            "can_publish": request.user.has_capability(Capability.PUBLISH_ADVISORY),
            "statuses": AdvisoryStatus.choices,
        },
    )


@require_POST
@login_required
@require_not_read_only
@require_capability(Capability.DRAFT_ADVISORY)
def advisory_transition(request, advisory_id):
    advisory = get_object_or_404(Advisory, advisory_id=advisory_id.upper())
    target = request.POST.get("target_status", "")
    try:
        transition_advisory(advisory, target, request.user, request=request)
        messages.success(request, f"Advisory : {advisory.get_status_display()}.")
    except (PermissionDenied, ValidationError) as exc:
        messages.error(request, "; ".join(getattr(exc, "messages", [str(exc)])))
    return redirect("disclosures:manage", advisory_id=advisory.advisory_id)


@require_POST
@login_required
@require_not_read_only
@require_capability(Capability.PUBLISH_ADVISORY)
def advisory_publish(request, advisory_id):
    advisory = get_object_or_404(Advisory, advisory_id=advisory_id.upper())
    try:
        publish_advisory(advisory, request.user, request=request)
        messages.success(request, f"Advisory {advisory.advisory_id} publie.")
    except (PermissionDenied, ValidationError) as exc:
        messages.error(request, "; ".join(getattr(exc, "messages", [str(exc)])))
    return redirect("disclosures:manage", advisory_id=advisory.advisory_id)


@require_POST
@login_required
@require_not_read_only
@require_capability(Capability.PUBLISH_ADVISORY)
def advisory_retract(request, advisory_id):
    advisory = get_object_or_404(Advisory, advisory_id=advisory_id.upper())
    reason = request.POST.get("reason", "")
    try:
        retract_advisory(advisory, request.user, reason, request=request)
        messages.success(request, "Advisory retire.")
    except (PermissionDenied, ValidationError) as exc:
        messages.error(request, "; ".join(getattr(exc, "messages", [str(exc)])))
    return redirect("disclosures:manage", advisory_id=advisory.advisory_id)
