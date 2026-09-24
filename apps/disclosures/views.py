"""Publication et consultation des advisories."""

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.paginator import Paginator
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect, render

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
    can_preview = request.user.is_authenticated and (
        request.user.has_capability(Capability.DRAFT_ADVISORY)
        or request.user.has_capability(Capability.PUBLISH_ADVISORY)
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
@require_capability(Capability.DRAFT_ADVISORY, Capability.PUBLISH_ADVISORY)
def advisory_manage_list(request):
    queryset = Advisory.objects.select_related("organization", "case").order_by("-created_at")
    page = Paginator(queryset, 25).get_page(request.GET.get("page"))
    return render(request, "disclosures/manage_list.html", {"page_obj": page})


@login_required
@require_not_read_only
@require_capability(Capability.DRAFT_ADVISORY, Capability.PUBLISH_ADVISORY)
def advisory_create(request, case_id=None):
    """Cree un brouillon d'advisory a partir d'un case valide."""
    case = None
    if not case_id and not request.user.has_capability(Capability.DRAFT_ADVISORY):
        # Advisory autonome (sans dossier) : redaction de l'analyste seulement.
        raise PermissionDenied("Capacité requise pour rédiger un advisory.")
    if case_id:
        from apps.coordination.workflow import can_edit_case_advisory, working_advisory

        case = get_object_or_404(Case, case_id=case_id.upper())
        if not case.is_visible_to(request.user):
            raise Http404("Dossier introuvable.")
        # Seul le responsable de l'etape (analyste a l'etape 9, Coordinateur a
        # l'etape 10) redige l'advisory du dossier.
        if not can_edit_case_advisory(case, request.user):
            raise Http404("Dossier introuvable.")
        existing = working_advisory(case)
        if existing is not None:
            # Un seul brouillon par dossier : on reprend celui en cours.
            return redirect("disclosures:manage", advisory_id=existing.advisory_id)

    if request.method == "POST":
        form = AdvisoryForm(request.POST)
        if form.is_valid():
            advisory = create_advisory(
                form.save(commit=False), request.user, case=case, request=request
            )
            messages.success(request, f"Advisory {advisory.advisory_id} créé.")
            return redirect("disclosures:manage", advisory_id=advisory.advisory_id)
    elif case is not None:
        try:
            advisory = create_advisory_from_case(case, request.user, request=request)
        except PermissionDenied as exc:
            messages.error(request, str(exc))
            return redirect("coordination:case_detail", case_id=case.case_id)
        messages.success(
            request,
            f"Proposition d'advisory {advisory.advisory_id} générée à partir du "
            f"dossier {case.case_id} : relisez-la et complétez-la avant de la soumettre.",
        )
        return redirect("disclosures:manage", advisory_id=advisory.advisory_id)
    else:
        form = AdvisoryForm()
    return render(request, "disclosures/form.html", {"form": form, "case": case})


def _appliquer_action(request, advisory):
    """Enchaine l'action de cycle de vie demandee apres l'enregistrement.

    Le contenu et le cycle de vie vivent dans un seul formulaire. Ils etaient
    separes : le redacteur saisissait son resume, cliquait « Publier », et la
    publication - postee par un autre formulaire - ne voyait que ce qui etait
    deja en base. Elle refusait alors un resume pourtant saisi sous ses yeux.
    L'enregistrement precede desormais toute transition, et rien ne se perd.
    """
    action = request.POST.get("action", "save")
    if action == "save":
        messages.success(request, "Advisory mis à jour.")
        return advisory

    try:
        if action == "publish":
            publish_advisory(advisory, request.user, request=request)
            messages.success(request, f"Advisory {advisory.advisory_id} publié.")
        elif action == "retract":
            retract_advisory(
                advisory, request.user, request.POST.get("reason", ""), request=request
            )
            messages.success(request, "Advisory retiré.")
        elif action == "status":
            transition_advisory(
                advisory,
                request.POST.get("target_status", ""),
                request.user,
                request=request,
            )
            messages.success(request, f"Advisory : {advisory.get_status_display()}.")
        else:
            messages.success(request, "Advisory mis à jour.")
            return advisory
    except (PermissionDenied, ValidationError) as exc:
        messages.success(request, "Contenu enregistré.")
        messages.error(request, "; ".join(getattr(exc, "messages", [str(exc)])))
    return advisory


@login_required
@require_not_read_only
@require_capability(Capability.DRAFT_ADVISORY, Capability.PUBLISH_ADVISORY)
def advisory_manage(request, advisory_id):
    """Redaction (analyste) et relecture / publication (coordinateur).

    Matrice v2 : le brouillon d'advisory est en acces complet pour
    l'analyste et le coordinateur.
    """
    advisory = get_object_or_404(Advisory, advisory_id=advisory_id.upper())
    if (
        advisory.case_id
        and not advisory.is_published
        and advisory.status != AdvisoryStatus.RETRACTED
    ):
        # Brouillon d'un dossier : au seul responsable de l'etape en cours.
        from apps.coordination.workflow import can_edit_case_advisory

        if not can_edit_case_advisory(advisory.case, request.user):
            raise Http404("Advisory introuvable.")

    if request.method == "POST":
        form = AdvisoryForm(request.POST, instance=advisory)
        formset = AdvisoryTimelineFormSet(request.POST, instance=advisory)
        if form.is_valid() and formset.is_valid():
            update_advisory(form.save(commit=False), request.user, request=request)
            formset.save()
            _appliquer_action(request, advisory)
            return redirect("disclosures:manage", advisory_id=advisory.advisory_id)
        messages.error(
            request,
            "Le formulaire comporte des erreurs : rien n'a été enregistre.",
        )
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
