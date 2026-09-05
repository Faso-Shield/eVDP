"""Vue publique de signalement d'une vulnerabilite."""

from django.contrib import messages
from django.core.exceptions import ValidationError
from django.shortcuts import get_object_or_404, redirect, render

from apps.attachments.services import store_attachment
from apps.core.markdown_utils import render_markdown
from apps.core.models import SiteSetting
from apps.core.ratelimit import rate_limited
from apps.core.views import DEFAULT_DISCLOSURE_POLICY
from apps.programs.models import Program
from apps.vulnerabilities.constants import ReportSource

from .forms import VulnerabilityReportForm
from .services import submit_report


@rate_limited("report")
def submit(request):
    """Formulaire public "Signaler une vulnerabilite".

    Le rapport cree est prive : il n'apparait jamais sur une page publique.
    """
    program = None
    program_slug = request.GET.get("program")
    if program_slug:
        program = Program.objects.public().filter(slug=program_slug).first()

    if request.method == "POST":
        form = VulnerabilityReportForm(
            request.POST, user=request.user if request.user.is_authenticated else None
        )
        if form.is_valid():
            report = form.save(commit=False)
            try:
                case = submit_report(
                    report,
                    request=request,
                    source=ReportSource.WEB,
                    reporter=request.user if request.user.is_authenticated else None,
                )
            except ValidationError as exc:
                messages.error(request, "; ".join(exc.messages))
            else:
                _attach_files(request, case, report)
                if request.user.is_authenticated:
                    messages.success(
                        request,
                        f"Signalement enregistre sous la reference {case.case_id}. "
                        "Suivez son traitement dans votre espace.",
                    )
                    return redirect("coordination:case_detail", case_id=case.case_id)
                return render(
                    request,
                    "reports/submitted.html",
                    {"case_id": case.case_id, "report": report},
                )
    else:
        initial = {}
        if program is not None:
            initial["program"] = program.pk
            initial["affected_organization"] = program.organization_id
        form = VulnerabilityReportForm(
            initial=initial,
            user=request.user if request.user.is_authenticated else None,
        )

    policy = SiteSetting.get_value("disclosure_policy", DEFAULT_DISCLOSURE_POLICY)
    return render(
        request,
        "reports/submit.html",
        {
            "form": form,
            "program": program,
            "policy_excerpt": render_markdown(policy[:1200]),
        },
    )


def _attach_files(request, case, report):
    """Enregistre les pieces jointes fournies avec le formulaire."""
    files = request.FILES.getlist("attachments")
    for uploaded in files[:5]:
        try:
            store_attachment(
                uploaded,
                request.user if request.user.is_authenticated else None,
                case=case,
                report=report,
                request=request,
            )
        except ValidationError as exc:
            messages.warning(
                request,
                f"Piece jointe « {uploaded.name} » refusee : {'; '.join(exc.messages)}",
            )


def submitted(request):
    return render(request, "reports/submitted.html", {})


def program_report(request, slug):
    """Point d'entree de signalement propre a un programme."""
    program = get_object_or_404(Program.objects.public(), slug=slug)
    return redirect(f"/report/?program={program.slug}")
