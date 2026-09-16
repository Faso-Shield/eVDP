"""Vue publique de signalement d'une vulnerabilite."""

import json

from django.conf import settings
from django.contrib import messages
from django.core.exceptions import ValidationError
from django.shortcuts import get_object_or_404, redirect, render

from apps.attachments.services import store_attachment
from apps.coordination.services import public_status_for, resolve_tracking_token
from apps.core.markdown_utils import render_markdown
from apps.core.models import SiteSetting
from apps.core.ratelimit import rate_limited
from apps.core.views import DEFAULT_DISCLOSURE_POLICY
from apps.programs.models import Program, ProgramType
from apps.vulnerabilities.constants import ReportSource

from .forms import TrackingCodeForm, VulnerabilityReportForm
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
                        f"Signalement enregistré sous la référence {case.case_id}. "
                        "Suivez son traitement dans votre espace.",
                    )
                    return redirect("coordination:case_detail", case_id=case.case_id)

                tracking_token_raw = getattr(case, "tracking_token_raw", None)
                # Le code n'est affiche a l'ecran que lorsqu'aucun email n'a
                # ete fourni : sinon le lien de suivi est deja parti par
                # email, l'afficher aussi ici n'apporterait rien.
                show_tracking_code = bool(tracking_token_raw) and not report.reporter_email
                return render(
                    request,
                    "reports/submitted.html",
                    {
                        "case_id": case.case_id,
                        "report": report,
                        "tracking_code": tracking_token_raw if show_tracking_code else None,
                        "emailed_link": bool(tracking_token_raw)
                        and bool(report.reporter_email),
                    },
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
    program_anonymity_rules = {
        str(p.pk): {
            "anonymous_allowed": (
                p.allows_anonymous_reports and p.program_type != ProgramType.BUG_BOUNTY
            ),
            "is_bounty": p.program_type == ProgramType.BUG_BOUNTY,
        }
        for p in Program.objects.public().only(
            "id", "allows_anonymous_reports", "program_type"
        )
    }
    return render(
        request,
        "reports/submit.html",
        {
            "form": form,
            "program": program,
            "policy_excerpt": render_markdown(policy[:1200]),
            "program_anonymity_rules_json": json.dumps(program_anonymity_rules),
            "max_attachments": settings.EVDP["MAX_ATTACHMENTS_PER_SUBMISSION"],
        },
    )


def _attach_files(request, case, report):
    """Enregistre les pieces jointes fournies avec le formulaire."""
    limit = settings.EVDP["MAX_ATTACHMENTS_PER_SUBMISSION"]
    files = request.FILES.getlist("attachments")
    if len(files) > limit:
        messages.warning(
            request,
            f"Seuls les {limit} premiers fichiers ont été pris en compte "
            f"({len(files)} proposés) : la limite par envoi est de {limit}.",
        )
    for uploaded in files[:limit]:
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
                f"Pièce jointe « {uploaded.name} » refusée : {'; '.join(exc.messages)}",
            )


def submitted(request):
    return render(request, "reports/submitted.html", {})


@rate_limited("track_lookup")
def track_lookup(request):
    """Page « Suivre mon signalement » : saisie manuelle du code de suivi
    (declarant anonyme sans email, qui n'a donc reçu aucun lien cliquable)."""
    if request.method == "POST":
        form = TrackingCodeForm(request.POST)
        if form.is_valid():
            return redirect("reports:track_status", token=form.cleaned_data["code"])
    else:
        form = TrackingCodeForm()
    return render(request, "reports/track_lookup.html", {"form": form})


@rate_limited("track_lookup", methods=("GET", "POST"))
def track_status(request, token):
    """Statut simplifie et en lecture seule d'un dossier, via jeton de suivi.

    Reponse volontairement identique (meme template, meme code HTTP) que le
    jeton soit inconnu ou expire : rien ne doit permettre de distinguer les
    deux cas, ni de deviner l'existence d'un jeton proche.
    """
    case = resolve_tracking_token(token)
    if case is None:
        return render(request, "reports/track_status.html", {"found": False})
    return render(
        request,
        "reports/track_status.html",
        {"found": True, "status": public_status_for(case)},
    )


def program_report(request, slug):
    """Point d'entree de signalement propre a un programme."""
    program = get_object_or_404(Program.objects.public(), slug=slug)
    return redirect(f"/report/?program={program.slug}")
