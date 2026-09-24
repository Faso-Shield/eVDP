"""Vue publique de signalement d'une vulnerabilite."""

from django.contrib import messages
from django.core.exceptions import ValidationError
from django.shortcuts import get_object_or_404, redirect, render

from apps.accounts.verification import grace_deadline
from apps.coordination.services import (
    provide_information_anonymously,
    public_status_for,
    resolve_tracking_token,
)
from apps.core.markdown_utils import render_markdown
from apps.core.models import SiteSetting
from apps.core.ratelimit import rate_limited
from apps.core.views import DEFAULT_DISCLOSURE_POLICY
from apps.programs.models import Program
from apps.vulnerabilities.constants import ReportSource

from .forms import TrackingCodeForm, TrackingComplementForm, VulnerabilityReportForm
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
                    attachments=request.FILES.getlist("attachments"),
                )
            except ValidationError as exc:
                if hasattr(exc, "error_dict"):
                    for field, errors in exc.message_dict.items():
                        target = field if field in form.fields else None
                        for error in errors:
                            form.add_error(target, error)
                messages.error(request, "; ".join(exc.messages))
            else:
                if request.user.is_authenticated:
                    messages.success(
                        request,
                        f"Signalement enregistre sous la référence {case.case_id}. "
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
                        "tracking_code": (tracking_token_raw if show_tracking_code else None),
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
    return render(
        request,
        "reports/submit.html",
        {
            "form": form,
            "program": program,
            "policy_excerpt": render_markdown(policy[:1200]),
            "delai_verification": grace_deadline(request.user),
            # Meme annonce que sur la fiche du programme : un visiteur sans
            # compte arrivant sur un Bug Bounty doit le savoir avant de
            # rediger, pas au moment de l'envoi.
            "refus_participation": (
                program.reporter_rejection(request.user) if program is not None else None
            ),
        },
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

    can_answer = case.status == "NEEDS_INFORMATION" and case.reporter_id is None
    form = TrackingComplementForm() if can_answer else None
    if request.method == "POST" and can_answer:
        form = TrackingComplementForm(request.POST)
        if form.is_valid():
            try:
                provide_information_anonymously(
                    case,
                    form.cleaned_data["body"],
                    attachments=request.FILES.getlist("attachments"),
                    request=request,
                )
            except ValidationError as exc:
                messages.error(request, "; ".join(exc.messages))
            else:
                messages.success(
                    request,
                    "Merci : vos compléments ont été transmis à l'équipe de coordination.",
                )
                return redirect("reports:track_status", token=token)
    return render(
        request,
        "reports/track_status.html",
        {"found": True, "status": public_status_for(case), "form": form, "token": token},
    )


def program_report(request, slug):
    """Point d'entree de signalement propre a un programme."""
    program = get_object_or_404(Program.objects.public(), slug=slug)
    return redirect(f"/report/?program={program.slug}")
