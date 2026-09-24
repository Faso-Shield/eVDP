"""Vues de gestion des recompenses Bug Bounty."""

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.paginator import Paginator
from django.http import FileResponse, Http404
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from apps.accounts.permissions import require_capability, require_not_read_only
from apps.accounts.roles import Capability
from apps.attachments.views import safe_filename
from apps.audit.models import AuditAction
from apps.audit.services import log_action
from apps.coordination.models import Case
from apps.coordination.services import perform_action
from apps.coordination.workflow import TransitionNotAllowed

from .forms import (
    BountyDecisionForm,
    BountyProposalForm,
    BountyReviewForm,
    PaymentFailureForm,
    PaymentForm,
    SettlementForm,
)
from .models import BountyPayment
from .services import (
    SETTLEMENT_ELIGIBLE_CASE_STATUSES,
    authorize_proof_download,
    budget_status,
    confirm_settlement,
    mark_payment_failed,
    record_payment,
    reject_bounty,
    review_bounty,
    suggested_amount,
    visible_bounties,
)


def _visible_bounties(user):
    """Isolation : chaque profil ne voit que les recompenses de son perimetre."""
    return visible_bounties(user)


def _get_bounty(request, bounty_id):
    """Prime du perimetre de l'utilisateur (visible_bounties), sinon 404.

    Le perimetre des primes suffit : un versement a traiter reste accessible
    a qui l'enregistre, meme une fois le dossier sorti de son etape.
    """
    return get_object_or_404(_visible_bounties(request.user), pk=bounty_id)


def _get_payment(request, payment_id):
    return get_object_or_404(
        BountyPayment.objects.select_related("bounty__case"),
        pk=payment_id,
        bounty__in=_visible_bounties(request.user),
    )


def _instruit_les_recompenses(user):
    """Le compte participe-t-il a l'instruction d'une recompense ?

    C'est la frontiere entre celui qui decide et celui qui recoit. Un
    signaleur voit sa recompense parce qu'elle le concerne ; il n'a pas a
    savoir qui l'a proposee, qui en a debattu, ni qui l'a signee. La
    deliberation d'un jury ne se communique pas au candidat.
    """
    return user.has_capability(Capability.PROPOSE_BOUNTY) or user.has_capability(
        Capability.APPROVE_BOUNTY
    )


@login_required
def bounty_list(request):
    queryset = _visible_bounties(request.user).order_by("-created_at")
    status = request.GET.get("status", "").upper()
    if status:
        queryset = queryset.filter(status=status)
    page = Paginator(queryset, 25).get_page(request.GET.get("page"))
    return render(
        request,
        "bounty/list.html",
        {
            "page_obj": page,
            "selected_status": status,
            "peut_instruire": _instruit_les_recompenses(request.user),
        },
    )


@login_required
def bounty_detail(request, bounty_id):
    bounty = _get_bounty(request, bounty_id)
    peut_instruire = _instruit_les_recompenses(request.user)
    can_pay = request.user.has_capability(Capability.RECORD_PAYMENT)
    contexte = {
        "bounty": bounty,
        "payments": bounty.payments.select_related("recorded_by"),
        "peut_instruire": peut_instruire,
        # Le proposant ne peut pas statuer sur sa propre proposition :
        # l'interface masque l'action, le service la refuse (defense en
        # profondeur, voir bounty.services.approve_bounty).
        "can_approve": (
            request.user.has_capability(Capability.APPROVE_BOUNTY)
            and bounty.proposed_by_id != request.user.pk
        ),
        "can_pay": can_pay,
    }
    # Les elements d'instruction ne sont pas seulement masques par le gabarit :
    # ils ne quittent pas la base pour un compte qui n'a pas a les lire. Le
    # budget du programme en fait partie - il ne regarde pas le beneficiaire.
    if peut_instruire:
        contexte.update(
            {
                "reviews": bounty.reviews.select_related("reviewer"),
                "decision_form": BountyDecisionForm(
                    initial={"amount": bounty.proposed_amount}
                ),
                "review_form": BountyReviewForm(),
                "payment_form": PaymentForm(initial={"amount": bounty.approved_amount}),
                "within_policy": bounty.within_policy(),
                "budget": budget_status(bounty),
            }
        )
    # Le portefeuille du chercheur ne regarde que qui va effectivement payer :
    # meme principe que ci-dessus, applique a la capacite la plus precise.
    if can_pay:
        payout_profile = (
            getattr(bounty.researcher, "payout_profile", None)
            if bounty.researcher_id
            else None
        )
        contexte["payout_profile"] = payout_profile
        contexte["payout_method"] = (
            payout_profile.methods.filter(is_primary=True, is_active=True).first()
            if payout_profile
            else None
        )
        # Reference de paiement en clair (nom legal et moyen principal) : elle
        # sert a qui execute et rapproche le versement (RECORD_PAYMENT, le
        # Coordinateur). Workflow v2 : jamais au super admin, qui n'a acces ni
        # aux dossiers ni au Wallet. Chaque consultation est journalisee.
        if contexte["payout_method"]:
            log_action(
                AuditAction.PAYOUT_REFERENCE_VIEWED,
                actor=request.user,
                obj=contexte["payout_method"],
                request=request,
                case=bounty.case.case_id,
            )
        contexte["settlement_form"] = SettlementForm()
        contexte["failure_form"] = PaymentFailureForm()
        contexte["settlement_eligible"] = (
            bounty.case.status in SETTLEMENT_ELIGIBLE_CASE_STATUSES
        )
    return render(request, "bounty/detail.html", contexte)


@login_required
@require_not_read_only
@require_capability(Capability.PROPOSE_BOUNTY)
def propose(request, case_id):
    case = get_object_or_404(Case, case_id=case_id.upper())
    if not case.is_visible_to(request.user):
        raise Http404("Dossier introuvable.")

    default_amount, currency = suggested_amount(case)
    if request.method == "POST":
        form = BountyProposalForm(request.POST)
        if form.is_valid():
            try:
                perform_action(
                    case,
                    "propose_bounty",
                    request.user,
                    data={
                        "amount": form.cleaned_data["amount"],
                        "justification": form.cleaned_data.get("justification", ""),
                    },
                    request=request,
                )
                bounty = case.bounty
            except TransitionNotAllowed as exc:
                messages.error(request, str(exc))
            except (PermissionDenied, ValidationError) as exc:
                messages.error(request, "; ".join(getattr(exc, "messages", [str(exc)])))
            else:
                messages.success(request, "Récompense proposée.")
                return redirect("bounty:detail", bounty_id=bounty.pk)
    else:
        form = BountyProposalForm(initial={"amount": default_amount})

    return render(
        request,
        "bounty/propose.html",
        {"case": case, "form": form, "suggested": default_amount, "currency": currency},
    )


@require_POST
@login_required
@require_not_read_only
@require_capability(Capability.PROPOSE_BOUNTY, Capability.APPROVE_BOUNTY)
def review(request, bounty_id):
    bounty = _get_bounty(request, bounty_id)
    form = BountyReviewForm(request.POST)
    if form.is_valid():
        try:
            review_bounty(
                bounty,
                request.user,
                form.cleaned_data["decision"],
                comment=form.cleaned_data.get("comment", ""),
                suggested=form.cleaned_data.get("suggested_amount"),
                request=request,
            )
            messages.success(request, "Avis enregistré.")
        except PermissionDenied as exc:
            messages.error(request, str(exc))
    else:
        messages.error(request, form.errors.as_text())
    return redirect("bounty:detail", bounty_id=bounty.pk)


@require_POST
@login_required
@require_not_read_only
@require_capability(Capability.APPROVE_BOUNTY)
def approve(request, bounty_id):
    bounty = _get_bounty(request, bounty_id)
    form = BountyDecisionForm(request.POST)
    if form.is_valid():
        try:
            perform_action(
                bounty.case,
                "approve_bounty",
                request.user,
                data={
                    "amount": form.cleaned_data.get("amount"),
                    "comment": form.cleaned_data.get("note", ""),
                },
                request=request,
            )
            messages.success(request, "Récompense approuvée et Wallet crédité.")
        except TransitionNotAllowed as exc:
            messages.error(request, str(exc))
        except (PermissionDenied, ValidationError) as exc:
            messages.error(request, "; ".join(getattr(exc, "messages", [str(exc)])))
    else:
        messages.error(request, form.errors.as_text())
    return redirect("bounty:detail", bounty_id=bounty.pk)


@require_POST
@login_required
@require_not_read_only
@require_capability(Capability.APPROVE_BOUNTY)
def reject(request, bounty_id):
    bounty = _get_bounty(request, bounty_id)
    form = BountyDecisionForm(request.POST)
    if form.is_valid():
        try:
            reject_bounty(
                bounty, request.user, note=form.cleaned_data.get("note", ""), request=request
            )
            messages.success(request, "Récompense rejetée.")
        except (PermissionDenied, ValidationError) as exc:
            messages.error(request, "; ".join(getattr(exc, "messages", [str(exc)])))
    else:
        messages.error(request, form.errors.as_text())
    return redirect("bounty:detail", bounty_id=bounty.pk)


@require_POST
@login_required
@require_not_read_only
@require_capability(Capability.RECORD_PAYMENT)
def payment(request, bounty_id):
    bounty = _get_bounty(request, bounty_id)
    form = PaymentForm(request.POST)
    if form.is_valid():
        try:
            recorded = record_payment(
                bounty,
                request.user,
                amount=form.cleaned_data.get("amount"),
                method=form.cleaned_data["method"],
                reference=form.cleaned_data.get("reference", ""),
                request=request,
            )
            if recorded.payout_warning:
                messages.warning(
                    request,
                    f"Versement enregistre, mais {recorded.payout_warning} "
                    "cote portefeuille : verifiez aupres du chercheur avant "
                    "d'executer le versement reel.",
                )
            messages.success(
                request,
                "Versement enregistre. Aucun flux financier réel n'est déclenché "
                "par la plateforme.",
            )
        except (PermissionDenied, ValidationError) as exc:
            messages.error(request, "; ".join(getattr(exc, "messages", [str(exc)])))
    else:
        messages.error(request, form.errors.as_text())
    return redirect("bounty:detail", bounty_id=bounty.pk)


@require_POST
@login_required
@require_not_read_only
@require_capability(Capability.RECORD_PAYMENT)
def settle_payment(request, payment_id):
    payment_obj = _get_payment(request, payment_id)
    form = SettlementForm(request.POST, request.FILES)
    if form.is_valid():
        try:
            confirm_settlement(
                payment_obj,
                request.user,
                proof_file=form.cleaned_data["proof_file"],
                note=form.cleaned_data.get("note", ""),
                request=request,
            )
            messages.success(request, "Versement confirmé réglé.")
        except (PermissionDenied, ValidationError) as exc:
            messages.error(request, "; ".join(getattr(exc, "messages", [str(exc)])))
    else:
        messages.error(request, form.errors.as_text())
    return redirect("bounty:detail", bounty_id=payment_obj.bounty_id)


@require_POST
@login_required
@require_not_read_only
@require_capability(Capability.RECORD_PAYMENT)
def fail_payment(request, payment_id):
    payment_obj = _get_payment(request, payment_id)
    form = PaymentFailureForm(request.POST)
    if form.is_valid():
        try:
            mark_payment_failed(
                payment_obj, request.user, reason=form.cleaned_data["reason"], request=request
            )
            messages.success(request, "Versement marqué en échec.")
        except (PermissionDenied, ValidationError) as exc:
            messages.error(request, "; ".join(getattr(exc, "messages", [str(exc)])))
    else:
        messages.error(request, form.errors.as_text())
    return redirect("bounty:detail", bounty_id=payment_obj.bounty_id)


@login_required
@require_capability(Capability.RECORD_PAYMENT)
def payment_proof_download(request, payment_id):
    """Telechargement controle de la preuve de paiement.

    Comme pour le justificatif d'identite du portefeuille : aucun fichier
    n'est servi directement, l'acces est reserve au meme perimetre que
    l'enregistrement des versements et journalise.
    """
    payment_obj = _get_payment(request, payment_id)
    if not payment_obj.proof_file:
        raise Http404("Aucune preuve enregistrée.")
    if not authorize_proof_download(payment_obj, request.user, request=request):
        raise Http404("Preuve introuvable.")

    response = FileResponse(
        payment_obj.proof_file.open("rb"),
        as_attachment=True,
        filename=safe_filename(payment_obj.proof_original_filename),
        content_type="application/octet-stream",
    )
    response["X-Content-Type-Options"] = "nosniff"
    response["Content-Security-Policy"] = "default-src 'none'; sandbox"
    response["Cache-Control"] = "no-store, private"
    return response
