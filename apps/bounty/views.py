"""Vues de gestion des recompenses Bug Bounty."""

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

from .forms import BountyDecisionForm, BountyProposalForm, BountyReviewForm, PaymentForm
from .models import Bounty
from .services import (
    approve_bounty,
    budget_status,
    propose_bounty,
    record_payment,
    reject_bounty,
    review_bounty,
    suggested_amount,
)


def _visible_bounties(user):
    """Isolation : chaque profil ne voit que les recompenses de son perimetre."""
    queryset = Bounty.objects.select_related("case", "program", "researcher")
    if user.is_national:
        return queryset
    case_ids = Case.objects.visible_to(user).values_list("id", flat=True)
    return queryset.filter(case_id__in=case_ids)


def _get_bounty(request, bounty_id):
    bounty = get_object_or_404(
        Bounty.objects.select_related("case", "program", "researcher"), pk=bounty_id
    )
    if not bounty.case.is_visible_to(request.user):
        raise Http404("Recompense introuvable.")
    return bounty


@login_required
def bounty_list(request):
    queryset = _visible_bounties(request.user).order_by("-created_at")
    status = request.GET.get("status", "").upper()
    if status:
        queryset = queryset.filter(status=status)
    page = Paginator(queryset, 25).get_page(request.GET.get("page"))
    return render(request, "bounty/list.html", {"page_obj": page, "selected_status": status})


@login_required
def bounty_detail(request, bounty_id):
    bounty = _get_bounty(request, bounty_id)
    return render(
        request,
        "bounty/detail.html",
        {
            "bounty": bounty,
            "reviews": bounty.reviews.select_related("reviewer"),
            "payments": bounty.payments.select_related("recorded_by"),
            "decision_form": BountyDecisionForm(initial={"amount": bounty.proposed_amount}),
            "review_form": BountyReviewForm(),
            "payment_form": PaymentForm(initial={"amount": bounty.approved_amount}),
            # Le proposant ne peut pas statuer sur sa propre proposition :
            # l'interface masque l'action, le service la refuse (defense en
            # profondeur, voir bounty.services.approve_bounty).
            "can_approve": (
                request.user.has_capability(Capability.APPROVE_BOUNTY)
                and bounty.proposed_by_id != request.user.pk
            ),
            "can_pay": request.user.has_capability(Capability.RECORD_PAYMENT),
            "within_policy": bounty.within_policy(),
            "budget": budget_status(bounty),
        },
    )


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
                bounty = propose_bounty(
                    case,
                    request.user,
                    amount=form.cleaned_data["amount"],
                    justification=form.cleaned_data.get("justification", ""),
                    request=request,
                )
            except (PermissionDenied, ValidationError) as exc:
                messages.error(request, "; ".join(getattr(exc, "messages", [str(exc)])))
            else:
                messages.success(request, "Recompense proposee.")
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
@require_capability(Capability.PROPOSE_BOUNTY)
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
            messages.success(request, "Avis enregistre.")
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
            approve_bounty(
                bounty,
                request.user,
                amount=form.cleaned_data.get("amount"),
                note=form.cleaned_data.get("note", ""),
                request=request,
            )
            messages.success(request, "Recompense approuvee.")
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
            messages.success(request, "Recompense rejetee.")
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
            record_payment(
                bounty,
                request.user,
                amount=form.cleaned_data.get("amount"),
                method=form.cleaned_data["method"],
                reference=form.cleaned_data.get("reference", ""),
                request=request,
            )
            messages.success(
                request,
                "Versement enregistre. Aucun flux financier reel n'est declenche "
                "par la plateforme.",
            )
        except (PermissionDenied, ValidationError) as exc:
            messages.error(request, "; ".join(getattr(exc, "messages", [str(exc)])))
    else:
        messages.error(request, form.errors.as_text())
    return redirect("bounty:detail", bounty_id=bounty.pk)
