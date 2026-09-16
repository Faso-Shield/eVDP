"""Vues de gestion des recompenses Bug Bounty."""

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.paginator import Paginator
from django.db import models
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect, render

from apps.accounts.permissions import require_capability, require_not_read_only
from apps.accounts.roles import Capability
from apps.coordination.models import Case

from .forms import BountyDecisionForm, BountyProposalForm, BountyReviewForm, PaymentForm
from .models import Bounty, BountyStatus
from .services import (
    approve_bounty,
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
    visible = _visible_bounties(request.user)
    status = request.GET.get("status", "").upper()
    queryset = visible.filter(status=status) if status else visible
    page = Paginator(queryset.order_by("-created_at"), 25).get_page(request.GET.get("page"))

    paid_total = visible.filter(status=BountyStatus.PAID).aggregate(
        total=models.Sum("approved_amount")
    )["total"] or 0
    return render(
        request,
        "bounty/list.html",
        {
            "page_obj": page,
            "selected_status": status,
            "statuses": BountyStatus.choices,
            "stats": {
                "total": visible.count(),
                "pending": visible.filter(status=BountyStatus.PENDING).count(),
                "approved": visible.filter(status=BountyStatus.APPROVED).count(),
                "paid": visible.filter(status=BountyStatus.PAID).count(),
                "paid_total": paid_total,
            },
        },
    )


@login_required
def bounty_detail(request, bounty_id):
    bounty = _get_bounty(request, bounty_id)
    # Un chercheur consultant sa propre recompense ne doit voir ni les notes
    # de triage interne (avis, justifications, references de paiement), ni
    # l'identite des agents CSIRT qui l'ont traitee : seuls le montant, le
    # statut et la date lui sont opposables. C'est le montant, jamais la
    # deliberation, qui doit etre visible (norme HackerOne/Bugcrowd).
    is_staff_viewer = request.user.is_national or request.user.is_organization_user
    context = {
        "bounty": bounty,
        "is_staff_viewer": is_staff_viewer,
        "payments": bounty.payments.select_related("recorded_by"),
        "can_approve": request.user.has_capability(Capability.APPROVE_BOUNTY),
        "can_pay": request.user.has_capability(Capability.RECORD_PAYMENT),
        "within_policy": bounty.within_policy(),
    }
    if is_staff_viewer:
        context["reviews"] = bounty.reviews.select_related("reviewer")
        context["decision_form"] = BountyDecisionForm(initial={"amount": bounty.proposed_amount})
        context["review_form"] = BountyReviewForm()
        context["payment_form"] = PaymentForm(initial={"amount": bounty.approved_amount})
    return render(request, "bounty/detail.html", context)


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
                messages.success(request, "Récompense proposée.")
                return redirect("bounty:detail", bounty_id=bounty.pk)
    else:
        form = BountyProposalForm(initial={"amount": default_amount})

    return render(
        request,
        "bounty/propose.html",
        {"case": case, "form": form, "suggested": default_amount, "currency": currency},
    )


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
            messages.success(request, "Avis enregistré.")
        except PermissionDenied as exc:
            messages.error(request, str(exc))
    else:
        messages.error(request, form.errors.as_text())
    return redirect("bounty:detail", bounty_id=bounty.pk)


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
            messages.success(request, "Récompense approuvée.")
        except (PermissionDenied, ValidationError) as exc:
            messages.error(request, "; ".join(getattr(exc, "messages", [str(exc)])))
    else:
        messages.error(request, form.errors.as_text())
    return redirect("bounty:detail", bounty_id=bounty.pk)


@login_required
@require_not_read_only
@require_capability(Capability.APPROVE_BOUNTY)
def reject(request, bounty_id):
    bounty = _get_bounty(request, bounty_id)
    form = BountyDecisionForm(request.POST)
    note = (
        form.data.get("note", "") if not form.is_valid() else form.cleaned_data.get("note", "")
    )
    try:
        reject_bounty(bounty, request.user, note=note, request=request)
        messages.success(request, "Récompense rejetée.")
    except (PermissionDenied, ValidationError) as exc:
        messages.error(request, "; ".join(getattr(exc, "messages", [str(exc)])))
    return redirect("bounty:detail", bounty_id=bounty.pk)


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
                "Versement enregistré. Aucun flux financier réel n'est déclenché "
                "par la plateforme.",
            )
        except (PermissionDenied, ValidationError) as exc:
            messages.error(request, "; ".join(getattr(exc, "messages", [str(exc)])))
    else:
        messages.error(request, form.errors.as_text())
    return redirect("bounty:detail", bounty_id=bounty.pk)
