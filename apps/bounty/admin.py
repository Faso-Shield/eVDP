"""Administration des recompenses.

L'administration ne reimplemente aucune regle metier : chaque action delegue
au service correspondant (apps.bounty.services), qui garantit en un seul geste
la verification de capacite, la separation proposant/approbateur, l'audit, la
notification du chercheur et la mise a jour du profil. Une action appliquee a
plusieurs lignes traite chaque recompense independamment et rapporte les refus.
"""

from django.contrib import admin, messages
from django.core.exceptions import PermissionDenied, ValidationError

from .models import Bounty, BountyPayment, BountyReview
from .services import approve_bounty, record_payment, reject_bounty


class BountyReviewInline(admin.TabularInline):
    model = BountyReview
    extra = 0
    readonly_fields = ("created_at", "updated_at")


class BountyPaymentInline(admin.TabularInline):
    model = BountyPayment
    extra = 0
    readonly_fields = ("created_at", "updated_at")


def _apply(modeladmin, request, queryset, service, success_label, **kwargs):
    """Applique un service a chaque recompense selectionnee.

    Un refus (capacite manquante, auto-approbation, transition interdite) est
    rapporte sans interrompre le traitement des autres lignes.
    """
    applied = 0
    for bounty in queryset:
        try:
            service(bounty, request.user, request=request, **kwargs)
        except (PermissionDenied, ValidationError) as exc:
            detail = "; ".join(getattr(exc, "messages", [str(exc)]))
            modeladmin.message_user(request, f"{bounty} : {detail}", messages.ERROR)
        else:
            applied += 1
    if applied:
        modeladmin.message_user(
            request, f"{applied} recompense(s) : {success_label}.", messages.SUCCESS
        )


@admin.action(description="Approuver la recompense (montant propose)")
def action_approve(modeladmin, request, queryset):
    _apply(modeladmin, request, queryset, approve_bounty, "approuvee(s)")


@admin.action(description="Rejeter la recompense")
def action_reject(modeladmin, request, queryset):
    _apply(
        modeladmin,
        request,
        queryset,
        reject_bounty,
        "rejetee(s)",
        note="Rejet depuis l'administration.",
    )


@admin.action(description="Enregistrer le versement (trace comptable)")
def action_record_payment(modeladmin, request, queryset):
    _apply(modeladmin, request, queryset, record_payment, "versement enregistre")


@admin.register(Bounty)
class BountyAdmin(admin.ModelAdmin):
    list_display = (
        "case",
        "researcher",
        "severity",
        "proposed_amount",
        "approved_amount",
        "currency",
        "status",
        "proposed_by",
        "decided_by",
        "decided_at",
    )
    list_filter = ("status", "severity", "currency")
    search_fields = ("case__case_id", "researcher__email")
    # Le cycle de vie n'est pilotable que par les actions ci-dessous : editer
    # ces champs a la main contournerait la machine a etats et l'audit.
    readonly_fields = (
        "status",
        "approved_amount",
        "decided_by",
        "decided_at",
        "created_at",
        "updated_at",
    )
    inlines = [BountyReviewInline, BountyPaymentInline]
    actions = [action_approve, action_reject, action_record_payment]

    def save_model(self, request, obj, form, change):
        # Le proposant est celui qui cree la ligne : sans lui, la separation
        # proposant / approbateur ne pourrait pas etre verifiee.
        if not change and not obj.proposed_by:
            obj.proposed_by = request.user
        super().save_model(request, obj, form, change)


@admin.register(BountyPayment)
class BountyPaymentAdmin(admin.ModelAdmin):
    list_display = ("bounty", "amount", "currency", "method", "status", "settled_at")
    list_filter = ("status", "method")
    search_fields = ("bounty__case__case_id", "reference")
