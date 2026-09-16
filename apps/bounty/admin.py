from django.contrib import admin

from .models import Bounty, BountyPayment, BountyReview


class BountyReviewInline(admin.TabularInline):
    model = BountyReview
    extra = 0


class BountyPaymentInline(admin.TabularInline):
    """Lecture seule : un versement ne doit etre cree que via
    apps.bounty.services.record_payment (journalise, capacite verifiee)."""

    model = BountyPayment
    extra = 0

    def has_add_permission(self, request, obj=None):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(Bounty)
class BountyAdmin(admin.ModelAdmin):
    """Le statut, le montant approuve et la decision ne sont pas modifiables
    ici : ils ne doivent transiter que par apps.bounty.services (propose /
    review / approve / reject), qui verifie les capacites, la separation
    proposeur/approbateur et journalise chaque decision. Un champ modifiable
    directement en admin contournerait ces garanties sans laisser de trace.
    """

    list_display = (
        "case",
        "researcher",
        "severity",
        "proposed_amount",
        "approved_amount",
        "currency",
        "status",
        "decided_at",
    )
    list_filter = ("status", "severity", "currency")
    search_fields = ("case__case_id", "researcher__email")
    readonly_fields = (
        "status",
        "approved_amount",
        "decided_by",
        "decided_at",
        "decision_note",
        "proposed_by",
        "created_at",
        "updated_at",
    )
    inlines = [BountyReviewInline, BountyPaymentInline]

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(BountyPayment)
class BountyPaymentAdmin(admin.ModelAdmin):
    """Le statut d'un versement ne se modifie que via
    apps.bounty.services.record_payment (journalise). Non modifiable ici.
    """

    list_display = ("bounty", "amount", "currency", "method", "status", "settled_at")
    list_filter = ("status", "method")
    search_fields = ("bounty__case__case_id", "reference")
    readonly_fields = ("status", "recorded_by", "created_at", "updated_at")

    def has_delete_permission(self, request, obj=None):
        return False
