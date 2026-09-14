""" from django.contrib import admin

from .models import Bounty, BountyPayment, BountyReview


class BountyReviewInline(admin.TabularInline):
    model = BountyReview
    extra = 0


class BountyPaymentInline(admin.TabularInline):
    model = BountyPayment
    extra = 0


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
        "decided_at",
    )
    list_filter = ("status", "severity", "currency")
    search_fields = ("case__case_id", "researcher__email")
    readonly_fields = ("created_at", "updated_at")
    inlines = [BountyReviewInline, BountyPaymentInline]


@admin.register(BountyPayment)
class BountyPaymentAdmin(admin.ModelAdmin):
    list_display = ("bounty", "amount", "currency", "method", "status", "settled_at")
    list_filter = ("status", "method")
    search_fields = ("bounty__case__case_id", "reference")
 """

from django.contrib import admin, messages
from django.utils import timezone

from .models import Bounty, BountyPayment, BountyReview, BountyStatus


class BountyReviewInline(admin.TabularInline):
    model = BountyReview
    extra = 0
    readonly_fields = ("created_at", "updated_at")


class BountyPaymentInline(admin.TabularInline):
    model = BountyPayment
    extra = 0
    readonly_fields = ("created_at", "updated_at")


# --- Actions personnalisées pour le cycle de vie ---

@admin.action(description="Passer en revue (PENDING -> UNDER_REVIEW)")
def action_start_review(modeladmin, request, queryset):
    updated = 0
    for bounty in queryset:
        if bounty.can_transition_to(BountyStatus.UNDER_REVIEW):
            bounty.status = BountyStatus.UNDER_REVIEW
            bounty.save(update_fields=["status", "updated_at"])
            updated += 1
        else:
            modeladmin.message_user(request, f"Transition impossible pour {bounty}.", messages.WARNING)
    modeladmin.message_user(request, f"{updated} récompense(s) passée(s) en revue.", messages.SUCCESS)


@admin.action(description="Approuver la récompense (-> APPROVED)")
def action_approve(modeladmin, request, queryset):
    updated = 0
    for bounty in queryset:
        if not bounty.can_transition_to(BountyStatus.APPROVED):
            modeladmin.message_user(request, f"Transition impossible pour {bounty}.", messages.WARNING)
            continue

        # Règle stricte : séparation des droits (Proposer vs Approuver)
        if bounty.proposed_by == request.user:
            modeladmin.message_user(request, f"Interdit : vous ne pouvez pas approuver votre propre proposition ({bounty}).", messages.ERROR)
            continue

        bounty.status = BountyStatus.APPROVED
        bounty.decided_by = request.user
        bounty.decided_at = timezone.now()
        bounty.save(update_fields=["status", "decided_by", "decided_at", "updated_at"])
        updated += 1
    modeladmin.message_user(request, f"{updated} récompense(s) approuvée(s).", messages.SUCCESS)


@admin.action(description="Rejeter la récompense (-> REJECTED)")
def action_reject(modeladmin, request, queryset):
    updated = 0
    for bounty in queryset:
        if not bounty.can_transition_to(BountyStatus.REJECTED):
            modeladmin.message_user(request, f"Transition impossible pour {bounty}.", messages.WARNING)
            continue

        # Règle stricte : séparation des droits
        if bounty.proposed_by == request.user:
            modeladmin.message_user(request, f"Interdit : vous ne pouvez pas rejeter votre propre proposition ({bounty}).", messages.ERROR)
            continue

        bounty.status = BountyStatus.REJECTED
        bounty.decided_by = request.user
        bounty.decided_at = timezone.now()
        bounty.save(update_fields=["status", "decided_by", "decided_at", "updated_at"])
        updated += 1
    modeladmin.message_user(request, f"{updated} récompense(s) rejetée(s).", messages.SUCCESS)


@admin.action(description="Marquer comme payée (APPROVED -> PAID)")
def action_mark_paid(modeladmin, request, queryset):
    updated = 0
    for bounty in queryset:
        if bounty.can_transition_to(BountyStatus.PAID):
            bounty.status = BountyStatus.PAID
            bounty.save(update_fields=["status", "updated_at"])
            updated += 1
        else:
            modeladmin.message_user(request, f"Transition impossible pour {bounty}.", messages.WARNING)
    modeladmin.message_user(request, f"{updated} récompense(s) marquée(s) payée(s).", messages.SUCCESS)


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
    
    # Le statut est en lecture seule pour empêcher le contournement manuel via le menu déroulant
    readonly_fields = ("status", "created_at", "updated_at", "decided_by", "decided_at")
    inlines = [BountyReviewInline, BountyPaymentInline]
    
    # Enregistrement des actions disponibles
    actions = [action_start_review, action_approve, action_reject, action_mark_paid]

    def save_model(self, request, obj, form, change):
        # Capture automatique du proposant lors de la création
        if not change and not obj.proposed_by:
            obj.proposed_by = request.user
        super().save_model(request, obj, form, change)


@admin.register(BountyPayment)
class BountyPaymentAdmin(admin.ModelAdmin):
    list_display = ("bounty", "amount", "currency", "method", "status", "settled_at")
    list_filter = ("status", "method")
    search_fields = ("bounty__case__case_id", "reference")