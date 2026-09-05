from django.contrib import admin

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
