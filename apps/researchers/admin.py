from django.contrib import admin

from .models import ReputationEvent, ResearcherProfile


@admin.register(ResearcherProfile)
class ResearcherProfileAdmin(admin.ModelAdmin):
    list_display = (
        "public_identity",
        "user",
        "country",
        "reputation",
        "reports_submitted",
        "reports_validated",
        "is_public_profile",
    )
    list_filter = ("identity_mode", "is_public_profile", "country")
    search_fields = ("pseudonym", "user__email", "affiliation")
    readonly_fields = (
        "reputation",
        "reports_submitted",
        "reports_validated",
        "critical_reports",
        "total_rewards",
    )
    actions = ["recompute_counters"]

    @admin.action(description="Recalculer les compteurs")
    def recompute_counters(self, request, queryset):
        for profile in queryset:
            profile.recompute()


@admin.register(ReputationEvent)
class ReputationEventAdmin(admin.ModelAdmin):
    list_display = ("profile", "reason", "points", "case", "created_at")
    list_filter = ("reason",)
    search_fields = ("profile__pseudonym", "profile__user__email")
    readonly_fields = ("created_at", "updated_at")
