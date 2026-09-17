from django.contrib import admin

from .models import PayoutMethod, PayoutProfile, ReputationEvent, ResearcherProfile


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


class PayoutMethodInline(admin.TabularInline):
    """Moyens de paiement affiches masques : les numeros complets restent
    consultables via le formulaire d'edition d'une ligne, jamais en liste."""

    model = PayoutMethod
    extra = 0
    fields = ("method_type", "summary", "is_primary", "is_active")
    readonly_fields = ("summary",)
    show_change_link = True


@admin.register(PayoutProfile)
class PayoutProfileAdmin(admin.ModelAdmin):
    list_display = ("user", "legal_full_name", "country", "is_complete")
    search_fields = ("user__email", "legal_full_name")
    readonly_fields = ("created_at", "updated_at")
    inlines = [PayoutMethodInline]

    @admin.display(boolean=True, description="Complet")
    def is_complete(self, obj):
        return obj.is_complete


@admin.register(PayoutMethod)
class PayoutMethodAdmin(admin.ModelAdmin):
    # Les identifiants sensibles (compte, numero mobile) n'apparaissent
    # jamais en liste : seul le resume masque (summary) y figure.
    list_display = ("profile", "method_type", "summary", "is_primary", "is_active")
    list_filter = ("method_type", "is_primary", "is_active")
    search_fields = ("profile__user__email", "bank_name", "other_label")
    readonly_fields = ("created_at", "updated_at")
