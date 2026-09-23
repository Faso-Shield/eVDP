from django.contrib import admin

from .models import Program, ProgramRule, ProgramScope, RewardPolicy, RewardTier


class ProgramScopeInline(admin.TabularInline):
    model = ProgramScope
    extra = 0


class ProgramRuleInline(admin.TabularInline):
    model = ProgramRule
    extra = 0


class RewardTierInline(admin.TabularInline):
    model = RewardTier
    extra = 0
    fields = ("scope", "severity", "min_amount", "max_amount", "description")

    def formfield_for_foreignkey(self, db_field, request, **kwargs):
        """N'offre que les actifs du programme de la politique editee.

        Sans ce filtrage, l'administration proposerait le perimetre de tous
        les programmes et la validation du modele rejetterait la saisie.
        """
        if db_field.name == "scope":
            policy_id = (request.resolver_match.kwargs or {}).get("object_id")
            kwargs["queryset"] = (
                ProgramScope.objects.filter(
                    program__reward_policy=policy_id, in_scope=True, is_active=True
                )
                if policy_id
                else ProgramScope.objects.none()
            )
        return super().formfield_for_foreignkey(db_field, request, **kwargs)


@admin.register(Program)
class ProgramAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "program_type",
        "organization",
        "status",
        "confidentiality",
        "starts_on",
        "ends_on",
    )
    list_filter = ("program_type", "status", "confidentiality")
    search_fields = ("name", "organization__name", "summary")
    prepopulated_fields = {"slug": ("name",)}
    inlines = [ProgramScopeInline, ProgramRuleInline]
    autocomplete_fields = ["organization"]
    actions = ["activate", "pause"]

    @admin.action(description="Activer les programmes selectionnes")
    def activate(self, request, queryset):
        queryset.update(status="ACTIVE")

    @admin.action(description="Suspendre les programmes selectionnes")
    def pause(self, request, queryset):
        queryset.update(status="PAUSED")


@admin.register(RewardPolicy)
class RewardPolicyAdmin(admin.ModelAdmin):
    list_display = ("program", "currency", "is_active", "total_budget")
    list_filter = ("is_active", "currency")
    search_fields = ("program__name",)
    inlines = [RewardTierInline]


@admin.register(ProgramScope)
class ProgramScopeAdmin(admin.ModelAdmin):
    list_display = (
        "identifier",
        "program",
        "in_scope",
        "target_type",
        "priority",
        "is_active",
    )
    list_filter = ("in_scope", "target_type", "priority", "is_active")
    search_fields = ("identifier", "program__name")
