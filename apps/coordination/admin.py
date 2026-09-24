from django.contrib import admin

from apps.core.admin import CaseContentAdminMixin

from .models import (
    Case,
    CaseAssignment,
    CaseMessage,
    CaseParticipant,
    CaseStatusHistory,
    CaseTimelineEvent,
    SLAEvent,
    SLAPolicy,
)


class CaseParticipantInline(admin.TabularInline):
    model = CaseParticipant
    extra = 0
    autocomplete_fields = ["user"]


class CaseTimelineInline(admin.TabularInline):
    model = CaseTimelineEvent
    extra = 0
    readonly_fields = ("created_at",)


class SLAEventInline(admin.TabularInline):
    model = SLAEvent
    extra = 0
    readonly_fields = ("created_at",)


@admin.register(Case)
class CaseAdmin(CaseContentAdminMixin, admin.ModelAdmin):
    list_display = (
        "case_id",
        "title",
        "workflow",
        "status",
        "severity",
        "organization",
        "assignee",
        "priority_score",
        "created_at",
    )
    list_filter = ("status", "severity", "workflow", "is_published", "organization")
    search_fields = ("case_id", "title", "product", "organization__name")
    readonly_fields = ("case_id", "created_at", "updated_at", "priority_score")
    autocomplete_fields = ["organization", "assignee", "reporter"]
    date_hierarchy = "created_at"
    inlines = [CaseParticipantInline, CaseTimelineInline, SLAEventInline]
    actions = ["recompute_priority"]

    @admin.action(description="Recalculer le score de priorite")
    def recompute_priority(self, request, queryset):
        for case in queryset:
            case.refresh_priority()


@admin.register(CaseMessage)
class CaseMessageAdmin(CaseContentAdminMixin, admin.ModelAdmin):
    list_display = ("case", "author", "confidentiality", "is_system", "created_at")
    list_filter = ("confidentiality", "is_system")
    search_fields = ("case__case_id", "author__email")
    readonly_fields = ("content_hash", "created_at", "updated_at")


@admin.register(CaseStatusHistory)
class CaseStatusHistoryAdmin(admin.ModelAdmin):
    list_display = ("case", "from_status", "to_status", "actor", "created_at")
    list_filter = ("to_status",)
    search_fields = ("case__case_id",)
    readonly_fields = ("created_at", "updated_at")

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(SLAPolicy)
class SLAPolicyAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "is_default",
        "acknowledgement_hours",
        "triage_days",
        "vendor_response_days",
        "disclosure_delay_days",
    )
    list_filter = ("is_default",)
    search_fields = ("name",)


@admin.register(SLAEvent)
class SLAEventAdmin(admin.ModelAdmin):
    list_display = ("case", "kind", "state", "due_at", "satisfied_at")
    list_filter = ("kind", "state")
    search_fields = ("case__case_id",)


@admin.register(CaseAssignment)
class CaseAssignmentAdmin(admin.ModelAdmin):
    list_display = ("case", "user", "assigned_by", "is_active", "created_at")
    list_filter = ("is_active",)
    search_fields = ("case__case_id", "user__email")
