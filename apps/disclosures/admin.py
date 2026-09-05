from django.contrib import admin

from .models import Advisory, AdvisoryReference, AdvisoryTimelineEntry


class AdvisoryTimelineInline(admin.TabularInline):
    model = AdvisoryTimelineEntry
    extra = 0


class AdvisoryReferenceInline(admin.TabularInline):
    model = AdvisoryReference
    extra = 0


@admin.register(Advisory)
class AdvisoryAdmin(admin.ModelAdmin):
    list_display = (
        "advisory_id",
        "title",
        "severity",
        "status",
        "organization",
        "published_at",
    )
    list_filter = ("status", "severity")
    search_fields = ("advisory_id", "title", "summary", "product")
    readonly_fields = (
        "advisory_id",
        "published_at",
        "published_by",
        "created_at",
        "updated_at",
    )
    inlines = [AdvisoryTimelineInline, AdvisoryReferenceInline]
    date_hierarchy = "created_at"
