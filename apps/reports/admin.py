from django.contrib import admin

from apps.core.admin import CaseContentAdminMixin

from .models import VulnerabilityReport


@admin.register(VulnerabilityReport)
class VulnerabilityReportAdmin(CaseContentAdminMixin, admin.ModelAdmin):
    list_display = (
        "title",
        "vulnerability_type",
        "reported_severity",
        "affected_organization",
        "source",
        "is_anonymous",
        "created_at",
    )
    list_filter = (
        "vulnerability_type",
        "reported_severity",
        "source",
        "is_anonymous",
        "is_pgp_encrypted",
    )
    search_fields = ("title", "product", "reporter__email", "reporter_email")
    readonly_fields = ("submitted_at", "submitter_ip_hash", "created_at", "updated_at")
    autocomplete_fields = ["affected_organization", "reporter"]
    date_hierarchy = "created_at"
