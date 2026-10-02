from django.contrib import admin

from apps.core.admin import CaseContentAdminMixin

from .models import Attachment


@admin.register(Attachment)
class AttachmentAdmin(CaseContentAdminMixin, admin.ModelAdmin):
    list_display = (
        "original_filename",
        "case",
        "uploaded_by",
        "human_size",
        "scan_status",
        "download_count",
        "created_at",
    )
    list_filter = ("scan_status", "is_pgp_encrypted")
    search_fields = ("original_filename", "sha256", "case__case_id")
    readonly_fields = (
        "storage_name",
        "sha256",
        "size",
        "content_type",
        "download_count",
        "created_at",
        "updated_at",
    )

    def has_add_permission(self, request, obj=None):
        # Toute piece jointe doit passer par le service de validation.
        return False
