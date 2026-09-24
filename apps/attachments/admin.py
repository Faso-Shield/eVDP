from django.contrib import admin

from .models import Attachment


@admin.register(Attachment)
class AttachmentAdmin(admin.ModelAdmin):
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
        "case",
        "report",
        "message",
        "uploaded_by",
        "original_filename",
        "storage_name",
        "sha256",
        "size",
        "content_type",
        "download_count",
        "created_at",
        "updated_at",
    )

    def has_add_permission(self, request):
        # Toute piece jointe doit passer par le service de validation.
        return False

    def has_change_permission(self, request, obj=None):
        # Preuves intouchables (spec v2) : lecture seule dans l'administration.
        return False

    def has_delete_permission(self, request, obj=None):
        return obj is None or not obj.is_reporter_evidence
