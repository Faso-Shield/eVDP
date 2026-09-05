from django.contrib import admin

from .models import AuditLog


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    """Le journal d'audit est consultable mais jamais modifiable."""

    list_display = (
        "timestamp",
        "action",
        "actor_label",
        "object_type",
        "object_repr",
        "result",
        "ip_address",
    )
    list_filter = ("action", "result", "object_type", "timestamp")
    search_fields = ("actor_label", "object_id", "object_repr", "ip_address")
    date_hierarchy = "timestamp"
    ordering = ("-timestamp",)
    readonly_fields = tuple(f.name for f in AuditLog._meta.fields)

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False
