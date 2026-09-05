from django.contrib import admin

from .models import EmailTemplate, Notification


@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ("recipient", "kind", "title", "read_at", "emailed_at", "created_at")
    list_filter = ("kind",)
    search_fields = ("recipient__email", "title")
    readonly_fields = ("created_at", "updated_at")


@admin.register(EmailTemplate)
class EmailTemplateAdmin(admin.ModelAdmin):
    list_display = ("code", "subject", "is_active", "updated_at")
    list_filter = ("is_active",)
    search_fields = ("code", "subject")
