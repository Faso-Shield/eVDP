from django.contrib import admin

from .models import SiteSetting


@admin.register(SiteSetting)
class SiteSettingAdmin(admin.ModelAdmin):
    list_display = ("key", "label", "is_published", "updated_at")
    list_filter = ("is_published",)
    search_fields = ("key", "label", "value")
    ordering = ("key",)
