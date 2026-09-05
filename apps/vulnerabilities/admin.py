from django.contrib import admin

from .models import CVE, CWE, VulnerabilityReference


@admin.register(CWE)
class CWEAdmin(admin.ModelAdmin):
    list_display = ("code", "name")
    search_fields = ("code", "name")


@admin.register(CVE)
class CVEAdmin(admin.ModelAdmin):
    list_display = ("cve_id", "state", "cvss_score", "in_cisa_kev", "published_at")
    list_filter = ("state", "in_cisa_kev")
    search_fields = ("cve_id", "summary")


@admin.register(VulnerabilityReference)
class VulnerabilityReferenceAdmin(admin.ModelAdmin):
    list_display = ("title", "kind", "is_public", "case", "advisory")
    list_filter = ("kind", "is_public")
    search_fields = ("title", "url")
