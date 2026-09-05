from django.contrib import admin

from .models import Organization, OrganizationMember, SecurityContact


class OrganizationMemberInline(admin.TabularInline):
    model = OrganizationMember
    extra = 0
    autocomplete_fields = ["user"]


class SecurityContactInline(admin.TabularInline):
    model = SecurityContact
    extra = 0


@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin):
    list_display = ("name", "acronym", "organization_type", "sector", "status", "accepts_vdp")
    list_filter = ("organization_type", "sector", "status", "accepts_vdp")
    search_fields = ("name", "acronym", "domain", "official_email")
    prepopulated_fields = {"slug": ("name",)}
    inlines = [OrganizationMemberInline, SecurityContactInline]
    actions = ["activate", "suspend"]

    @admin.action(description="Activer les organisations selectionnees")
    def activate(self, request, queryset):
        queryset.update(status="ACTIVE")

    @admin.action(description="Suspendre les organisations selectionnees")
    def suspend(self, request, queryset):
        queryset.update(status="SUSPENDED")


@admin.register(OrganizationMember)
class OrganizationMemberAdmin(admin.ModelAdmin):
    list_display = ("user", "organization", "membership_role", "is_active", "is_primary")
    list_filter = ("membership_role", "is_active")
    search_fields = ("user__email", "organization__name")
    autocomplete_fields = ["user", "organization"]


@admin.register(SecurityContact)
class SecurityContactAdmin(admin.ModelAdmin):
    list_display = ("name", "organization", "email", "is_primary")
    list_filter = ("is_primary",)
    search_fields = ("name", "email", "organization__name")
