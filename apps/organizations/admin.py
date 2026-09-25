from django.contrib import admin

from apps.accounts.roles import Capability

from .models import Organization, OrganizationMember, SecurityContact


class OrganizationManagersOnlyMixin:
    """Gestion des organisations dans l'administration Django.

    Ouverte aux comptes portant MANAGE_ALL_ORGANIZATIONS : super admin,
    et Coordinateur ou analyste s'ils ont acces a l'administration. Un
    simple compte staff sans cette capacite n'y accede pas.
    """

    def _allowed(self, request):
        return request.user.has_capability(Capability.MANAGE_ALL_ORGANIZATIONS)

    def has_module_permission(self, request):
        return self._allowed(request)

    def has_view_permission(self, request, obj=None):
        return self._allowed(request)

    def has_change_permission(self, request, obj=None):
        return self._allowed(request)

    def has_add_permission(self, request, obj=None):
        return self._allowed(request)

    def has_delete_permission(self, request, obj=None):
        return self._allowed(request)


class OrganizationMemberInline(admin.TabularInline):
    model = OrganizationMember
    extra = 0
    autocomplete_fields = ["user"]


class SecurityContactInline(admin.TabularInline):
    model = SecurityContact
    extra = 0


@admin.register(Organization)
class OrganizationAdmin(OrganizationManagersOnlyMixin, admin.ModelAdmin):
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
class OrganizationMemberAdmin(OrganizationManagersOnlyMixin, admin.ModelAdmin):
    list_display = ("user", "organization", "membership_role", "is_active", "is_primary")
    list_filter = ("membership_role", "is_active")
    search_fields = ("user__email", "organization__name")
    autocomplete_fields = ["user", "organization"]


@admin.register(SecurityContact)
class SecurityContactAdmin(OrganizationManagersOnlyMixin, admin.ModelAdmin):
    list_display = ("name", "organization", "email", "is_primary")
    list_filter = ("is_primary",)
    search_fields = ("name", "email", "organization__name")
