from django.contrib import admin

from .models import SiteSetting


@admin.register(SiteSetting)
class SiteSettingAdmin(admin.ModelAdmin):
    list_display = ("key", "label", "is_published", "updated_at")
    list_filter = ("is_published",)
    search_fields = ("key", "label", "value")
    ordering = ("key",)


class CaseContentAdminMixin:
    """Contenu des dossiers ferme a l'administration technique.

    Workflow v2 : le super admin gere comptes, roles, configuration, SLA et
    matrices de prime, mais ne lit jamais le contenu d'un dossier (ISO/IEC
    27001 A.5.3, separation des taches). Rapports, messages, pieces jointes
    et primes ne se consultent que dans l'application, sous le controle de
    la matrice de visibilite ; les preuves du declarant n'y sont jamais
    modifiables.
    """

    def has_view_permission(self, request, obj=None):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_add_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    def has_module_permission(self, request):
        return False
