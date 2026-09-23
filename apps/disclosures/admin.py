"""Administration des advisories.

Comme pour apps.bounty.admin : l'administration ne reimplemente aucune
regle metier, chaque action delegue au service correspondant
(apps.disclosures.services), qui garantit en un seul geste la verification
de capacite, l'exigence de resume rempli, l'audit et la notification.
"""

from django.contrib import admin, messages
from django.core.exceptions import PermissionDenied, ValidationError

from .models import Advisory, AdvisoryReference, AdvisoryTimelineEntry
from .services import publish_advisory, retract_advisory


class AdvisoryTimelineInline(admin.TabularInline):
    model = AdvisoryTimelineEntry
    extra = 0


class AdvisoryReferenceInline(admin.TabularInline):
    model = AdvisoryReference
    extra = 0


def _apply(modeladmin, request, queryset, service, success_label, **kwargs):
    """Applique un service a chaque advisory selectionne.

    Un refus (capacite manquante, transition interdite, resume manquant) est
    rapporte sans interrompre le traitement des autres lignes.
    """
    applied = 0
    for advisory in queryset:
        try:
            service(advisory, request.user, request=request, **kwargs)
        except (PermissionDenied, ValidationError) as exc:
            detail = "; ".join(getattr(exc, "messages", [str(exc)]))
            modeladmin.message_user(request, f"{advisory} : {detail}", messages.ERROR)
        else:
            applied += 1
    if applied:
        modeladmin.message_user(
            request, f"{applied} advisory(ies) : {success_label}.", messages.SUCCESS
        )


@admin.action(description="Publier l'advisory")
def action_publish(modeladmin, request, queryset):
    _apply(modeladmin, request, queryset, publish_advisory, "publie(s)")


@admin.action(description="Retirer l'advisory")
def action_retract(modeladmin, request, queryset):
    _apply(
        modeladmin,
        request,
        queryset,
        retract_advisory,
        "retire(s)",
        reason="Retrait depuis l'administration.",
    )


@admin.register(Advisory)
class AdvisoryAdmin(admin.ModelAdmin):
    list_display = (
        "advisory_id",
        "title",
        "severity",
        "status",
        "organization",
        "published_at",
    )
    list_filter = ("status", "severity")
    search_fields = ("advisory_id", "title", "summary", "product")
    # Le cycle de vie n'est pilotable que par les actions ci-dessous : editer
    # ce champ a la main contournerait le controle de capacite et l'audit.
    readonly_fields = (
        "advisory_id",
        "status",
        "published_at",
        "published_by",
        "created_at",
        "updated_at",
    )
    inlines = [AdvisoryTimelineInline, AdvisoryReferenceInline]
    date_hierarchy = "created_at"
    actions = [action_publish, action_retract]
