"""Administration des comptes.

Les comptes sont presentes en **deux listes** et non une : les comptes
metiers et administrateurs d'un cote, les signaleurs de l'autre. Ce sont deux
populations sans cycle de vie commun — l'une est creee par un administrateur
et porte un second facteur, l'autre s'inscrit seule et se juge a sa
reputation — et les informations utiles n'y sont pas les memes. Une liste
unique obligeait a lire la colonne role pour savoir a qui on avait affaire,
et a filtrer avant toute action de masse.

Le modele `User` reste enregistre mais **retire de l'index** : cinq autres
administrations le referencent en `autocomplete_fields`, ce qui exige un
`ModelAdmin` avec des `search_fields`. Le laisser visible aurait affiche une
troisieme liste, melangee, qui aurait vide le decoupage de son sens.
"""

from django.contrib import admin, messages
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin

from apps.audit.models import AuditAction
from apps.audit.services import log_action

from .models import ApiKey, BusinessAccount, ReporterAccount, User, UserToken
from .roles import BUSINESS_ROLES, RESEARCHER_ROLES


@admin.register(User)
class UserAutocompleteAdmin(admin.ModelAdmin):
    """Sert les `autocomplete_fields` des autres administrations, sans plus.

    Les cases, les appartenances et les rapports designent un utilisateur par
    autocompletion, et Django exige pour cela un `ModelAdmin` enregistre sur
    le modele cible. Celui-ci n'existe que pour ca : `get_model_perms` le
    retire de l'index, les deux listes de comptes restant les seules portes
    de gestion. Ses URL demeurent joignables, ce dont la vue d'autocompletion
    a besoin.
    """

    search_fields = ("email", "full_name", "display_name")

    def get_model_perms(self, request):
        return {}


class BaseAccountAdmin(DjangoUserAdmin):
    """Socle commun : identite, mot de passe, journalisation des changements."""

    ordering = ("email",)
    search_fields = ("email", "full_name", "display_name")
    readonly_fields = ("last_login", "created_at", "updated_at", "last_login_ip")

    #: Roles presentes par cette liste. Definis par chaque sous-classe.
    roles = frozenset()

    def get_queryset(self, request):
        """Le partage se fait ici, et non dans un manager par defaut.

        Un manager filtre servirait aussi de `_base_manager` et masquerait
        des lignes a l'ORM bien au-dela de l'administration.
        """
        return super().get_queryset(request).filter(role__in=self.roles)

    def save_model(self, request, obj, form, change):
        role_changed = change and "role" in form.changed_data
        super().save_model(request, obj, form, change)

        if role_changed:
            log_action(
                AuditAction.ROLE_CHANGED,
                actor=request.user,
                obj=obj,
                request=request,
                new_role=obj.role,
            )
            if obj.role not in self.roles:
                # Le compte vient de changer de population. Sans ce message,
                # il disparaitrait de la liste sans explication.
                self.message_user(
                    request,
                    f"{obj.email} porte desormais le role "
                    f"{obj.get_role_display()} : le compte figure maintenant "
                    "dans l'autre liste.",
                    messages.WARNING,
                )
        elif not change:
            log_action(AuditAction.USER_CREATED, actor=request.user, obj=obj, request=request)


@admin.register(BusinessAccount)
class BusinessAccountAdmin(BaseAccountAdmin):
    """Comptes crees par un administrateur, soumis au second facteur."""

    roles = BUSINESS_ROLES
    list_display = (
        "email",
        "full_name",
        "role",
        "organisation",
        "is_active",
        "second_facteur",
        "last_login",
    )
    list_filter = ("role", "is_active", "is_staff", "mfa_enabled", "email_verified")
    actions = ("reinitialiser_mfa",)
    readonly_fields = BaseAccountAdmin.readonly_fields + ("mfa_confirmed_at",)
    fieldsets = (
        (None, {"fields": ("email", "password")}),
        ("Identité", {"fields": ("full_name", "display_name", "phone")}),
        (
            "RBAC",
            {
                "fields": (
                    "role",
                    "is_active",
                    "is_staff",
                    "is_superuser",
                    "groups",
                    "user_permissions",
                )
            },
        ),
        (
            "Sécurité",
            {
                "fields": (
                    "email_verified",
                    "mfa_enabled",
                    "mfa_confirmed_at",
                    "pgp_public_key",
                    "pgp_fingerprint",
                    "last_login_ip",
                )
            },
        ),
        ("Horodatage", {"fields": ("last_login", "created_at", "updated_at")}),
    )
    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": ("email", "full_name", "role", "password1", "password2"),
            },
        ),
    )

    @admin.display(description="Organisation")
    def organisation(self, obj):
        organisation = obj.primary_organization
        return organisation.name if organisation else "—"

    @admin.display(description="Second facteur", boolean=True)
    def second_facteur(self, obj):
        """Enrolement TOTP effectif : la colonne qui n'a pas de sens ailleurs."""
        return obj.mfa_enabled

    @admin.action(description="Réinitialiser la double authentification")
    def reinitialiser_mfa(self, request, queryset):
        """Revoque l'enrolement TOTP : appareil perdu, ou depart d'un agent.

        Le compte n'en est pas dispense pour autant : son role l'y soumet
        toujours, et sa prochaine connexion repassera par l'enrolement.
        """
        concernes = [u for u in queryset if u.mfa_enabled or u.mfa_secret]
        for utilisateur in concernes:
            utilisateur.reset_mfa()
            log_action(
                AuditAction.MFA_RESET,
                actor=request.user,
                obj=utilisateur,
                request=request,
            )
        self.message_user(
            request,
            f"{len(concernes)} compte(s) devront enregistrer un nouvel "
            "authentificateur a la prochaine connexion.",
        )


@admin.register(ReporterAccount)
class ReporterAccountAdmin(BaseAccountAdmin):
    """Comptes d'inscription libre. Ni second facteur, ni droits d'equipe."""

    roles = RESEARCHER_ROLES
    list_display = (
        "email",
        "identite_publique",
        "role",
        "email_verified",
        "reputation",
        "rapports_soumis",
        "is_active",
        "inscrit_le",
    )
    list_filter = ("role", "is_active", "email_verified")
    fieldsets = (
        (None, {"fields": ("email", "password")}),
        ("Identité", {"fields": ("full_name", "display_name", "phone")}),
        ("Rôle", {"fields": ("role", "is_active")}),
        (
            "Sécurité",
            {
                "fields": (
                    "email_verified",
                    "pgp_public_key",
                    "pgp_fingerprint",
                    "last_login_ip",
                ),
                "description": "Un compte signaleur n'est jamais soumis à la "
                "double authentification.",
            },
        ),
        ("Horodatage", {"fields": ("last_login", "created_at", "updated_at")}),
    )
    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": ("email", "full_name", "role", "password1", "password2"),
            },
        ),
    )

    def get_queryset(self, request):
        return super().get_queryset(request).select_related("researcher_profile")

    @admin.display(description="Identité publique")
    def identite_publique(self, obj):
        """Ce que le public voit : nom, pseudonyme, ou anonymat revendique."""
        return obj.public_identity()

    @admin.display(description="Réputation", ordering="researcher_profile__reputation")
    def reputation(self, obj):
        profil = getattr(obj, "researcher_profile", None)
        return profil.reputation if profil else "—"

    @admin.display(description="Rapports")
    def rapports_soumis(self, obj):
        profil = getattr(obj, "researcher_profile", None)
        return profil.reports_submitted if profil else "—"

    @admin.display(description="Inscrit le", ordering="created_at")
    def inscrit_le(self, obj):
        """`created_at` vient de `TimeStampedModel`, partage par tout le projet.

        Le renommer la-bas ferait une migration dans chaque application pour
        un libelle de colonne. Et "Inscrit le" dit mieux ce dont il s'agit
        ici qu'un "Cree le" generique : ces comptes s'inscrivent seuls.
        """
        return obj.created_at


@admin.register(UserToken)
class UserTokenAdmin(admin.ModelAdmin):
    list_display = ("user", "purpose", "expires_at", "used_at", "created_at")
    list_filter = ("purpose",)
    search_fields = ("user__email",)
    readonly_fields = ("token", "created_at", "updated_at")


@admin.register(ApiKey)
class ApiKeyAdmin(admin.ModelAdmin):
    list_display = ("label", "user", "prefix", "is_active", "last_used_at", "expires_at")
    list_filter = ("is_active",)
    search_fields = ("label", "user__email", "prefix")
    readonly_fields = ("prefix", "key_hash", "last_used_at", "created_at", "updated_at")
