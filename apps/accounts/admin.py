from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin

from apps.audit.models import AuditAction
from apps.audit.services import log_action

from .models import ApiKey, User, UserToken


@admin.register(User)
class UserAdmin(DjangoUserAdmin):
    ordering = ("email",)
    list_display = (
        "email",
        "display_name",
        "role",
        "is_active",
        "email_verified",
        "created_at",
    )
    list_filter = ("role", "is_active", "is_staff", "email_verified", "mfa_enabled")
    actions = ("reinitialiser_mfa",)
    search_fields = ("email", "full_name", "display_name")
    readonly_fields = (
        "last_login",
        "created_at",
        "updated_at",
        "last_login_ip",
        "mfa_confirmed_at",
    )
    fieldsets = (
        (None, {"fields": ("email", "password")}),
        ("Identite", {"fields": ("full_name", "display_name", "phone")}),
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
            "Securite",
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

    @admin.action(description="Reinitialiser la double authentification")
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
        elif not change:
            log_action(AuditAction.USER_CREATED, actor=request.user, obj=obj, request=request)


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
