"""Vues d'authentification et de gestion de compte."""

from django.contrib import messages
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.views import (
    LoginView,
    LogoutView,
    PasswordResetCompleteView,
    PasswordResetConfirmView,
    PasswordResetDoneView,
    PasswordResetView,
)
from django.db import transaction
from django.shortcuts import redirect, render
from django.urls import reverse, reverse_lazy
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.utils.encoding import force_bytes
from django.utils.http import url_has_allowed_host_and_scheme, urlsafe_base64_encode
from django.views.decorators.debug import sensitive_post_parameters
from django.views.decorators.http import require_POST

from apps.audit.models import AuditAction
from apps.audit.services import log_action
from apps.core.middleware import get_client_ip
from apps.core.ratelimit import rate_limited, reset
from apps.notifications.models import NotificationKind
from apps.notifications.services import notify
from apps.researchers.services import get_or_create_profile

from . import mfa
from .forms import (
    EmailAuthenticationForm,
    ProfileForm,
    RegistrationForm,
    ResearcherProfileForm,
    StrongPasswordChangeForm,
    TotpCodeForm,
)
from .middleware import elevate, session_is_elevated
from .models import TokenPurpose, UserToken

#: Secret candidat d'un enrolement en cours. Il ne rejoint le compte qu'une
#: fois un code valide fourni : un enrolement abandonne ne laisse rien
#: derriere lui, et le compte garde son facteur precedent jusqu'au bout.
SETUP_SESSION_KEY = "mfa_setup_candidate"


def _login_par_compte(request):
    """Limite indexee sur le compte vise : un essai de mots de passe reparti
    sur de nombreuses IP echappe a la limite par IP."""
    return (request.POST.get("username") or "").strip().lower() or "-"


@method_decorator(sensitive_post_parameters("password"), name="dispatch")
@method_decorator(rate_limited("login"), name="dispatch")
@method_decorator(rate_limited("login_account", key_func=_login_par_compte), name="dispatch")
class EvdpLoginView(LoginView):
    template_name = "accounts/login.html"
    authentication_form = EmailAuthenticationForm
    redirect_authenticated_user = True

    def form_valid(self, form):
        response = super().form_valid(form)
        user = self.request.user
        ip = get_client_ip(self.request)
        if ip:
            user.last_login_ip = ip
            user.save(update_fields=["last_login_ip", "updated_at"])
        reset("login", ip or "-")
        reset("login_account", _login_par_compte(self.request))
        return response


class EvdpLogoutView(LogoutView):
    next_page = "/"


@rate_limited("register")
def register(request):
    """Inscription publique d'un chercheur."""
    if request.user.is_authenticated:
        return redirect("dashboard:home")

    if request.method == "POST":
        form = RegistrationForm(request.POST)
        if form.is_valid():
            with transaction.atomic():
                user = form.save()
                get_or_create_profile(
                    user,
                    pseudonym=form.cleaned_data.get("pseudonym") or "",
                    identity_mode=form.cleaned_data["identity_mode"],
                )
                token = UserToken.issue(user, TokenPurpose.EMAIL_VERIFICATION)
            log_action(
                AuditAction.USER_CREATED,
                actor=user,
                obj=user,
                request=request,
                role=user.role,
            )
            notify(
                user,
                NotificationKind.ACCOUNT,
                title="Bienvenue sur eVDP",
                body="Confirmez votre adresse email pour activer toutes les fonctions.",
                url=f"/verify-email/{token.token}/",
            )
            messages.success(
                request,
                "Compte créé. Un email de vérification vous à été envoyé : "
                "confirmez votre adresse pour soumettre des rapports.",
            )
            login(request, user, backend="django.contrib.auth.backends.ModelBackend")
            return redirect("dashboard:home")
    else:
        form = RegistrationForm()
    return render(request, "accounts/register.html", {"form": form})


def _safe_next(request):
    """`next` s'il designe une page de ce site, None sinon."""
    target = request.GET.get("next") or ""
    allowed = url_has_allowed_host_and_scheme(
        target, allowed_hosts={request.get_host()}, require_https=request.is_secure()
    )
    return target if allowed else None


def _mfa_par_compte(request):
    """Limite de debit par compte : c'est le code d'un compte qu'on devine."""
    return str(getattr(request.user, "pk", "-"))


@login_required
@rate_limited("mfa", key_func=_mfa_par_compte)
def mfa_setup(request):
    """Enrolement d'un authentificateur TOTP.

    Accessible sans session elevee au premier enrolement seulement : le
    compte vient de prouver son mot de passe et n'a pas encore de facteur a
    opposer. Une fois enrole, changer d'authentificateur exige d'abord de
    valider celui en place, sinon le mot de passe seul suffirait a remplacer
    le second facteur — et il n'y aurait plus de second facteur.
    """
    if not request.user.mfa_required:
        messages.info(request, "Votre compte n'est pas soumis à la double authentification.")
        return redirect("accounts:profile")
    if not request.user.mfa_pending_enrollment and not session_is_elevated(request):
        return redirect("accounts:mfa_challenge")

    secret = request.session.get(SETUP_SESSION_KEY)
    if not secret:
        secret = mfa.new_secret()
        request.session[SETUP_SESSION_KEY] = secret

    form = TotpCodeForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        pas = mfa.matching_step(secret, form.cleaned_data["code"])
        if pas is None:
            log_action(
                AuditAction.MFA_FAILED,
                actor=request.user,
                obj=request.user,
                request=request,
                phase="enrolement",
            )
            messages.error(request, "Code incorrect. Vérifiez l'heure de votre appareil.")
        else:
            user = request.user
            user.mfa_secret = secret
            user.mfa_enabled = True
            user.mfa_confirmed_at = timezone.now()
            user.mfa_last_step = pas
            user.save(
                update_fields=[
                    "mfa_secret",
                    "mfa_enabled",
                    "mfa_confirmed_at",
                    "mfa_last_step",
                    "updated_at",
                ]
            )
            request.session.pop(SETUP_SESSION_KEY, None)
            elevate(request)
            log_action(AuditAction.MFA_ENROLLED, actor=user, obj=user, request=request)
            messages.success(
                request,
                "Double authentification activée. Un code vous sera demandé "
                "à chaque connexion.",
            )
            return _show_new_backup_codes(request, user)

    return render(
        request,
        "accounts/mfa_setup.html",
        {
            "form": form,
            "secret_lisible": mfa.readable_secret(secret),
            "uri": mfa.provisioning_uri(request.user, secret),
            "qr": mfa.qr_data_uri(request.user, secret),
            "reenrolement": not request.user.mfa_pending_enrollment,
        },
    )


@login_required
@rate_limited("mfa", key_func=_mfa_par_compte)
def mfa_challenge(request):
    """Validation du second facteur : eleve la session pour sa duree."""
    if not request.user.mfa_required:
        return redirect("accounts:profile")
    if request.user.mfa_pending_enrollment:
        return redirect("accounts:mfa_setup")
    if session_is_elevated(request):
        return redirect("dashboard:home")

    form = TotpCodeForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        code = form.cleaned_data["code"]
        # Code de secours (lettres et chiffres) ou code TOTP (six chiffres).
        by_backup = mfa.looks_like_backup_code(code)
        if by_backup:
            accepted = mfa.consume_backup_code(request.user, code)
        else:
            accepted = mfa.consume_code(request.user, code)
        if accepted:
            if by_backup:
                remaining = mfa.remaining_backup_codes(request.user)
                if remaining <= mfa.BACKUP_CODES_LOW:
                    messages.warning(
                        request,
                        f"Il vous reste {remaining} code(s) de secours : "
                        "régénérez-en depuis votre profil.",
                    )
            elevate(request)
            log_action(
                AuditAction.MFA_VERIFIED,
                actor=request.user,
                obj=request.user,
                request=request,
                method="code_de_secours" if by_backup else "totp",
            )
            return redirect(_safe_next(request) or "dashboard:home")
        log_action(
            AuditAction.MFA_FAILED,
            actor=request.user,
            obj=request.user,
            request=request,
            phase="connexion",
        )
        messages.error(request, "Code incorrect ou déjà utilisé.")

    return render(request, "accounts/mfa_challenge.html", {"form": form})


#: Codes de secours tout juste generes, en attente de leur unique affichage.
BACKUP_CODES_SESSION_KEY = "mfa_backup_codes"


def _show_new_backup_codes(request, user):
    request.session[BACKUP_CODES_SESSION_KEY] = mfa.generate_backup_codes(user)
    log_action(AuditAction.MFA_BACKUP_CODES_GENERATED, actor=user, obj=user, request=request)
    return redirect("accounts:mfa_backup_codes")


@login_required
def mfa_backup_codes(request):
    """Affiche une seule fois les codes de secours qui viennent d'etre generes."""
    codes = request.session.pop(BACKUP_CODES_SESSION_KEY, None)
    if not codes:
        return redirect("accounts:profile")
    response = render(request, "accounts/mfa_backup_codes.html", {"codes": codes})
    response["Cache-Control"] = "no-store"
    return response


@login_required
@require_POST
@rate_limited("mfa", key_func=_mfa_par_compte)
def mfa_regenerate_backup_codes(request):
    """Nouveau lot de codes de secours, contre le mot de passe du compte."""
    user = request.user
    if not user.mfa_enabled or not session_is_elevated(request):
        return redirect("accounts:profile")
    if not user.check_password(request.POST.get("password", "")):
        messages.error(request, "Mot de passe incorrect : aucun code n'a été généré.")
        return redirect("accounts:profile")
    return _show_new_backup_codes(request, user)


def verify_email(request, token):
    """Confirme l'adresse email a partir d'un jeton a usage unique."""
    entry = (
        UserToken.objects.filter(token=token, purpose=TokenPurpose.EMAIL_VERIFICATION)
        .select_related("user")
        .first()
    )
    if entry is None or not entry.is_valid:
        messages.error(request, "Lien de vérification invalide ou expiré.")
        return redirect("core:home")
    user = entry.user
    user.email_verified = True
    user.save(update_fields=["email_verified", "updated_at"])
    entry.consume()
    log_action(AuditAction.EMAIL_VERIFIED, actor=user, obj=user, request=request)
    messages.success(request, "Adresse email vérifiée. Merci.")
    return redirect("dashboard:home")


@login_required
def resend_verification(request):
    if request.user.email_verified:
        messages.info(request, "Votre adresse est déjà vérifiée.")
        return redirect("accounts:profile")
    token = UserToken.issue(request.user, TokenPurpose.EMAIL_VERIFICATION)
    notify(
        request.user,
        NotificationKind.ACCOUNT,
        title="Vérification de votre adresse email",
        body="Un nouveau lien de verification est disponible.",
        url=f"/verify-email/{token.token}/",
    )
    messages.success(request, "Un nouveau lien de vérification vous à été envoyé.")
    return redirect("accounts:profile")


@login_required
def profile(request):
    """Profil utilisateur : identite, PGP, options de publication."""
    researcher_profile = (
        get_or_create_profile(request.user) if request.user.is_researcher else None
    )

    if request.method == "POST":
        user_form = ProfileForm(request.POST, instance=request.user)
        profile_form = (
            ResearcherProfileForm(request.POST, instance=researcher_profile)
            if researcher_profile
            else None
        )
        forms_valid = user_form.is_valid() and (
            profile_form is None or profile_form.is_valid()
        )
        if forms_valid:
            user_form.save()
            if profile_form is not None:
                profile_form.save()
            log_action(
                AuditAction.USER_UPDATED,
                actor=request.user,
                obj=request.user,
                request=request,
            )
            messages.success(request, "Profil mis à jour.")
            return redirect("accounts:profile")
    else:
        user_form = ProfileForm(instance=request.user)
        profile_form = (
            ResearcherProfileForm(instance=researcher_profile) if researcher_profile else None
        )

    return render(
        request,
        "accounts/profile.html",
        {
            "user_form": user_form,
            "profile_form": profile_form,
            "researcher_profile": researcher_profile,
            "api_keys": request.user.api_keys.filter(is_active=True),
            "backup_codes_left": (
                mfa.remaining_backup_codes(request.user) if request.user.mfa_enabled else None
            ),
        },
    )


@login_required
def change_password(request):
    if request.method == "POST":
        form = StrongPasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            form.save()
            log_action(
                AuditAction.PASSWORD_CHANGED,
                actor=request.user,
                obj=request.user,
                request=request,
            )
            messages.success(request, "Mot de passe modifié. Reconnectez-vous si nécessaire.")
            return redirect("accounts:profile")
    else:
        form = StrongPasswordChangeForm(request.user)
    return render(request, "accounts/change_password.html", {"form": form})


@method_decorator(rate_limited("password_reset"), name="dispatch")
class EvdpPasswordResetView(PasswordResetView):
    template_name = "accounts/password_reset.html"
    email_template_name = "accounts/emails/password_reset.txt"
    subject_template_name = "accounts/emails/password_reset_subject.txt"
    success_url = reverse_lazy("accounts:password_reset_done")

    def form_valid(self, form):
        log_action(
            AuditAction.PASSWORD_RESET_REQUESTED,
            request=self.request,
            object_type="User",
            object_repr=form.cleaned_data.get("email", "")[:255],
        )
        return super().form_valid(form)


class EvdpPasswordResetDoneView(PasswordResetDoneView):
    template_name = "accounts/password_reset_done.html"


class EvdpPasswordResetConfirmView(PasswordResetConfirmView):
    template_name = "accounts/password_reset_confirm.html"
    success_url = reverse_lazy("accounts:password_reset_complete")


class EvdpPasswordResetCompleteView(PasswordResetCompleteView):
    template_name = "accounts/password_reset_complete.html"


def send_password_setup_link(user, title, body):
    """Envoie un lien de choix de mot de passe.

    Reutilise le mecanisme de reinitialisation standard de Django : un
    compte cree sans mot de passe utilisable peut s'en voir attribuer un via
    ce meme lien (`accounts:password_reset_confirm`), sans jeton ni vue
    supplementaire a maintenir.

    `notify()` prefixe lui-meme l'hote via `_absolute()` (voir
    apps/notifications/services.py) : le chemin transmis ici doit rester
    relatif, comme partout ailleurs dans ce module (`verify_email`,
    `resend_verification`) — sinon l'hote se retrouve double dans le lien
    envoye par email.
    """
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = default_token_generator.make_token(user)
    path = reverse("accounts:password_reset_confirm", kwargs={"uidb64": uid, "token": token})
    notify(user, NotificationKind.ACCOUNT, title=title, body=body, url=path)
