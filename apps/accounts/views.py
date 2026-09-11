"""Vues d'authentification et de gestion de compte."""

from django.contrib import messages
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
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
from django.urls import reverse_lazy
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views.decorators.debug import sensitive_post_parameters

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


@method_decorator(sensitive_post_parameters("password"), name="dispatch")
@method_decorator(rate_limited("login"), name="dispatch")
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
                "Compte cree. Un email de verification vous a ete envoye : "
                "confirmez votre adresse pour soumettre des rapports.",
            )
            login(request, user, backend="django.contrib.auth.backends.ModelBackend")
            return redirect("dashboard:home")
    else:
        form = RegistrationForm()
    return render(request, "accounts/register.html", {"form": form})


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
        messages.info(request, "Votre compte n'est pas soumis a la double authentification.")
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
            messages.error(request, "Code incorrect. Verifiez l'heure de votre appareil.")
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
                "Double authentification activee. Un code vous sera demande "
                "a chaque connexion.",
            )
            return redirect("dashboard:home")

    return render(
        request,
        "accounts/mfa_setup.html",
        {
            "form": form,
            "secret_lisible": mfa.readable_secret(secret),
            "uri": mfa.provisioning_uri(request.user, secret),
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
        if mfa.consume_code(request.user, form.cleaned_data["code"]):
            elevate(request)
            log_action(
                AuditAction.MFA_VERIFIED,
                actor=request.user,
                obj=request.user,
                request=request,
            )
            return redirect(request.GET.get("next") or "dashboard:home")
        log_action(
            AuditAction.MFA_FAILED,
            actor=request.user,
            obj=request.user,
            request=request,
            phase="connexion",
        )
        messages.error(request, "Code incorrect ou deja utilise.")

    return render(request, "accounts/mfa_challenge.html", {"form": form})


def verify_email(request, token):
    """Confirme l'adresse email a partir d'un jeton a usage unique."""
    entry = (
        UserToken.objects.filter(token=token, purpose=TokenPurpose.EMAIL_VERIFICATION)
        .select_related("user")
        .first()
    )
    if entry is None or not entry.is_valid:
        messages.error(request, "Lien de verification invalide ou expire.")
        return redirect("core:home")
    user = entry.user
    user.email_verified = True
    user.save(update_fields=["email_verified", "updated_at"])
    entry.consume()
    log_action(AuditAction.EMAIL_VERIFIED, actor=user, obj=user, request=request)
    messages.success(request, "Adresse email verifiee. Merci.")
    return redirect("dashboard:home")


@login_required
def resend_verification(request):
    if request.user.email_verified:
        messages.info(request, "Votre adresse est deja verifiee.")
        return redirect("accounts:profile")
    token = UserToken.issue(request.user, TokenPurpose.EMAIL_VERIFICATION)
    notify(
        request.user,
        NotificationKind.ACCOUNT,
        title="Verification de votre adresse email",
        body="Un nouveau lien de verification est disponible.",
        url=f"/verify-email/{token.token}/",
    )
    messages.success(request, "Un nouveau lien de verification vous a ete envoye.")
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
            messages.success(request, "Profil mis a jour.")
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
            messages.success(request, "Mot de passe modifie. Reconnectez-vous si necessaire.")
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
