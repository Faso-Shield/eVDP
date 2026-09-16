"""Vues d'authentification et de gestion de compte."""

from datetime import timedelta

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
from django.core.paginator import Paginator
from django.db import transaction
from django.db.models import Q
from django.http import Http404, HttpResponseNotAllowed
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse, reverse_lazy
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.views.decorators.debug import sensitive_post_parameters

from apps.accounts.permissions import require_capability
from apps.api.authentication import generate_key
from apps.audit.models import AuditAction
from apps.audit.services import log_action
from apps.core.middleware import get_client_ip
from apps.core.ratelimit import rate_limited, reset
from apps.notifications.models import NotificationKind
from apps.notifications.services import notify
from apps.researchers.services import get_or_create_profile

from . import mfa
from .forms import (
    ApiKeyForm,
    EmailAuthenticationForm,
    MFACodeForm,
    MFADisableForm,
    ProfileForm,
    RegistrationForm,
    ResearcherProfileForm,
    StrongPasswordChangeForm,
    UserCreateForm,
    UserEditForm,
)
from .models import ApiKey, TokenPurpose, User, UserToken
from .roles import MFA_REQUIRED_ROLES, Capability, Role

MFA_SESSION_TIMEOUT = timedelta(minutes=5)


def _login_account_identifier(request):
    """Cle de limitation basee sur le compte cible, pas la source : ferme le
    trou d'un brute-force distribue sur de nombreuses IP contre un seul
    compte, que la limite par IP ne freine pas."""
    email = (request.POST.get("username") or "").strip().lower()
    return email or (get_client_ip(request) or "-")


@method_decorator(sensitive_post_parameters("password"), name="dispatch")
@method_decorator(rate_limited("login"), name="dispatch")
@method_decorator(
    rate_limited("login_account", key_func=_login_account_identifier), name="dispatch"
)
class EvdpLoginView(LoginView):
    template_name = "accounts/login.html"
    authentication_form = EmailAuthenticationForm
    redirect_authenticated_user = True

    def form_valid(self, form):
        user = form.get_user()
        if user.mfa_enabled:
            # Mot de passe verifie (form.get_user() l'a fait), mais pas
            # encore de session ouverte : le second facteur reste a fournir
            # avant tout appel a login().
            self.request.session["mfa_user_id"] = str(user.pk)
            self.request.session["mfa_started_at"] = timezone.now().isoformat()
            return redirect("accounts:mfa_verify")

        response = super().form_valid(form)
        user = self.request.user
        ip = get_client_ip(self.request)
        if ip:
            user.last_login_ip = ip
            user.save(update_fields=["last_login_ip", "updated_at"])
        reset("login", ip or "-")
        return response


def _pending_mfa_user(request):
    """Utilisateur en attente de second facteur, ou None si la session de
    connexion en cours est absente, expiree, ou ne correspond plus a un
    compte avec MFA actif."""
    user_id = request.session.get("mfa_user_id")
    started_at = request.session.get("mfa_started_at")
    if not user_id or not started_at:
        return None
    try:
        started = timezone.datetime.fromisoformat(started_at)
    except ValueError:
        return None
    if timezone.now() - started > MFA_SESSION_TIMEOUT:
        return None
    return User.objects.filter(pk=user_id, is_active=True, mfa_enabled=True).first()


def _clear_pending_mfa(request):
    request.session.pop("mfa_user_id", None)
    request.session.pop("mfa_started_at", None)


@rate_limited("mfa_verify")
def mfa_verify(request):
    """Deuxieme etape de connexion : code TOTP a 6 chiffres."""
    user = _pending_mfa_user(request)
    if user is None:
        _clear_pending_mfa(request)
        messages.error(request, "Session de connexion expirée ou invalide. Reconnectez-vous.")
        return redirect("accounts:login")

    if request.method == "POST":
        form = MFACodeForm(request.POST)
        if form.is_valid() and mfa.verify_code(user.mfa_secret, form.cleaned_data["code"]):
            _clear_pending_mfa(request)
            login(request, user, backend="django.contrib.auth.backends.ModelBackend")
            ip = get_client_ip(request)
            if ip:
                user.last_login_ip = ip
                user.save(update_fields=["last_login_ip", "updated_at"])
            reset("login", ip or "-")
            reset("mfa_verify", ip or "-")
            return redirect("dashboard:home")
        form.add_error("code", "Code invalide ou expiré.")
    else:
        form = MFACodeForm()
    return render(request, "accounts/mfa_verify.html", {"form": form})


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
                "Compte créé. Un email de vérification vous a été envoyé : "
                "confirmez votre adresse pour pouvoir soumettre à un programme "
                "Bug Bounty (obligatoire dès qu'une récompense est en jeu).",
            )
            login(request, user, backend="django.contrib.auth.backends.ModelBackend")
            return redirect("dashboard:home")
    else:
        form = RegistrationForm()
    return render(request, "accounts/register.html", {"form": form})


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
        title="Verification de votre adresse email",
        body="Un nouveau lien de verification est disponible.",
        url=f"/verify-email/{token.token}/",
    )
    messages.success(request, "Un nouveau lien de vérification vous a été envoyé.")
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
            "api_key_form": ApiKeyForm(),
            "mfa_disable_form": MFADisableForm(),
        },
    )


@login_required
def mfa_activate(request):
    """Ecran d'activation du second facteur (TOTP).

    Le secret genere n'est ecrit en base qu'une fois le code de confirmation
    verifie : tant que l'utilisateur n'a pas prouve avoir bien scanne le QR
    code, aucune activation partielle ne peut le verrouiller hors de son
    compte.
    """
    if request.user.mfa_enabled:
        messages.info(request, "La double authentification est déjà activée.")
        return redirect("accounts:profile")

    if request.method == "POST":
        secret = request.session.get("mfa_pending_secret")
        form = MFACodeForm(request.POST)
        if secret and form.is_valid() and mfa.verify_code(secret, form.cleaned_data["code"]):
            request.user.mfa_secret = secret
            request.user.mfa_enabled = True
            request.user.save(update_fields=["mfa_secret", "mfa_enabled", "updated_at"])
            request.session.pop("mfa_pending_secret", None)
            log_action(
                AuditAction.USER_UPDATED,
                actor=request.user,
                obj=request.user,
                request=request,
                mfa="enabled",
            )
            messages.success(request, "Double authentification activée.")
            return redirect("accounts:profile")
        form.add_error(
            "code", "Code invalide. Vérifiez l'heure de votre téléphone et réessayez."
        )
    else:
        secret = mfa.generate_secret()
        request.session["mfa_pending_secret"] = secret
        form = MFACodeForm()

    uri = mfa.provisioning_uri(request.user.email, secret)
    return render(
        request,
        "accounts/mfa_activate.html",
        {
            "form": form,
            "secret": secret,
            "qr_data_uri": mfa.qr_code_data_uri(uri),
            "mfa_enforced": request.user.role in MFA_REQUIRED_ROLES,
        },
    )


@login_required
def mfa_disable(request):
    """Desactivation par l'utilisateur lui-meme : exige le mot de passe
    actuel (defense contre une session laissee ouverte sur un poste partage).
    Un administrateur peut aussi desactiver mfa_enabled depuis l'admin si
    l'utilisateur a perdu l'acces a son application d'authentification."""
    if not request.user.mfa_enabled:
        return redirect("accounts:profile")
    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])
    form = MFADisableForm(request.POST, user=request.user)
    if form.is_valid():
        request.user.mfa_enabled = False
        request.user.mfa_secret = ""
        request.user.save(update_fields=["mfa_enabled", "mfa_secret", "updated_at"])
        log_action(
            AuditAction.USER_UPDATED,
            actor=request.user,
            obj=request.user,
            request=request,
            mfa="disabled",
        )
        messages.success(request, "Double authentification désactivée.")
    else:
        messages.error(request, "Mot de passe incorrect : désactivation refusée.")
    return redirect("accounts:profile")


@login_required
def api_key_create(request):
    """Genere une nouvelle cle d'API. La valeur en clair n'est montree qu'une
    seule fois, dans le message de confirmation qui suit."""
    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])
    form = ApiKeyForm(request.POST)
    if not form.is_valid():
        messages.error(request, "Impossible de créer la clé : " + str(form.errors))
        return redirect("accounts:profile")

    raw_key, prefix, key_hash = generate_key()
    expires_in_days = form.cleaned_data.get("expires_in_days")
    expires_at = timezone.now() + timedelta(days=expires_in_days) if expires_in_days else None
    api_key = ApiKey.objects.create(
        user=request.user,
        label=form.cleaned_data["label"],
        prefix=prefix,
        key_hash=key_hash,
        expires_at=expires_at,
    )
    log_action(
        AuditAction.API_KEY_CREATED,
        actor=request.user,
        obj=api_key,
        request=request,
        label=api_key.label,
    )
    messages.success(
        request,
        f"Clé d'API créée : {raw_key}\n\n"
        "Copiez-la maintenant : elle ne sera plus jamais affichée en clair.",
    )
    return redirect("accounts:profile")


@login_required
def api_key_revoke(request, key_id):
    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])
    api_key = get_object_or_404(ApiKey, pk=key_id, user=request.user)
    api_key.is_active = False
    api_key.save(update_fields=["is_active", "updated_at"])
    log_action(
        AuditAction.API_KEY_REVOKED,
        actor=request.user,
        obj=api_key,
        request=request,
        label=api_key.label,
    )
    messages.success(request, f"Clé « {api_key.label} » révoquée.")
    return redirect("accounts:profile")


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


# ---------------------------------------------------------------------------
# Gestion des utilisateurs (MANAGE_USERS) : alternative a l'admin Django pour
# l'usage quotidien, sans exposer is_staff a un role non technique.
# ---------------------------------------------------------------------------
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


@login_required
@require_capability(Capability.MANAGE_USERS)
def user_manage_list(request):
    query = (request.GET.get("q") or "").strip()
    queryset = User.objects.all().order_by("email")
    if query:
        queryset = queryset.filter(Q(email__icontains=query) | Q(full_name__icontains=query))
    page = Paginator(queryset, 30).get_page(request.GET.get("page"))
    return render(request, "accounts/manage_list.html", {"page_obj": page, "query": query})


@login_required
@require_capability(Capability.MANAGE_USERS)
def user_manage_create(request):
    allow_super_admin = request.user.is_superuser
    if request.method == "POST":
        form = UserCreateForm(request.POST, allow_super_admin=allow_super_admin)
        if form.is_valid():
            role = form.cleaned_data["role"]
            if role == Role.SUPER_ADMIN and not allow_super_admin:
                form.add_error("role", "Seul un superutilisateur peut créer ce rôle.")
            else:
                user = User.objects.create_user(
                    email=form.cleaned_data["email"],
                    password=None,
                    full_name=form.cleaned_data["full_name"],
                    role=role,
                )
                log_action(
                    AuditAction.USER_CREATED,
                    actor=request.user,
                    obj=user,
                    request=request,
                    role=user.role,
                )
                send_password_setup_link(
                    user,
                    title="Votre compte eVDP a été créé",
                    body=(
                        f"{request.user.display_name or request.user.email} vous a créé "
                        "un compte sur eVDP. Choisissez votre mot de passe pour l'activer."
                    ),
                )
                messages.success(
                    request,
                    f"Compte créé pour {user.email} — un lien pour choisir son mot de "
                    "passe lui a été envoyé.",
                )
                return redirect("accounts:user_manage_detail", user_id=user.pk)
    else:
        form = UserCreateForm(allow_super_admin=allow_super_admin)
    return render(request, "accounts/manage_create.html", {"form": form})


@login_required
@require_capability(Capability.MANAGE_USERS)
def user_manage_detail(request, user_id):
    target = get_object_or_404(User, pk=user_id)
    allow_super_admin = request.user.is_superuser
    if not allow_super_admin and target.role == Role.SUPER_ADMIN:
        # Un coordinateur ne doit meme pas savoir qu'un compte super-admin
        # existe a cette adresse : meme traitement que les autres perimetres
        # (404, jamais 403, pour ne pas confirmer l'existence).
        raise Http404("Compte introuvable.")

    if request.method == "POST":
        form = UserEditForm(request.POST, allow_super_admin=allow_super_admin)
        if form.is_valid():
            new_role = form.cleaned_data["role"]
            new_active = form.cleaned_data["is_active"]
            if new_role == Role.SUPER_ADMIN and not allow_super_admin:
                form.add_error("role", "Seul un superutilisateur peut attribuer ce rôle.")
            elif target.id == request.user.id and not new_active:
                form.add_error(
                    "is_active", "Vous ne pouvez pas désactiver votre propre compte."
                )
            else:
                role_changed = target.role != new_role
                target.role = new_role
                target.is_active = new_active
                target.save(update_fields=["role", "is_active", "updated_at"])
                if role_changed:
                    log_action(
                        AuditAction.ROLE_CHANGED,
                        actor=request.user,
                        obj=target,
                        request=request,
                        new_role=target.role,
                    )
                messages.success(request, "Compte mis à jour.")
                return redirect("accounts:user_manage_detail", user_id=target.pk)
    else:
        form = UserEditForm(
            initial={"role": target.role, "is_active": target.is_active},
            allow_super_admin=allow_super_admin,
        )
    return render(request, "accounts/manage_detail.html", {"target": target, "form": form})


@login_required
@require_capability(Capability.MANAGE_USERS)
def user_manage_resend_link(request, user_id):
    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])
    target = get_object_or_404(User, pk=user_id)
    send_password_setup_link(
        target,
        title="Accès à votre compte eVDP",
        body=(
            f"{request.user.display_name or request.user.email} vous a envoyé un "
            "nouveau lien pour définir votre mot de passe eVDP."
        ),
    )
    log_action(
        AuditAction.PASSWORD_RESET_REQUESTED, actor=request.user, obj=target, request=request
    )
    messages.success(request, f"Lien envoyé à {target.email}.")
    return redirect("accounts:user_manage_detail", user_id=target.pk)
