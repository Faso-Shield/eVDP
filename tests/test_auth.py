"""Tests d'authentification et de gestion de compte."""

import pytest
from django.urls import reverse

from apps.accounts.models import TokenPurpose, User, UserToken
from apps.accounts.roles import Role
from apps.audit.models import AuditAction, AuditLog

from .conftest import PASSWORD

pytestmark = pytest.mark.django_db


def test_registration_creates_researcher_with_profile(client):
    response = client.post(
        reverse("accounts:register"),
        {
            "email": "nouveau@test.bf",
            "full_name": "Nouveau Chercheur",
            "role": Role.SECURITY_RESEARCHER,
            "password1": "MotDePasseTresSolide2026",
            "password2": "MotDePasseTresSolide2026",
            "pseudonym": "nouveau",
            "identity_mode": "PSEUDONYM",
            "accept_policy": "on",
        },
        follow=True,
    )
    assert response.status_code == 200
    user = User.objects.get(email="nouveau@test.bf")
    assert user.role == Role.SECURITY_RESEARCHER
    assert user.email_verified is False
    assert user.researcher_profile.pseudonym == "nouveau"


def test_registration_refuses_privileged_role(client):
    """Le role envoye par le client ne doit jamais accorder de privilege."""
    client.post(
        reverse("accounts:register"),
        {
            "email": "pirate@test.bf",
            "full_name": "Pirate",
            "role": Role.SUPER_ADMIN,
            "password1": "MotDePasseTresSolide2026",
            "password2": "MotDePasseTresSolide2026",
            "identity_mode": "PSEUDONYM",
            "accept_policy": "on",
        },
    )
    assert not User.objects.filter(email="pirate@test.bf").exists()


def test_registration_does_not_leak_existing_account(client, researcher_a):
    response = client.post(
        reverse("accounts:register"),
        {
            "email": researcher_a.email,
            "full_name": "Doublon",
            "role": Role.SECURITY_RESEARCHER,
            "password1": "MotDePasseTresSolide2026",
            "password2": "MotDePasseTresSolide2026",
            "identity_mode": "PSEUDONYM",
            "accept_policy": "on",
        },
    )
    content = response.content.decode()
    assert "existe deja" not in content.lower()
    assert User.objects.filter(email=researcher_a.email).count() == 1


def test_login_success_is_audited(client, researcher_a):
    response = client.post(
        reverse("accounts:login"),
        {"username": researcher_a.email, "password": PASSWORD},
        follow=True,
    )
    assert response.status_code == 200
    assert AuditLog.objects.filter(action=AuditAction.LOGIN, actor=researcher_a).exists()


def test_failed_login_is_audited(client, researcher_a):
    client.post(
        reverse("accounts:login"),
        {"username": researcher_a.email, "password": "mauvais-mot-de-passe"},
    )
    assert AuditLog.objects.filter(action=AuditAction.LOGIN_FAILED).exists()


def test_email_verification_consumes_token(client, researcher_a):
    researcher_a.email_verified = False
    researcher_a.save(update_fields=["email_verified"])
    token = UserToken.issue(researcher_a, TokenPurpose.EMAIL_VERIFICATION)

    client.force_login(researcher_a)
    client.get(reverse("accounts:verify_email", args=[token.token]), follow=True)

    researcher_a.refresh_from_db()
    token.refresh_from_db()
    assert researcher_a.email_verified is True
    assert token.used_at is not None
    assert token.is_valid is False


def test_expired_token_is_rejected(client, researcher_a):
    from datetime import timedelta

    from django.utils import timezone

    researcher_a.email_verified = False
    researcher_a.save(update_fields=["email_verified"])
    token = UserToken.issue(researcher_a, TokenPurpose.EMAIL_VERIFICATION)
    token.expires_at = timezone.now() - timedelta(hours=1)
    token.save(update_fields=["expires_at"])

    client.force_login(researcher_a)
    client.get(reverse("accounts:verify_email", args=[token.token]), follow=True)

    researcher_a.refresh_from_db()
    assert researcher_a.email_verified is False


def test_user_cannot_change_own_role_via_profile(client_for, researcher_a):
    client = client_for(researcher_a)
    client.post(
        reverse("accounts:profile"),
        {
            "full_name": "Chercheur",
            "display_name": "chercheur",
            "phone": "",
            "role": Role.SUPER_ADMIN,
            "is_staff": "on",
            "is_superuser": "on",
            "pseudonym": "alpha-hunter",
            "country": "Burkina Faso",
            "affiliation": "",
            "website": "",
            "biography": "",
            "identity_mode": "PSEUDONYM",
        },
    )
    researcher_a.refresh_from_db()
    assert researcher_a.role == Role.SECURITY_RESEARCHER
    assert researcher_a.is_staff is False
    assert researcher_a.is_superuser is False


def test_anonymous_is_redirected_from_dashboard(client):
    response = client.get(reverse("dashboard:home"))
    assert response.status_code == 302
    assert "/login/" in response.url


def test_password_hashing_uses_configured_hasher(researcher_a):
    assert not researcher_a.password.startswith("plain")
    assert researcher_a.check_password(PASSWORD)


# ------------------------------------------------ activation par email
REGISTRATION = {
    "email": "activation@test.bf",
    "full_name": "A Activer",
    "role": Role.SECURITY_RESEARCHER,
    "password1": "MotDePasseTresSolide2026",
    "password2": "MotDePasseTresSolide2026",
    "identity_mode": "PSEUDONYM",
    "accept_policy": "on",
}


def _activation_link(mailbox):
    import re

    return re.search(r"https?://[^\s]+/verify-email/[^\s/]+/", mailbox[-1].body).group(0)


def test_account_stays_inactive_until_its_email_is_confirmed(client, mailoutbox):
    response = client.post(reverse("accounts:register"), REGISTRATION)
    assert "Vérifiez votre boîte mail" in response.content.decode()
    user = User.objects.get(email="activation@test.bf")
    assert not user.is_active and user.pending_activation
    # Ni connecte d'office, ni capable de se connecter.
    assert "_auth_user_id" not in client.session
    client.post(
        reverse("accounts:login"),
        {"username": "activation@test.bf", "password": "MotDePasseTresSolide2026"},
    )
    assert "_auth_user_id" not in client.session

    link = _activation_link(mailoutbox)
    response = client.get(link[link.index("/verify-email/") :])
    user.refresh_from_db()
    assert user.is_active and user.email_verified and not user.pending_activation
    assert response["Location"] == reverse("dashboard:home")
    assert client.session["_auth_user_id"] == str(user.pk)


def test_old_link_does_not_revive_a_disabled_account(client, mailoutbox, researcher_a):
    token = UserToken.issue(researcher_a, TokenPurpose.EMAIL_VERIFICATION)
    researcher_a.is_active = False
    researcher_a.save(update_fields=["is_active"])
    client.get(reverse("accounts:verify_email", args=[token.token]))
    researcher_a.refresh_from_db()
    assert not researcher_a.is_active


def test_activation_link_can_be_resent_without_revealing_accounts(client, mailoutbox):
    client.post(reverse("accounts:register"), REGISTRATION)
    sent = len(mailoutbox)
    url = reverse("accounts:resend_activation")
    known = client.post(url, {"email": "activation@test.bf"}).content.decode()
    assert len(mailoutbox) == sent + 1
    unknown = client.post(url, {"email": "personne@test.bf"}).content.decode()
    assert len(mailoutbox) == sent + 1
    assert ("Si une inscription en attente" in known) and (
        "Si une inscription en attente" in unknown
    )


def test_unconfirmed_registrations_are_purged_after_a_week(client):
    from datetime import timedelta

    from django.utils import timezone

    from apps.accounts.tasks import purge_pending_activations

    client.post(reverse("accounts:register"), REGISTRATION)
    User.objects.filter(email="activation@test.bf").update(
        created_at=timezone.now() - timedelta(days=8)
    )
    assert purge_pending_activations() == 1
    assert not User.objects.filter(email="activation@test.bf").exists()
