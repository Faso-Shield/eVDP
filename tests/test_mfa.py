"""Tests de la double authentification (TOTP)."""

import pyotp
import pytest
from django.urls import reverse

from apps.accounts import mfa
from apps.accounts.models import User
from apps.accounts.roles import Role
from apps.audit.models import AuditAction, AuditLog

from .conftest import PASSWORD

pytestmark = pytest.mark.django_db


# --------------------------------------------------------------- activation
def test_activation_page_shows_qr_code(client_for, researcher_a):
    client = client_for(researcher_a)
    response = client.get(reverse("accounts:mfa_activate"))
    assert response.status_code == 200
    assert "qr_data_uri" in response.context
    assert response.context["qr_data_uri"].startswith("data:image/png;base64,")
    assert "mfa_pending_secret" in client.session


def test_activation_with_correct_code_enables_mfa(client_for, researcher_a):
    client = client_for(researcher_a)
    client.get(reverse("accounts:mfa_activate"))
    secret = client.session["mfa_pending_secret"]
    code = pyotp.TOTP(secret).now()

    response = client.post(reverse("accounts:mfa_activate"), {"code": code}, follow=True)
    assert response.status_code == 200

    researcher_a.refresh_from_db()
    assert researcher_a.mfa_enabled is True
    assert researcher_a.mfa_secret == secret
    assert "mfa_pending_secret" not in client.session
    assert AuditLog.objects.filter(
        action=AuditAction.USER_UPDATED, actor=researcher_a
    ).exists()


def test_activation_with_wrong_code_does_not_enable_mfa(client_for, researcher_a):
    client = client_for(researcher_a)
    client.get(reverse("accounts:mfa_activate"))

    response = client.post(reverse("accounts:mfa_activate"), {"code": "000000"})
    assert response.status_code == 200

    researcher_a.refresh_from_db()
    assert researcher_a.mfa_enabled is False


def test_cannot_reactivate_already_enabled_mfa(client_for, researcher_a):
    researcher_a.mfa_enabled = True
    researcher_a.mfa_secret = mfa.generate_secret()
    researcher_a.save(update_fields=["mfa_enabled", "mfa_secret"])
    client = client_for(researcher_a)
    response = client.get(reverse("accounts:mfa_activate"))
    assert response.status_code == 302


# -------------------------------------------------------------------- login
def test_login_without_mfa_logs_in_directly(client, researcher_a):
    response = client.post(
        reverse("accounts:login"),
        {"username": researcher_a.email, "password": PASSWORD},
        follow=True,
    )
    assert response.status_code == 200
    assert response.wsgi_request.user == researcher_a


def test_login_with_mfa_does_not_log_in_before_second_factor(client, researcher_a):
    researcher_a.mfa_enabled = True
    researcher_a.mfa_secret = mfa.generate_secret()
    researcher_a.save(update_fields=["mfa_enabled", "mfa_secret"])

    response = client.post(
        reverse("accounts:login"),
        {"username": researcher_a.email, "password": PASSWORD},
    )
    assert response.status_code == 302
    assert response.url == reverse("accounts:mfa_verify")
    assert response.wsgi_request.user.is_authenticated is False
    assert client.session["mfa_user_id"] == str(researcher_a.pk)


def test_login_with_mfa_completes_with_correct_code(client, researcher_a):
    secret = mfa.generate_secret()
    researcher_a.mfa_enabled = True
    researcher_a.mfa_secret = secret
    researcher_a.save(update_fields=["mfa_enabled", "mfa_secret"])

    client.post(
        reverse("accounts:login"), {"username": researcher_a.email, "password": PASSWORD}
    )
    code = pyotp.TOTP(secret).now()
    response = client.post(reverse("accounts:mfa_verify"), {"code": code}, follow=True)

    assert response.status_code == 200
    assert response.wsgi_request.user == researcher_a
    assert AuditLog.objects.filter(action=AuditAction.LOGIN, actor=researcher_a).exists()
    assert "mfa_user_id" not in client.session


def test_login_with_mfa_rejects_wrong_code(client, researcher_a):
    secret = mfa.generate_secret()
    researcher_a.mfa_enabled = True
    researcher_a.mfa_secret = secret
    researcher_a.save(update_fields=["mfa_enabled", "mfa_secret"])

    client.post(
        reverse("accounts:login"), {"username": researcher_a.email, "password": PASSWORD}
    )
    response = client.post(reverse("accounts:mfa_verify"), {"code": "000000"})
    assert response.status_code == 200
    assert response.wsgi_request.user.is_authenticated is False


def test_mfa_verify_without_pending_login_redirects_to_login(client):
    response = client.get(reverse("accounts:mfa_verify"))
    assert response.status_code == 302
    assert response.url == reverse("accounts:login")


def test_mfa_verify_is_rate_limited(client, researcher_a):
    secret = mfa.generate_secret()
    researcher_a.mfa_enabled = True
    researcher_a.mfa_secret = secret
    researcher_a.save(update_fields=["mfa_enabled", "mfa_secret"])
    client.post(
        reverse("accounts:login"), {"username": researcher_a.email, "password": PASSWORD}
    )

    statuses = [
        client.post(reverse("accounts:mfa_verify"), {"code": "000000"}).status_code
        for _ in range(10)
    ]
    assert 429 in statuses


# ------------------------------------------------------------------ desactivation
def test_disable_requires_correct_password(client_for, researcher_a):
    researcher_a.mfa_enabled = True
    researcher_a.mfa_secret = mfa.generate_secret()
    researcher_a.save(update_fields=["mfa_enabled", "mfa_secret"])
    client = client_for(researcher_a)

    response = client.post(reverse("accounts:mfa_disable"), {"password": "mauvais"})
    assert response.status_code == 302
    researcher_a.refresh_from_db()
    assert researcher_a.mfa_enabled is True


def test_disable_with_correct_password_disables_mfa(client_for, researcher_a):
    researcher_a.mfa_enabled = True
    researcher_a.mfa_secret = mfa.generate_secret()
    researcher_a.save(update_fields=["mfa_enabled", "mfa_secret"])
    client = client_for(researcher_a)

    response = client.post(reverse("accounts:mfa_disable"), {"password": PASSWORD})
    assert response.status_code == 302
    researcher_a.refresh_from_db()
    assert researcher_a.mfa_enabled is False
    assert researcher_a.mfa_secret == ""


# ------------------------------------------------------ mise en application
def _unprotected_coordinator():
    """Un role interne provisionne sans MFA : cas que le middleware doit bloquer.

    Ne passe pas par make_user(), qui active le MFA par defaut pour les roles
    a privilege afin de ne pas casser le reste de la suite : ce test veut au
    contraire un compte encore "non onboarde"."""
    return User.objects.create_user(
        email="coordinateur-sans-mfa@test.bf",
        password=PASSWORD,
        role=Role.NATIONAL_COORDINATOR,
        full_name="Coordinateur sans MFA",
    )


def test_privileged_role_without_mfa_is_redirected_to_activation(client_for):
    user = _unprotected_coordinator()
    client = client_for(user)
    response = client.get(reverse("dashboard:home"))
    assert response.status_code == 302
    assert response.url == reverse("accounts:mfa_activate")


def test_privileged_role_with_mfa_reaches_dashboard(client_for, coordinator):
    """coordinator (fixture) a deja mfa_enabled=True : voir make_user()."""
    client = client_for(coordinator)
    response = client.get(reverse("dashboard:home"), follow=True)
    assert response.status_code == 200
    assert response.redirect_chain[-1][0] != reverse("accounts:mfa_activate")


def test_researcher_role_is_never_enforced(client_for, researcher_a):
    assert researcher_a.mfa_enabled is False
    client = client_for(researcher_a)
    response = client.get(reverse("dashboard:home"), follow=True)
    assert response.status_code == 200
    assert response.redirect_chain[-1][0] != reverse("accounts:mfa_activate")


def test_mfa_activation_page_itself_stays_reachable_without_mfa(client_for):
    user = _unprotected_coordinator()
    client = client_for(user)
    response = client.get(reverse("accounts:mfa_activate"))
    assert response.status_code == 200


def test_logout_stays_reachable_without_mfa(client_for):
    user = _unprotected_coordinator()
    client = client_for(user)
    response = client.post(reverse("accounts:logout"))
    assert response.status_code in (200, 302)
    assert response.wsgi_request.user.is_authenticated is False


def test_unprotected_coordinator_can_complete_activation_and_then_reach_dashboard(
    client_for,
):
    user = _unprotected_coordinator()
    client = client_for(user)
    client.get(reverse("accounts:mfa_activate"))
    secret = client.session["mfa_pending_secret"]
    code = pyotp.TOTP(secret).now()
    client.post(reverse("accounts:mfa_activate"), {"code": code})

    response = client.get(reverse("dashboard:home"), follow=True)
    assert response.status_code == 200
    assert response.redirect_chain[-1][0] != reverse("accounts:mfa_activate")


# ----------------------------------------------------------------------- helpers
def test_verify_code_rejects_malformed_input():
    secret = mfa.generate_secret()
    assert mfa.verify_code(secret, "") is False
    assert mfa.verify_code(secret, "abcdef") is False
    assert mfa.verify_code(secret, "12345") is False
    assert mfa.verify_code("", "123456") is False
