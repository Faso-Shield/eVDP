"""Gestion des comptes dans l'application (MANAGE_USERS)."""

import pytest
from django.urls import reverse

from apps.accounts.models import User
from apps.accounts.roles import Role
from apps.audit.models import AuditAction, AuditLog
from apps.notifications.models import Notification, NotificationKind
from apps.organizations.models import OrganizationMember

from .conftest import make_user

pytestmark = pytest.mark.django_db


@pytest.fixture
def superadmin(db):
    return make_user("root@test.bf", Role.SUPER_ADMIN, is_superuser=True, is_staff=True)


def test_only_account_managers_reach_the_screen(
    client_for, coordinator, analyst, researcher_a
):
    url = reverse("accounts:user_manage_list")
    assert client_for(coordinator).get(url).status_code == 200
    assert client_for(analyst).get(url).status_code == 403
    assert client_for(researcher_a).get(url).status_code == 403


def test_super_admins_stay_out_of_reach_of_a_coordinator(client_for, coordinator, superadmin):
    client = client_for(coordinator)
    assert (
        superadmin.email
        not in client.get(reverse("accounts:user_manage_list")).content.decode()
    )
    for name in ("user_manage_detail", "user_manage_resend_link", "user_manage_reset_mfa"):
        url = reverse(f"accounts:{name}", args=[superadmin.pk])
        response = client.post(url) if name != "user_manage_detail" else client.get(url)
        assert response.status_code == 404, name


def test_creation_sends_a_setup_link_and_attaches_the_organization(
    client_for, coordinator, organization
):
    response = client_for(coordinator).post(
        reverse("accounts:user_manage_create"),
        {
            "email": "Nouvelle.DSI@alpha.bf",
            "full_name": "Nouvelle DSI",
            "role": Role.DSI_ADMIN,
            "organization": organization.pk,
        },
    )
    user = User.objects.get(email="nouvelle.dsi@alpha.bf")
    assert response["Location"] == reverse("accounts:user_manage_detail", args=[user.pk])
    assert not user.has_usable_password()
    assert OrganizationMember.objects.filter(user=user, organization=organization).exists()
    assert Notification.objects.filter(recipient=user, kind=NotificationKind.ACCOUNT).exists()
    assert AuditLog.objects.filter(
        action=AuditAction.USER_CREATED, object_id=str(user.pk)
    ).exists()


def test_an_organization_account_needs_its_organization(client_for, coordinator):
    client_for(coordinator).post(
        reverse("accounts:user_manage_create"),
        {"email": "dsi@exemple.bf", "full_name": "DSI", "role": Role.DSI_ADMIN},
    )
    assert not User.objects.filter(email="dsi@exemple.bf").exists()


def test_a_coordinator_cannot_create_a_super_admin(client_for, coordinator):
    client_for(coordinator).post(
        reverse("accounts:user_manage_create"),
        {"email": "pirate@exemple.bf", "full_name": "X", "role": Role.SUPER_ADMIN},
    )
    assert not User.objects.filter(email="pirate@exemple.bf").exists()


def test_nobody_changes_its_own_role_or_disables_itself(client_for, coordinator):
    url = reverse("accounts:user_manage_detail", args=[coordinator.pk])
    client = client_for(coordinator)
    client.post(url, {"role": Role.CSIRT_ANALYST, "is_active": "on"})
    client.post(url, {"role": Role.NATIONAL_COORDINATOR})
    coordinator.refresh_from_db()
    assert coordinator.role == Role.NATIONAL_COORDINATOR
    assert coordinator.is_active


def test_role_and_state_changes_are_audited(client_for, coordinator, triager):
    url = reverse("accounts:user_manage_detail", args=[triager.pk])
    client_for(coordinator).post(url, {"role": Role.CSIRT_ANALYST})
    triager.refresh_from_db()
    assert triager.role == Role.CSIRT_ANALYST
    assert not triager.is_active
    assert AuditLog.objects.filter(
        action=AuditAction.ROLE_CHANGED, object_id=str(triager.pk)
    ).exists()
    assert AuditLog.objects.filter(
        action=AuditAction.USER_UPDATED, object_id=str(triager.pk)
    ).exists()


def test_a_reporter_keeps_its_role(client_for, coordinator, researcher_a):
    url = reverse("accounts:user_manage_detail", args=[researcher_a.pk])
    client_for(coordinator).post(url, {"role": Role.NATIONAL_COORDINATOR, "is_active": "on"})
    researcher_a.refresh_from_db()
    assert researcher_a.role == Role.SECURITY_RESEARCHER


def test_manager_resets_a_second_factor(client_for, coordinator, analyst):
    analyst.mfa_secret = "JBSWY3DPEHPK3PXP"
    analyst.mfa_enabled = True
    analyst.save()
    client_for(coordinator).post(reverse("accounts:user_manage_reset_mfa", args=[analyst.pk]))
    analyst.refresh_from_db()
    assert not analyst.mfa_enabled
    assert AuditLog.objects.filter(
        action=AuditAction.MFA_RESET, object_id=str(analyst.pk)
    ).exists()
