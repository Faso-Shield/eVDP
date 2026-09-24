"""Rattachement d'un compte DSI ou responsable d'organisation a son organisation.

Depuis le perimetre par etape, un compte d'organisation non rattache ne voit
aucun dossier, meme aux etapes 6 et 7 qui lui reviennent. Le rattachement
se fait donc des la creation du compte (administration), et reste possible
depuis la fiche de l'organisation dans l'application.
"""

import pytest
from django.urls import reverse

from apps.accounts.admin import BusinessAccountAdmin
from apps.accounts.models import BusinessAccount, User
from apps.accounts.roles import Role
from apps.audit.models import AuditAction, AuditLog
from apps.organizations.models import MembershipRole, OrganizationMember

from .conftest import PASSWORD, make_user

pytestmark = pytest.mark.django_db


@pytest.fixture
def admin_client(client_for, db):
    superuser = User.objects.create_superuser(email="root@test.bf", password=PASSWORD)
    return client_for(superuser)


def _creation_data(**overrides):
    data = {
        "email": "nouvelle-dsi@alpha.gov.bf",
        "full_name": "Nouvelle DSI",
        "role": Role.DSI_ADMIN,
        "password1": "Evdp-Solide-2026!",
        "password2": "Evdp-Solide-2026!",
        "usable_password": "true",
    }
    data.update(overrides)
    return data


ADD_URL = "/admin/accounts/businessaccount/add/"


def _creation_form(rf, data):
    """Formulaire de creation tel que l'administration le construit."""
    from django.contrib.admin.sites import site

    request = rf.get(ADD_URL)
    request.user = User.objects.create_superuser(email="form@test.bf", password=PASSWORD)
    form_class = BusinessAccountAdmin(BusinessAccount, site).get_form(request, obj=None)
    return form_class(data=data)


# ------------------------------------------------ creation (administration)
@pytest.mark.parametrize("role", [Role.DSI_ADMIN, Role.ORGANIZATION_MANAGER])
def test_organization_is_required_for_organization_roles(rf, role):
    form = _creation_form(rf, _creation_data(role=role))
    assert not form.is_valid()
    assert "organization" in form.errors


def test_organization_stays_optional_for_national_roles(rf):
    form = _creation_form(rf, _creation_data(role=Role.CSIRT_ANALYST))
    form.is_valid()
    assert "organization" not in form.errors


def test_creation_form_offers_the_organization(admin_client, organization):
    content = admin_client.get(ADD_URL).content.decode()
    assert 'name="organization"' in content
    assert organization.name in content


@pytest.mark.parametrize(
    ("role", "membership"),
    [
        (Role.DSI_ADMIN, MembershipRole.DSI),
        (Role.ORGANIZATION_MANAGER, MembershipRole.MANAGER),
    ],
)
def test_created_account_is_attached_to_its_organization(
    admin_client, organization, role, membership
):
    response = admin_client.post(
        ADD_URL, _creation_data(role=role, organization=organization.pk)
    )
    assert response.status_code == 302, response.content.decode()[:500]

    user = User.objects.get(email="nouvelle-dsi@alpha.gov.bf")
    member = OrganizationMember.objects.get(user=user)
    assert member.organization == organization
    assert member.membership_role == membership
    assert member.is_primary
    assert user.primary_organization == organization
    assert AuditLog.objects.filter(
        action=AuditAction.MEMBERSHIP_CHANGED, object_id=str(organization.pk)
    ).exists()


def test_creation_without_organization_is_refused(admin_client):
    response = admin_client.post(ADD_URL, _creation_data())
    assert response.status_code == 200  # formulaire reaffiche avec l'erreur
    assert not User.objects.filter(email="nouvelle-dsi@alpha.gov.bf").exists()


def test_attached_dsi_sees_its_cases_at_its_steps(organization, case_alpha):
    """Le rattachement est ce qui rend les etapes 6 et 7 accessibles."""
    from apps.coordination.models import Case
    from apps.coordination.workflow import CaseStatus

    from .conftest import advance

    advance(case_alpha, CaseStatus.VENDOR_NOTIFIED)
    orphan = make_user("dsi-orpheline@test.bf", Role.DSI_ADMIN)
    assert case_alpha not in Case.objects.visible_to(orphan)
    OrganizationMember.objects.create(
        organization=organization, user=orphan, membership_role=MembershipRole.DSI
    )
    assert case_alpha in Case.objects.visible_to(orphan)


def test_organizations_are_editable_after_creation(admin_client, dsi_alpha):
    content = admin_client.get(
        f"/admin/accounts/businessaccount/{dsi_alpha.pk}/change/"
    ).content.decode()
    assert "Organisations rattachées" in content


# ------------------------------------------ fiche de l'organisation (appli)
def test_manage_page_shows_the_member_form(client_for, dsi_alpha, organization):
    content = (
        client_for(dsi_alpha)
        .get(reverse("organizations:manage", args=[organization.slug]))
        .content.decode()
    )
    assert "Ajouter un membre" in content
    assert reverse("organizations:member_add", args=[organization.slug]) in content
    assert "administration Django" not in content


@pytest.mark.parametrize(
    ("membership", "role"),
    [
        (MembershipRole.DSI, Role.DSI_ADMIN),
        (MembershipRole.MANAGER, Role.ORGANIZATION_MANAGER),
    ],
)
def test_invitation_gives_the_matching_role(
    client_for, coordinator, organization, membership, role
):
    response = client_for(coordinator).post(
        reverse("organizations:member_add", args=[organization.slug]),
        {
            "email": "invitee@alpha.gov.bf",
            "full_name": "Personne Invitee",
            "membership_role": membership,
            "is_primary": "",
        },
    )
    assert response.status_code == 302
    invited = User.objects.get(email="invitee@alpha.gov.bf")
    assert invited.role == role
    assert OrganizationMember.objects.filter(
        organization=organization, user=invited, membership_role=membership
    ).exists()
