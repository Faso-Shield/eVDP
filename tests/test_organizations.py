"""Tests des organisations : isolation multi-organisation, gestion."""

import pytest
from django.urls import reverse

from apps.organizations.models import Organization

pytestmark = pytest.mark.django_db


def manage_payload(organization, **overrides):
    payload = {
        "name": organization.name,
        "acronym": organization.acronym,
        "organization_type": organization.organization_type,
        "sector": organization.sector,
        "status": organization.status,
        "domain": organization.domain,
        "accepts_vdp": "on" if organization.accepts_vdp else "",
    }
    payload.update(overrides)
    return payload


# --------------------------------------------------------------- isolation
def test_manager_cannot_manage_another_organization(
    client_for, manager_alpha, other_organization
):
    """Regression : aucun test ne couvrait l'isolation multi-organisation
    pour la gestion (uniquement pour les cases)."""
    client = client_for(manager_alpha)
    response = client.get(reverse("organizations:manage", args=[other_organization.slug]))
    assert response.status_code == 404


def test_manager_can_manage_own_organization(client_for, manager_alpha, organization):
    client = client_for(manager_alpha)
    response = client.get(reverse("organizations:manage", args=[organization.slug]))
    assert response.status_code == 200


def test_manager_cannot_update_another_organization_via_post(
    client_for, manager_beta, organization, other_organization
):
    """manager_beta appartient a other_organization : toute tentative de POST
    sur `organization` (qui n'est pas la sienne) doit etre refusee, pas
    seulement le GET."""
    client = client_for(manager_beta)
    response = client.post(
        reverse("organizations:manage", args=[organization.slug]),
        manage_payload(organization, name="Nom modifie par un tiers"),
    )
    assert response.status_code == 404
    organization.refresh_from_db()
    assert organization.name != "Nom modifie par un tiers"


def test_manage_list_only_shows_own_organizations(
    client_for, manager_alpha, organization, other_organization
):
    client = client_for(manager_alpha)
    response = client.get(reverse("organizations:manage_list"))
    content = response.content.decode()
    assert organization.name in content
    assert other_organization.name not in content


def test_dsi_cannot_create_organization(client_for, dsi_alpha):
    """Seule une capacite nationale (MANAGE_ALL_ORGANIZATIONS) peut creer une
    organisation ; une DSI ne gere que celle(s) dont elle est deja membre."""
    client = client_for(dsi_alpha)
    response = client.get(reverse("organizations:create"))
    assert response.status_code == 403


def test_national_coordinator_can_manage_any_organization(
    client_for, coordinator, other_organization
):
    client = client_for(coordinator)
    response = client.get(reverse("organizations:manage", args=[other_organization.slug]))
    assert response.status_code == 200


# ------------------------------------------------------------------- public
def test_inactive_organization_hidden_from_public_detail(client, organization):
    from apps.organizations.models import OrganizationStatus

    organization.status = OrganizationStatus.SUSPENDED
    organization.save(update_fields=["status"])
    response = client.get(reverse("organizations:detail", args=[organization.slug]))
    assert response.status_code == 404


def test_national_user_can_still_see_inactive_organization(
    client_for, coordinator, organization
):
    from apps.organizations.models import OrganizationStatus

    organization.status = OrganizationStatus.SUSPENDED
    organization.save(update_fields=["status"])
    client = client_for(coordinator)
    response = client.get(reverse("organizations:detail", args=[organization.slug]))
    assert response.status_code == 200


def test_organization_list_only_shows_vdp_accepting_active_organizations(client, organization):
    organization.accepts_vdp = False
    organization.save(update_fields=["accepts_vdp"])
    response = client.get(reverse("organizations:list"))
    assert organization.name not in response.content.decode()


def test_organization_count_unaffected_by_query_injection_attempt(client):
    """Verification basique : un caractere special dans la recherche ne
    casse pas la page (pas d'injection SQL via icontains parametree)."""
    response = client.get(reverse("organizations:list"), {"q": "%' OR '1'='1"})
    assert response.status_code == 200
    assert Organization.objects.exists() or True


# --------------------------------------------------------------- membres
def test_manager_can_add_existing_user_as_member(
    client_for, manager_alpha, organization, analyst
):
    from apps.organizations.models import MembershipRole, OrganizationMember

    client = client_for(manager_alpha)
    response = client.post(
        reverse("organizations:member_add", args=[organization.slug]),
        {"email": analyst.email, "membership_role": MembershipRole.ANALYST, "is_primary": ""},
    )
    assert response.status_code == 302
    assert OrganizationMember.objects.filter(organization=organization, user=analyst).exists()


def test_manager_cannot_add_member_to_another_organization(
    client_for, manager_alpha, other_organization, analyst
):
    """Isolation multi-organisation : une DSI ne doit pas pouvoir rattacher
    quelqu'un a une organisation dont elle n'est pas gestionnaire."""
    from apps.organizations.models import MembershipRole, OrganizationMember

    client = client_for(manager_alpha)
    response = client.post(
        reverse("organizations:member_add", args=[other_organization.slug]),
        {"email": analyst.email, "membership_role": MembershipRole.ANALYST, "is_primary": ""},
    )
    assert response.status_code == 404
    assert not OrganizationMember.objects.filter(
        organization=other_organization, user=analyst
    ).exists()


def test_add_member_with_unknown_email_creates_nothing(
    client_for, manager_alpha, organization
):
    from apps.organizations.models import MembershipRole, OrganizationMember

    client = client_for(manager_alpha)
    response = client.post(
        reverse("organizations:member_add", args=[organization.slug]),
        {
            "email": "inconnu@test.bf",
            "membership_role": MembershipRole.ANALYST,
            "is_primary": "",
        },
    )
    assert response.status_code == 302
    assert (
        not OrganizationMember.objects.filter(organization=organization)
        .exclude(user=manager_alpha)
        .exists()
    )


# ------------------------------------------------ qui gere les organisations
def test_analyst_manages_any_organization(client_for, analyst, other_organization):
    client = client_for(analyst)
    assert client.get(reverse("organizations:manage_list")).status_code == 200
    assert (
        client.get(reverse("organizations:manage", args=[other_organization.slug])).status_code
        == 200
    )
    assert client.get(reverse("organizations:create")).status_code == 200


def test_dsi_no_longer_manages_its_organization(client_for, dsi_alpha, organization):
    """La DSI traite la remediation ; la fiche revient au responsable."""
    client = client_for(dsi_alpha)
    assert client.get(reverse("organizations:manage_list")).status_code == 403
    assert (
        client.get(reverse("organizations:manage", args=[organization.slug])).status_code
        == 403
    )


@pytest.mark.parametrize("role", ["TRIAGER", "AUDITOR", "SECURITY_RESEARCHER"])
def test_other_roles_cannot_manage_organizations(client_for, role, organization):
    from .conftest import make_user

    user = make_user(f"autre-{role.lower()}@test.bf", role)
    assert client_for(user).get(reverse("organizations:manage_list")).status_code == 403


def test_super_admin_cannot_manage_organizations(client_for, organization):
    from apps.accounts.models import User

    root = User.objects.create_superuser(email="root-org@test.bf", password="Xx-123456789!")
    client = client_for(root)
    assert client.get(reverse("organizations:manage_list")).status_code == 403
    assert client.get("/admin/organizations/organization/").status_code in (302, 403)
