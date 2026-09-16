"""Tests RBAC : isolation stricte des donnees et des capacites."""

import pytest
from django.urls import reverse

from apps.accounts.roles import Capability, Role
from apps.coordination.models import Case
from apps.coordination.services import transition_case
from apps.coordination.workflow import CaseStatus

pytestmark = pytest.mark.django_db


# ---------------------------------------------------------- isolation chercheur
def test_researcher_cannot_access_other_researcher_case(client_for, researcher_a, case_beta):
    """Un chercheur A ne peut pas acceder au rapport du chercheur B."""
    client = client_for(researcher_a)
    response = client.get(reverse("coordination:case_detail", args=[case_beta.case_id]))
    assert response.status_code == 404


def test_researcher_sees_only_own_cases_in_list(
    client_for, researcher_a, case_alpha, case_beta
):
    client = client_for(researcher_a)
    response = client.get(reverse("coordination:case_list"))
    content = response.content.decode()
    assert case_alpha.case_id in content
    assert case_beta.case_id not in content


def test_case_queryset_isolation(researcher_a, case_alpha, case_beta):
    visible = set(Case.objects.visible_to(researcher_a).values_list("case_id", flat=True))
    assert visible == {case_alpha.case_id}


# ------------------------------------------------- navigation adaptee au role
def test_researcher_dashboard_hides_csirt_only_navigation(client_for, researcher_a):
    """Un chercheur ne doit jamais voir de lien vers une zone qu'il ne peut pas
    ouvrir (Journal d'audit, Organisations, Kanban...) : le backend refusait
    deja l'acces, mais un lien menant a un ecran "Acces refuse" reste une
    mauvaise experience, pas une protection."""
    client = client_for(researcher_a)
    response = client.get(reverse("dashboard:researcher"))
    content = response.content.decode()
    assert "Journal d'audit" not in content
    assert "Organisations</a>" not in content
    assert "Kanban" not in content
    assert "Rédaction d'advisories" not in content
    assert "Mes programmes" not in content


def test_coordinator_dashboard_keeps_full_navigation(client_for, coordinator):
    client = client_for(coordinator)
    response = client.get(reverse("dashboard:home"), follow=True)
    content = response.content.decode()
    assert "Journal d'audit" in content
    assert "Kanban" in content


def test_case_list_hides_organization_columns_for_researcher(
    client_for, researcher_a, case_alpha
):
    client = client_for(researcher_a)
    response = client.get(reverse("coordination:case_list"))
    assert response.context["researcher_view"] is True
    content = response.content.decode()
    assert "Toutes les organisations" not in content
    assert "Mes dossiers" in content


def test_case_list_keeps_organization_filter_for_coordinator(client_for, coordinator):
    client = client_for(coordinator)
    response = client.get(reverse("coordination:case_list"))
    assert response.context["researcher_view"] is False
    assert "Toutes les organisations" in response.content.decode()


# ------------------------------------------------------- isolation organisation
def test_organization_cannot_access_other_organization_case(client_for, dsi_beta, case_alpha):
    """Une organisation A ne peut pas acceder aux vulnerabilites de B."""
    client = client_for(dsi_beta)
    response = client.get(reverse("coordination:case_detail", args=[case_alpha.case_id]))
    assert response.status_code == 404


def test_organization_accesses_own_case(client_for, dsi_alpha, case_alpha, coordinator):
    """L'organisation n'accede au dossier qu'une fois le CSIRT l'ayant
    explicitement engagee -- jamais pendant le triage (voir test ci-dessous)."""
    for target in (CaseStatus.TRIAGE, CaseStatus.VALIDATED, CaseStatus.VENDOR_CONTACTED):
        transition_case(case_alpha, target, coordinator)
    client = client_for(dsi_alpha)
    response = client.get(reverse("coordination:case_detail", args=[case_alpha.case_id]))
    assert response.status_code == 200


def test_organization_cannot_access_case_before_vendor_contacted(
    client_for, dsi_alpha, case_alpha
):
    """Protection du declarant pendant le triage : l'organisation ne doit
    rien voir d'un dossier qui la concerne tant que le CSIRT ne l'a pas
    explicitement engagee (cf. cahier des charges -- risque de poursuites
    prematurees en l'absence de ce filtrage)."""
    assert case_alpha.status == CaseStatus.SUBMITTED
    client = client_for(dsi_alpha)
    response = client.get(reverse("coordination:case_detail", args=[case_alpha.case_id]))
    assert response.status_code == 404


def test_dsi_cannot_access_national_dashboard(client_for, dsi_alpha):
    """Un utilisateur DSI ne peut pas acceder aux fonctions nationales."""
    client = client_for(dsi_alpha)
    response = client.get(reverse("dashboard:national"))
    assert response.status_code == 403


def test_dsi_cannot_access_audit_log(client_for, dsi_alpha):
    client = client_for(dsi_alpha)
    assert client.get(reverse("audit:list")).status_code == 403


def test_dsi_cannot_publish_advisory(dsi_alpha):
    assert not dsi_alpha.has_capability(Capability.PUBLISH_ADVISORY)


# ---------------------------------------------------------------- roles CSIRT
def test_national_roles_see_all_cases(coordinator, case_alpha, case_beta):
    visible = set(Case.objects.visible_to(coordinator).values_list("case_id", flat=True))
    assert visible == {case_alpha.case_id, case_beta.case_id}


def test_national_dashboard_does_not_identify_organizations_or_cases(
    client_for, coordinator, case_alpha
):
    """Regression : le tableau de bord national se presente comme
    strictement agrege ("aucune information permettant d'identifier une
    infrastructure sensible n'est affichee ici"), mais affichait un
    classement nominatif des organisations et le detail des dossiers en
    depassement (identifiant + titre + organisation)."""
    client = client_for(coordinator)
    response = client.get(reverse("dashboard:national"))
    assert response.status_code == 200
    content = response.content.decode()
    assert case_alpha.organization.name not in content
    assert case_alpha.organization.acronym not in content
    assert case_alpha.case_id not in content
    assert case_alpha.title not in content


def test_analyst_cannot_approve_bounty(analyst):
    assert analyst.has_capability(Capability.PROPOSE_BOUNTY)
    assert not analyst.has_capability(Capability.APPROVE_BOUNTY)


def test_coordinator_can_approve_bounty(coordinator):
    assert coordinator.has_capability(Capability.APPROVE_BOUNTY)


def test_triager_cannot_manage_organizations(triager):
    assert not triager.has_capability(Capability.MANAGE_ALL_ORGANIZATIONS)


# -------------------------------------------------------------- role auditeur
def test_auditor_is_read_only(auditor):
    assert auditor.is_read_only is True
    assert auditor.has_capability(Capability.VIEW_ALL_CASES)
    assert not auditor.has_capability(Capability.CHANGE_CASE_STATUS)


def test_auditor_cannot_post_message(client_for, auditor, case_alpha):
    client = client_for(auditor)
    response = client.post(
        reverse("coordination:post_message", args=[case_alpha.case_id]),
        {"body": "Tentative", "confidentiality": "PARTICIPANTS"},
    )
    assert response.status_code == 403
    assert case_alpha.messages.count() == 0


def test_auditor_can_read_audit_log(client_for, auditor):
    client = client_for(auditor)
    assert client.get(reverse("audit:list")).status_code == 200


# ------------------------------------------------------------- capacites brutes
@pytest.mark.parametrize(
    "role,capability,expected",
    [
        (Role.SECURITY_RESEARCHER, Capability.SUBMIT_REPORT, True),
        (Role.SECURITY_RESEARCHER, Capability.VIEW_ALL_CASES, False),
        (Role.SECURITY_RESEARCHER, Capability.TRIAGE_CASE, False),
        (Role.CSIRT_ANALYST, Capability.TRIAGE_CASE, True),
        (Role.CSIRT_ANALYST, Capability.MANAGE_USERS, False),
        (Role.NATIONAL_COORDINATOR, Capability.PUBLISH_ADVISORY, True),
        (Role.DSI_ADMIN, Capability.VIEW_ALL_CASES, False),
        (Role.DSI_ADMIN, Capability.VIEW_ORG_CASES, True),
        (Role.PUBLIC_USER, Capability.VIEW_ALL_CASES, False),
    ],
)
def test_capability_matrix(db, role, capability, expected):
    from .conftest import make_user

    user = make_user(f"{role.lower()}@matrix.bf", role)
    assert user.has_capability(capability) is expected


def test_inactive_user_has_no_capability(researcher_a):
    researcher_a.is_active = False
    assert researcher_a.has_capability(Capability.SUBMIT_REPORT) is False
