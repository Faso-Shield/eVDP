"""Tests RBAC : isolation stricte des donnees et des capacites."""

import pytest
from django.urls import reverse

from apps.accounts.roles import Capability, Role
from apps.coordination.models import Case

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


# ------------------------------------------------------- isolation organisation
def test_organization_cannot_access_other_organization_case(client_for, dsi_beta, case_alpha):
    """Une organisation A ne peut pas acceder aux vulnerabilites de B."""
    client = client_for(dsi_beta)
    response = client.get(reverse("coordination:case_detail", args=[case_alpha.case_id]))
    assert response.status_code == 404


def test_organization_accesses_own_case(client_for, dsi_alpha, case_alpha):
    client = client_for(dsi_alpha)
    response = client.get(reverse("coordination:case_detail", args=[case_alpha.case_id]))
    assert response.status_code == 200


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


# ----------------------------------------- vues de gestion ouvertes par oubli
# Les deux ne portaient que @login_required alors qu'elles servent des ecrans
# de traitement. Le menu lateral les reserve deja ; la vue doit refuser de
# meme, sans quoi l'URL saisie a la main suffirait.
def test_a_reporter_cannot_open_the_triage_board(client_for, researcher_a):
    assert client_for(researcher_a).get(reverse("coordination:kanban")).status_code == 403


def test_a_reporter_cannot_open_the_program_management_list(client_for, researcher_a):
    assert client_for(researcher_a).get(reverse("programs:my_programs")).status_code == 403


def test_an_auditor_keeps_the_triage_board_but_loses_program_management(client_for, auditor):
    """L'auditeur voit tout et n'administre rien : la nuance porte ici.

    National, il recevait jusqu'ici la liste de tous les programmes du pays
    dans un ecran d'administration. L'annuaire public lui reste ouvert.
    """
    client = client_for(auditor)
    assert client.get(reverse("coordination:kanban")).status_code == 200
    assert client.get(reverse("programs:my_programs")).status_code == 403
    assert client.get(reverse("programs:list")).status_code == 200


def test_the_staff_roles_keep_both(client_for, analyst, dsi_alpha):
    for utilisateur in (analyst, dsi_alpha):
        client = client_for(utilisateur)
        assert client.get(reverse("coordination:kanban")).status_code == 200
        assert client.get(reverse("programs:my_programs")).status_code == 200


def test_the_refusal_is_audited(client_for, researcher_a):
    """Un refus doit laisser une trace : c'est la regle du depot."""
    from apps.audit.models import AuditAction, AuditLog

    client_for(researcher_a).get(reverse("coordination:kanban"))
    assert AuditLog.objects.filter(
        action=AuditAction.PERMISSION_DENIED, actor=researcher_a
    ).exists()
