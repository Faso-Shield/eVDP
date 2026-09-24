"""Tests RBAC : isolation stricte des donnees et des capacites."""

import pytest
from django.urls import reverse

from apps.accounts.models import User
from apps.accounts.roles import Capability, Role
from apps.coordination.models import Case
from apps.coordination.workflow import CaseStatus

from .conftest import advance

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
    """Visible par l'organisation a partir de l'etape 5 seulement."""
    client = client_for(dsi_alpha)
    url = reverse("coordination:case_detail", args=[case_alpha.case_id])
    assert client.get(url).status_code == 404
    advance(case_alpha, CaseStatus.VENDOR_NOTIFIED)
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
    assert not auditor.has_capability(Capability.SET_SEVERITY)
    assert not auditor.has_capability(Capability.ARBITRATE_CASE)


def test_auditor_cannot_post_message(client_for, auditor, case_alpha):
    client = client_for(auditor)
    response = client.post(
        reverse("coordination:post_message", args=[case_alpha.case_id]),
        {"body": "Tentative", "confidentiality": "RESEARCHER"},
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
        (Role.CSIRT_ANALYST, Capability.TRIAGE_CASE, False),
        (Role.CSIRT_ANALYST, Capability.SET_SEVERITY, True),
        (Role.CSIRT_ANALYST, Capability.COORDINATE_VENDOR, True),
        (Role.CSIRT_ANALYST, Capability.DRAFT_ADVISORY, True),
        (Role.CSIRT_ANALYST, Capability.PROPOSE_BOUNTY, True),
        (Role.CSIRT_ANALYST, Capability.VALIDATE_SEVERITY, False),
        (Role.TRIAGER, Capability.TRIAGE_CASE, True),
        (Role.TRIAGER, Capability.REQUEST_INFORMATION, True),
        (Role.TRIAGER, Capability.PROPOSE_REJECTION, True),
        (Role.TRIAGER, Capability.SET_SEVERITY, False),
        (Role.NATIONAL_COORDINATOR, Capability.VALIDATE_SEVERITY, True),
        (Role.NATIONAL_COORDINATOR, Capability.ARBITRATE_CASE, True),
        (Role.NATIONAL_COORDINATOR, Capability.APPROVE_BOUNTY, True),
        (Role.NATIONAL_COORDINATOR, Capability.SET_SEVERITY, False),
        (Role.NATIONAL_COORDINATOR, Capability.DRAFT_ADVISORY, False),
        (Role.NATIONAL_COORDINATOR, Capability.PROPOSE_BOUNTY, False),
        (Role.DSI_ADMIN, Capability.MANAGE_REMEDIATION, True),
        (Role.DSI_ADMIN, Capability.PROPOSE_BOUNTY, False),
        (Role.ORGANIZATION_MANAGER, Capability.MANAGE_REMEDIATION, True),
        (Role.ORGANIZATION_MANAGER, Capability.PROPOSE_BOUNTY, False),
        (Role.SUPER_ADMIN, Capability.MANAGE_USERS, True),
        (Role.SUPER_ADMIN, Capability.MANAGE_PROGRAM, True),
        (Role.SUPER_ADMIN, Capability.VIEW_ALL_CASES, False),
        (Role.SUPER_ADMIN, Capability.PUBLISH_ADVISORY, False),
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


# ------------------------------------------------------------ workflow v2
def test_senior_analyst_gains_validation_only(db):
    from .conftest import make_user

    senior = make_user("senior@matrix.bf", Role.CSIRT_ANALYST, is_senior_analyst=True)
    assert senior.has_capability(Capability.VALIDATE_SEVERITY)
    assert not senior.has_capability(Capability.APPROVE_BOUNTY)


def test_senior_flag_ignored_for_other_roles(db):
    from .conftest import make_user

    user = make_user("triage-senior@matrix.bf", Role.TRIAGER, is_senior_analyst=True)
    assert not user.has_capability(Capability.VALIDATE_SEVERITY)


def test_superuser_has_only_administration_capabilities(db, case_alpha):
    superuser = User.objects.create_superuser(email="root@matrix.bf", password="Xx-123456789!")
    assert superuser.has_capability(Capability.MANAGE_USERS)
    assert not superuser.has_capability(Capability.VIEW_ALL_CASES)
    assert not superuser.has_capability(Capability.PUBLISH_ADVISORY)
    assert not Case.objects.visible_to(superuser).exists()
    assert not case_alpha.is_visible_to(superuser)


def test_participant_organization_does_not_see_case_before_step_5(dsi_alpha, case_alpha):
    """Etre participant ne deroge pas a la regle de l'etape 5."""
    from apps.coordination.services import add_participant

    add_participant(case_alpha, dsi_alpha)
    assert not case_alpha.is_visible_to(dsi_alpha)
    assert not Case.objects.visible_to(dsi_alpha).exists()


def test_organization_sees_case_from_step_5(dsi_alpha, case_alpha):
    advance(case_alpha, CaseStatus.VENDOR_NOTIFIED)
    assert case_alpha.is_visible_to(dsi_alpha)
    assert set(Case.objects.visible_to(dsi_alpha)) == {case_alpha}


# ------------------------------------------ reference de paiement en clair
# Workflow v2 : reservee a qui execute le versement (RECORD_PAYMENT, le
# Coordinateur), sur la fiche de la prime, toujours journalisee. Jamais au
# super admin, qui n'a acces ni aux dossiers ni au Wallet, et jamais sur la
# fiche du dossier.
@pytest.fixture
def super_admin(db):
    from apps.accounts.models import User

    return User.objects.create_superuser(
        email="admin@test.bf", password="x", full_name="Admin Test"
    )


def _give_a_wallet(researcher):
    from django.core.files.uploadedfile import SimpleUploadedFile

    from apps.researchers.models import PayoutMethod, PayoutMethodType
    from apps.researchers.services import (
        add_payout_method,
        attach_id_document,
        get_or_create_payout_profile,
    )

    profile = get_or_create_payout_profile(researcher)
    profile.legal_full_name = "Awa Traore"
    profile.contact_phone = "+22670000000"
    profile.accepted_terms = True
    profile.save()
    attach_id_document(
        profile,
        researcher,
        SimpleUploadedFile("cnib.pdf", b"%PDF-1.4 test", content_type="application/pdf"),
    )
    return add_payout_method(
        profile,
        researcher,
        PayoutMethod(
            method_type=PayoutMethodType.BANK_TRANSFER,
            bank_name="Coris Bank",
            account_holder_name="Awa Traore",
            account_number="BF1234567890123456",
        ),
    )


def _bounty_for(case, analyst):
    from decimal import Decimal

    from apps.bounty.services import propose_bounty

    return propose_bounty(case, analyst, amount=Decimal("1500000"))


def test_coordinator_sees_the_payout_reference_on_the_bounty(
    client_for, coordinator, analyst, bounty_researcher, bounty_case
):
    from apps.audit.models import AuditAction, AuditLog

    _give_a_wallet(bounty_researcher)
    bounty = _bounty_for(bounty_case, analyst)

    content = (
        client_for(coordinator)
        .get(reverse("bounty:detail", args=[bounty.pk]))
        .content.decode()
    )
    assert "BF1234567890123456" in content
    assert "Awa Traore" in content  # nom legal, pas seulement le moyen
    assert AuditLog.objects.filter(
        action=AuditAction.PAYOUT_REFERENCE_VIEWED, actor=coordinator
    ).exists()


def test_analyst_never_sees_the_payout_reference(
    client_for, analyst, bounty_researcher, bounty_case
):
    """L'analyste propose la prime mais n'execute pas le versement."""
    _give_a_wallet(bounty_researcher)
    bounty = _bounty_for(bounty_case, analyst)

    content = (
        client_for(analyst).get(reverse("bounty:detail", args=[bounty.pk])).content.decode()
    )
    assert "BF1234567890123456" not in content


def test_case_page_never_shows_the_payout_reference(
    client_for, coordinator, bounty_researcher, bounty_case
):
    _give_a_wallet(bounty_researcher)
    content = (
        client_for(coordinator)
        .get(reverse("coordination:case_detail", args=[bounty_case.case_id]))
        .content.decode()
    )
    assert "BF1234567890123456" not in content


def test_super_admin_never_reaches_the_payout_reference(
    client_for, super_admin, analyst, bounty_researcher, bounty_case
):
    _give_a_wallet(bounty_researcher)
    bounty = _bounty_for(bounty_case, analyst)
    client = client_for(super_admin)

    assert (
        client.get(reverse("coordination:case_detail", args=[bounty_case.case_id])).status_code
        == 404
    )
    assert client.get(reverse("bounty:detail", args=[bounty.pk])).status_code == 404
