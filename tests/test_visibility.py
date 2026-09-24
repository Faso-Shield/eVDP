"""Matrice de visibilite des donnees d'un dossier (workflow v2).

Une ligne de la matrice par bloc de tests : rapport et pieces jointes,
identite du chercheur, CVSS, notes et canaux, Wallet, advisory, journal
d'audit, statut simplifie du declarant, administration technique.
"""

import pytest
from django.core.exceptions import PermissionDenied
from django.template import Context, Template
from django.urls import reverse

from apps.accounts.models import User
from apps.accounts.roles import Role
from apps.audit.models import AuditAction
from apps.audit.services import log_action
from apps.coordination.constants import Confidentiality
from apps.coordination.services import post_message, visible_messages
from apps.coordination.visibility import (
    case_view,
    pseudonymize,
    readable_channels,
    reporter_label,
    writable_channels,
)
from apps.coordination.workflow import CaseStatus
from apps.researchers.models import IdentityMode

from .conftest import PASSWORD, advance, make_user

pytestmark = pytest.mark.django_db

CVSS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"


@pytest.fixture
def notified_case(case_alpha):
    """Dossier transmis a l'organisation (etape 5) : la DSI y a acces."""
    return advance(case_alpha, CaseStatus.VENDOR_NOTIFIED)


@pytest.fixture
def superuser(db):
    return User.objects.create_superuser(email="root@test.bf", password=PASSWORD)


def _detail(client, case):
    return client.get(reverse("coordination:case_detail", args=[case.case_id]))


# ------------------------------------------------ rapport et pieces jointes
def test_auditor_sees_report_metadata_only(client_for, auditor, case_alpha):
    content = _detail(client_for(auditor), case_alpha).content.decode()
    assert "Description suffisamment longue" not in content
    assert "Contenu réservé au responsable" in content


def test_auditor_cannot_download_attachment(client_for, auditor, case_alpha):
    attachment = case_alpha.attachments.first()
    response = client_for(auditor).get(reverse("attachments:download", args=[attachment.id]))
    assert response.status_code == 404


def test_auditor_cannot_export_case_pdf(client_for, auditor, case_alpha):
    response = client_for(auditor).get(
        reverse("dashboard:export_case_pdf", args=[case_alpha.case_id])
    )
    assert response.status_code == 404


def test_only_the_step_owner_downloads_attachment(client_for, triager, analyst, case_alpha):
    """Etape 1 : l'agent de triage ; etape 3 : l'analyste, plus le triage."""
    attachment = case_alpha.attachments.first()
    url = reverse("attachments:download", args=[attachment.id])
    assert client_for(triager).get(url).status_code == 200
    assert client_for(analyst).get(url).status_code == 404

    advance(case_alpha, CaseStatus.IN_ANALYSIS)
    assert client_for(analyst).get(url).status_code == 200
    assert client_for(triager).get(url).status_code == 404


def test_dsi_reads_report_only_from_step_5(client_for, dsi_alpha, case_alpha):
    client = client_for(dsi_alpha)
    attachment = case_alpha.attachments.first()
    assert _detail(client, case_alpha).status_code == 404
    download = reverse("attachments:download", args=[attachment.id])
    assert client.get(download).status_code == 404

    advance(case_alpha, CaseStatus.VENDOR_NOTIFIED)
    content = _detail(client, case_alpha).content.decode()
    assert "Description suffisamment longue" in content
    assert client.get(download).status_code == 200


def test_other_organization_never_sees_the_case(client_for, dsi_beta, notified_case):
    assert _detail(client_for(dsi_beta), notified_case).status_code == 404


def test_reporter_evidence_is_read_only_in_admin(case_alpha):
    """Aucune voie d'administration ne modifie ni ne supprime une preuve."""
    from django.contrib import admin

    from apps.attachments.models import Attachment

    model_admin = admin.site._registry[Attachment]
    attachment = case_alpha.attachments.first()
    assert not model_admin.has_change_permission(None, attachment)
    assert not model_admin.has_delete_permission(None, attachment)


# ------------------------------------------------------ identite du chercheur
def test_dsi_sees_pseudonym(dsi_alpha, notified_case):
    assert reporter_label(notified_case, dsi_alpha) == "alpha-hunter"


def test_dsi_sees_nothing_for_private_identity(dsi_alpha, notified_case, researcher_a):
    profile = researcher_a.researcher_profile
    profile.identity_mode = IdentityMode.PRIVATE
    profile.save(update_fields=["identity_mode"])
    assert reporter_label(notified_case, dsi_alpha) == "Identité protégée"


def test_dsi_sees_nothing_for_anonymous_report(dsi_alpha, notified_case):
    report = notified_case.report
    report.is_anonymous = True
    report.save(update_fields=["is_anonymous"])
    assert reporter_label(notified_case, dsi_alpha) == "Identité protégée"


def test_auditor_sees_pseudonymized_identity(auditor, case_alpha):
    label = reporter_label(case_alpha, auditor)
    assert label == pseudonymize(case_alpha)
    assert label.startswith("Déclarant #") and len(label) == len("Déclarant #") + 8
    assert "alpha" not in label


def test_csirt_sees_real_identity(analyst, case_alpha):
    assert reporter_label(case_alpha, analyst) == case_alpha.report.reporter_display


# ------------------------------------------------------------------------ CVSS
def test_reporter_sees_no_cvss(client_for, researcher_a, analyst, case_alpha):
    case_alpha.cvss_vector = CVSS
    case_alpha.cvss_score = "8.1"
    case_alpha.save(update_fields=["cvss_vector", "cvss_score"])
    assert case_view(case_alpha, researcher_a)["cvss"] is None
    client = client_for(researcher_a)
    assert CVSS not in _detail(client, case_alpha).content.decode()
    data = client.get(f"/api/v1/reports/{case_alpha.case_id}/").json()
    assert "cvss_vector" not in data and "cvss_score" not in data


def test_dsi_sees_score_without_vector(client_for, dsi_alpha, notified_case):
    client = client_for(dsi_alpha)
    data = client.get(f"/api/v1/reports/{notified_case.case_id}/").json()
    assert "cvss_score" in data
    assert "cvss_vector" not in data
    assert notified_case.cvss_vector not in _detail(client, notified_case).content.decode()


def test_analyst_writes_cvss_and_triager_reads(analyst, triager, case_alpha):
    assert case_view(case_alpha, analyst)["cvss"] == "write"
    assert case_view(case_alpha, triager)["cvss"] == "read"


# ------------------------------------------------------------ notes et canaux
def test_channel_matrix(
    researcher_a, triager, analyst, coordinator, auditor, dsi_alpha, case_alpha
):
    """Seul le responsable de l'etape en cours (et le declarant) lit les canaux."""
    RES = Confidentiality.RESEARCHER
    ORG = Confidentiality.ORGANIZATION
    INT = Confidentiality.INTERNAL

    # Etape 6 : la DSI est responsable (plan de remediation).
    advance(case_alpha, CaseStatus.VENDOR_NOTIFIED)
    assert readable_channels(case_alpha, researcher_a) == {RES}
    assert readable_channels(case_alpha, dsi_alpha) == {ORG}
    for other in (triager, analyst, coordinator, auditor):
        assert readable_channels(case_alpha, other) == set()
        assert writable_channels(case_alpha, other) == []
    assert set(writable_channels(case_alpha, researcher_a)) == {RES}
    assert set(writable_channels(case_alpha, dsi_alpha)) == {ORG}

    # Etape 8 : l'analyste est responsable (confirmer le correctif).
    advance(case_alpha, CaseStatus.FIX_AVAILABLE)
    assert readable_channels(case_alpha, analyst) == {RES, ORG, INT}
    assert set(writable_channels(case_alpha, analyst)) == {RES, ORG, INT}
    for other in (triager, coordinator, auditor, dsi_alpha):
        assert readable_channels(case_alpha, other) == set()


def test_dsi_never_writes_to_researcher(dsi_alpha, notified_case):
    with pytest.raises(PermissionDenied):
        post_message(
            notified_case, dsi_alpha, "Bonjour", confidentiality=Confidentiality.RESEARCHER
        )


def _system_message(case, body, channel):
    """Message depose par la plateforme, quel que soit le responsable d'etape."""
    return post_message(case, None, body, confidentiality=channel, is_system=True)


def test_reporter_never_reads_organization_channel(researcher_a, notified_case):
    _system_message(notified_case, "Canal org", Confidentiality.ORGANIZATION)
    assert "Canal org" not in [m.body for m in visible_messages(notified_case, researcher_a)]


def test_triager_never_reads_organization_channel(triager, notified_case):
    _system_message(notified_case, "Canal org", Confidentiality.ORGANIZATION)
    assert "Canal org" not in [m.body for m in visible_messages(notified_case, triager)]


def test_dsi_never_reads_researcher_channel_or_notes(dsi_alpha, notified_case):
    _system_message(notified_case, "Canal chercheur", Confidentiality.RESEARCHER)
    _system_message(notified_case, "Note interne", Confidentiality.INTERNAL)
    _system_message(notified_case, "Canal org", Confidentiality.ORGANIZATION)
    bodies = [m.body for m in visible_messages(notified_case, dsi_alpha)]
    assert "Canal chercheur" not in bodies
    assert "Note interne" not in bodies
    assert "Canal org" in bodies  # responsable de l'etape 6


def test_auditor_reads_no_channel(auditor, notified_case):
    """L'auditeur n'est jamais responsable d'une etape : aucun contenu."""
    _system_message(notified_case, "Note interne", Confidentiality.INTERNAL)
    _system_message(notified_case, "Canal org", Confidentiality.ORGANIZATION)
    assert list(visible_messages(notified_case, auditor)) == []


# ---------------------------------------------------------------------- Wallet
def test_wallet_visibility(
    bounty_case, bounty_researcher, analyst, coordinator, auditor, triager, researcher_a
):
    from apps.bounty.services import propose_bounty, visible_bounties

    bounty = propose_bounty(bounty_case, analyst)
    assert bounty in visible_bounties(coordinator)
    assert bounty in visible_bounties(analyst)
    assert bounty in visible_bounties(auditor)
    assert bounty in visible_bounties(bounty_researcher)
    assert bounty not in visible_bounties(triager)
    assert bounty not in visible_bounties(researcher_a)


def test_dsi_sees_no_bounty(bounty_case, analyst, triager, organization):
    from apps.bounty.services import propose_bounty, visible_bounties
    from apps.organizations.models import MembershipRole, OrganizationMember

    propose_bounty(bounty_case, analyst)
    dsi = make_user("dsi-bb@test.bf", Role.DSI_ADMIN)
    OrganizationMember.objects.create(
        organization=organization, user=dsi, membership_role=MembershipRole.DSI
    )
    assert not visible_bounties(dsi).exists()
    assert case_view(bounty_case, analyst)["wallet"] == "partial"
    assert case_view(bounty_case, triager)["wallet"] is None


# --------------------------------------------------------------------- advisory
def test_advisory_matrix(
    analyst, coordinator, auditor, triager, researcher_a, dsi_alpha, notified_case
):
    assert case_view(notified_case, analyst)["advisory"] == "write"
    assert case_view(notified_case, coordinator)["advisory"] == "write"
    assert case_view(notified_case, dsi_alpha)["advisory"] == "read"
    assert case_view(notified_case, auditor)["advisory"] == "read"
    assert case_view(notified_case, triager)["advisory"] is None
    assert case_view(notified_case, researcher_a)["advisory"] is None


# -------------------------------------------------------------- journal d'audit
def test_super_admin_audit_hides_case_entries(client_for, superuser, auditor, case_alpha):
    log_action(AuditAction.CASE_VIEWED, actor=auditor, obj=case_alpha)
    admin_page = client_for(superuser).get(reverse("audit:list")).content.decode()
    auditor_page = client_for(auditor).get(reverse("audit:list")).content.decode()
    assert case_alpha.case_id in auditor_page
    assert case_alpha.case_id not in admin_page


def test_dsi_and_triager_have_no_audit_log(client_for, dsi_alpha, triager):
    assert client_for(dsi_alpha).get(reverse("audit:list")).status_code == 403
    assert client_for(triager).get(reverse("audit:list")).status_code == 403


# ---------------------------------------------------- statut simplifie declarant
def _status_tag(case, user):
    template = Template("{% load evdp_tags %}{% case_status case %}")
    return template.render(Context({"case": case, "user": user}))


def test_reporter_sees_simplified_status(researcher_a, analyst, case_alpha):
    assert _status_tag(case_alpha, researcher_a) == "Reçu"
    advance(case_alpha, CaseStatus.VALIDATION_PENDING)
    assert _status_tag(case_alpha, researcher_a) == "En analyse"
    assert _status_tag(case_alpha, analyst) == "Qualification à valider"


def test_reporter_never_sees_pending_rejection(researcher_a, triager, case_alpha):
    from apps.coordination.services import perform_action

    perform_action(
        case_alpha, "propose_rejection", triager, data={"comment": "Hors perimetre"}
    )
    assert case_alpha.status == CaseStatus.REJECTION_PENDING
    assert _status_tag(case_alpha, researcher_a) == "En analyse"


def test_reporter_detail_shows_simplified_label(client_for, researcher_a, case_alpha):
    advance(case_alpha, CaseStatus.VALIDATION_PENDING)
    content = _detail(client_for(researcher_a), case_alpha).content.decode()
    assert "Qualification à valider" not in content
    assert "En analyse" in content


# ------------------------------------------------- administration technique
def test_superuser_sees_no_case(client_for, superuser, case_alpha):
    assert _detail(client_for(superuser), case_alpha).status_code == 404


def test_superuser_admin_has_no_case_content(client_for, superuser, case_alpha):
    client = client_for(superuser)
    for url in (
        "/admin/coordination/case/",
        f"/admin/coordination/case/{case_alpha.pk}/change/",
        "/admin/reports/vulnerabilityreport/",
        "/admin/attachments/attachment/",
    ):
        response = client.get(url)
        assert response.status_code in (302, 403, 404)
        assert case_alpha.case_id.encode() not in response.content
