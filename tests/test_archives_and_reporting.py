"""Archives des dossiers termines et signalement reserve aux chercheurs.

Archives : un dossier clos, rejete ou doublon n'a plus de responsable
d'etape. Il reste consultable en lecture seule : contenu compris pour le
Coordinateur et, pour les dossiers clos de son organisation, pour la DSI ;
en metadonnees pour l'agent de triage et l'analyste (recherche de doublons).

Signalement : seuls un compte chercheur (chercheur, chercheur Bug Bounty)
ou un signaleur anonyme declarent une vulnerabilite ; un compte metier
traite les signalements, il n'en emet pas.
"""

import pytest
from django.core.exceptions import PermissionDenied
from django.urls import reverse

from apps.accounts.roles import Role
from apps.coordination.constants import Confidentiality
from apps.coordination.models import Case
from apps.coordination.services import post_message
from apps.coordination.visibility import has_content_access, readable_channels
from apps.coordination.workflow import CaseStatus, archive_access, must_claim
from apps.reports.models import VulnerabilityReport
from apps.reports.services import submit_report

from .conftest import act, advance, build_report, evidence, make_user, submit, workflow_actor

pytestmark = pytest.mark.django_db


@pytest.fixture
def closed_case(case_alpha):
    return advance(case_alpha, CaseStatus.CLOSED)


@pytest.fixture
def rejected_case(case_alpha):
    triager = workflow_actor("triager")
    act(case_alpha, "propose_rejection", triager, data={"comment": "Hors perimetre."})
    act(
        case_alpha,
        "confirm_rejection",
        workflow_actor("coordinator"),
        data={"comment": "Rejet confirme."},
    )
    case_alpha.refresh_from_db()
    assert case_alpha.status == CaseStatus.REJECTED
    return case_alpha


def _page(client, case):
    return client.get(reverse("coordination:case_detail", args=[case.case_id]))


# ------------------------------------------------------------------- archives
def test_coordinator_reads_closed_cases(client_for, coordinator, closed_case):
    assert archive_access(closed_case, coordinator) == "content"
    assert closed_case in Case.objects.visible_to(coordinator)
    assert has_content_access(closed_case, coordinator)
    content = _page(client_for(coordinator), closed_case).content.decode()
    assert "Dossier archivé" in content
    assert "Description suffisamment longue" in content


def test_coordinator_reads_rejected_cases(coordinator, rejected_case):
    assert rejected_case in Case.objects.visible_to(coordinator)
    assert has_content_access(rejected_case, coordinator)


@pytest.mark.parametrize("fixture_name", ["triager", "analyst"])
def test_csirt_finds_archives_as_metadata(request, client_for, closed_case, fixture_name):
    user = request.getfixturevalue(fixture_name)
    assert archive_access(closed_case, user) == "metadata"
    assert closed_case in Case.objects.visible_to(user)
    assert not has_content_access(closed_case, user)
    content = _page(client_for(user), closed_case).content.decode()
    assert "seules ses métadonnées" in content
    assert "Description suffisamment longue" not in content
    attachment = closed_case.attachments.first()
    url = reverse("attachments:download", args=[attachment.id])
    assert client_for(user).get(url).status_code == 404


def test_triager_finds_an_archive_to_mark_a_duplicate(
    triager, closed_case, researcher_b, sla_policy
):
    """Recherche de doublons : le dossier original clos reste reperable."""
    assert closed_case in Case.objects.visible_to(triager).filter(title__icontains="test")


def test_organization_reads_its_own_closed_cases(dsi_alpha, dsi_beta, closed_case):
    assert closed_case in Case.objects.visible_to(dsi_alpha)
    assert has_content_access(closed_case, dsi_alpha)
    assert Confidentiality.ORGANIZATION in readable_channels(closed_case, dsi_alpha)
    assert closed_case not in Case.objects.visible_to(dsi_beta)
    assert not closed_case.is_visible_to(dsi_beta)


def test_organization_never_sees_a_rejected_case(dsi_alpha, rejected_case):
    """Un rejet n'a jamais atteint l'organisation : il ne lui est pas archive."""
    assert rejected_case not in Case.objects.visible_to(dsi_alpha)


def test_archives_are_read_only(client_for, coordinator, closed_case):
    assert must_claim(closed_case, coordinator)
    with pytest.raises(PermissionDenied):
        post_message(
            closed_case, coordinator, "Note", confidentiality=Confidentiality.RESEARCHER
        )
    content = _page(client_for(coordinator), closed_case).content.decode()
    assert "Prendre en charge" not in content
    assert "Publier le message" not in content


def test_auditor_is_unchanged(auditor, closed_case):
    assert archive_access(closed_case, auditor) is None
    assert closed_case in Case.objects.visible_to(auditor)
    assert not has_content_access(closed_case, auditor)


def test_open_cases_stay_step_scoped(coordinator, case_alpha):
    """Les archives n'ouvrent que les dossiers termines."""
    assert archive_access(case_alpha, coordinator) is None
    assert case_alpha not in Case.objects.visible_to(coordinator)


# ------------------------------------------------ signalement reserve
BUSINESS = [
    Role.TRIAGER,
    Role.CSIRT_ANALYST,
    Role.NATIONAL_COORDINATOR,
    Role.DSI_ADMIN,
    Role.ORGANIZATION_MANAGER,
    Role.AUDITOR,
]


@pytest.mark.parametrize("role", BUSINESS)
def test_business_account_cannot_report(role, organization, sla_policy):
    user = make_user(f"metier-{role.lower()}@test.bf", role)
    with pytest.raises(PermissionDenied):
        submit(build_report(user, organization), reporter=user)
    assert not VulnerabilityReport.objects.exists()


def test_super_admin_cannot_report(organization, sla_policy):
    from apps.accounts.models import User

    root = User.objects.create_superuser(email="root@test.bf", password="Xx-123456789!")
    with pytest.raises(PermissionDenied):
        submit(build_report(root, organization), reporter=root)


@pytest.mark.parametrize("role", [Role.SECURITY_RESEARCHER, Role.BUG_BOUNTY_RESEARCHER])
def test_researchers_still_report(role, organization, vdp_program):
    user = make_user(f"chercheur-{role.lower()}@test.bf", role)
    case = submit(build_report(user, organization, vdp_program), reporter=user)
    assert case.reporter == user


def test_anonymous_reporter_still_reports(organization, vdp_program):
    vdp_program.allows_anonymous_reports = True
    vdp_program.save(update_fields=["allows_anonymous_reports"])
    case = submit(build_report(None, organization, vdp_program, is_anonymous=True))
    assert case.reporter is None


def test_csaf_import_is_not_a_report(analyst, organization):
    """L'import CSAF, geste de l'analyste, reste possible."""
    from apps.vulnerabilities.constants import ReportSource

    report = build_report(analyst, organization, title="Avis importe")
    case = submit_report(report, source=ReportSource.CSAF, reporter=analyst)
    assert case.pk


def test_business_account_sees_no_report_form(client_for, analyst):
    response = client_for(analyst).get(reverse("reports:submit"))
    assert response.status_code == 403
    assert "Signalement réservé aux chercheurs" in response.content.decode()


def test_business_account_cannot_post_the_form(client_for, analyst, organization):
    response = client_for(analyst).post(
        reverse("reports:submit"),
        {"title": "Tentative", "attachments": evidence()},
    )
    assert response.status_code == 403
    assert not VulnerabilityReport.objects.exists()


def test_business_account_refused_by_the_api(client_for, analyst):
    response = client_for(analyst).post(
        "/api/v1/reports/", {"title": "Tentative", "attachments": evidence()}
    )
    assert response.status_code == 403


def test_report_link_hidden_from_business_accounts(client_for, analyst, researcher_a):
    home = reverse("dashboard:home")
    business = client_for(analyst).get(home, follow=True).content.decode()
    researcher = client_for(researcher_a).get(home, follow=True).content.decode()
    submit_url = reverse("reports:submit")
    assert f'href="{submit_url}"' not in business
    assert f'href="{submit_url}"' in researcher


def test_anonymous_visitor_sees_the_report_link(client):
    content = client.get("/").content.decode()
    assert f'href="{reverse("reports:submit")}"' in content
