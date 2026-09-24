"""Responsable de l'etape en cours : acces au contenu, notifications, anonymat.

Trois regles ajoutees au workflow v2 :

1. seul le responsable de l'etape en cours d'un dossier (et le declarant,
   pour son propre rapport) accede au contenu du dossier ;
2. a chaque etape, le responsable recoit une notification et un email ;
3. un declarant anonyme n'a aucun canal de reponse : aucune demande de
   complements ne peut lui etre adressee.
"""

import pytest
from django.core import mail
from django.core.exceptions import PermissionDenied
from django.urls import reverse

from apps.accounts.roles import Role
from apps.coordination.constants import Confidentiality
from apps.coordination.services import perform_action, post_message
from apps.coordination.visibility import has_content_access, writable_channels
from apps.coordination.workflow import (
    MAIN_PATH,
    CaseStatus,
    TransitionNotAllowed,
    current_owner_ids,
    reporter_can_reply,
)
from apps.notifications.models import Notification, NotificationKind

from .conftest import advance, build_report, make_user, submit, workflow_actor

pytestmark = pytest.mark.django_db


def _detail(client, case):
    return client.get(reverse("coordination:case_detail", args=[case.case_id]))


# ------------------------------------------------------ acces au contenu
def test_only_the_step_owner_reads_the_report(
    client_for, triager, analyst, coordinator, auditor, case_alpha
):
    """Etape 1 : l'agent de triage lit le rapport.

    L'analyste, dont l'etape n'est pas venue, ne voit meme pas le dossier ;
    coordinateur et auditeur (vue nationale) n'en lisent que les metadonnees.
    """
    body = "Description suffisamment longue"
    assert body in _detail(client_for(triager), case_alpha).content.decode()
    assert _detail(client_for(analyst), case_alpha).status_code == 404
    for other in (coordinator, auditor):
        response = _detail(client_for(other), case_alpha)
        assert response.status_code == 200  # le dossier reste reperable
        content = response.content.decode()
        assert body not in content
        assert "Contenu réservé au responsable" in content


def test_content_follows_the_current_step(triager, analyst, coordinator, case_alpha):
    advance(case_alpha, CaseStatus.IN_ANALYSIS)
    assert has_content_access(case_alpha, analyst)
    assert not has_content_access(case_alpha, triager)

    advance(case_alpha, CaseStatus.VALIDATION_PENDING)
    assert has_content_access(case_alpha, coordinator)
    assert not has_content_access(case_alpha, analyst)


def test_reporter_always_reads_his_own_report(researcher_a, case_alpha):
    for status in (CaseStatus.IN_ANALYSIS, CaseStatus.VENDOR_NOTIFIED, CaseStatus.CLOSED):
        advance(case_alpha, status)
        assert has_content_access(case_alpha, researcher_a)


def test_organization_reads_only_during_its_own_steps(dsi_alpha, case_alpha):
    advance(case_alpha, CaseStatus.VENDOR_NOTIFIED)
    assert has_content_access(case_alpha, dsi_alpha)
    advance(case_alpha, CaseStatus.FIX_AVAILABLE)
    assert case_alpha.is_visible_to(dsi_alpha)
    assert not has_content_access(case_alpha, dsi_alpha)


def test_closed_case_content_is_closed_to_staff(analyst, coordinator, auditor, case_alpha):
    advance(case_alpha, CaseStatus.CLOSED)
    assert current_owner_ids(case_alpha) == set()
    for user in (analyst, coordinator, auditor):
        assert not has_content_access(case_alpha, user)


def test_assigned_analyst_is_the_only_owner(analyst, coordinator, case_alpha):
    from apps.coordination.services import assign_case

    other = make_user("analyste-b@test.bf", Role.CSIRT_ANALYST)
    advance(case_alpha, CaseStatus.IN_ANALYSIS)
    assign_case(case_alpha, analyst, coordinator)

    assert has_content_access(case_alpha, analyst)
    assert not has_content_access(case_alpha, other)
    assert not case_alpha.is_visible_to(other)
    with pytest.raises(TransitionNotAllowed):
        perform_action(case_alpha, "submit_qualification", other)


def test_non_owner_cannot_take_an_exception_action(analyst, case_alpha):
    """Etape 1 : l'analyste n'est pas responsable, il ne propose pas de rejet."""
    with pytest.raises(TransitionNotAllowed):
        perform_action(
            case_alpha, "propose_rejection", analyst, data={"comment": "Hors sujet"}
        )


def test_non_owner_cannot_post_or_upload(client_for, analyst, case_alpha):
    with pytest.raises(PermissionDenied):
        post_message(case_alpha, analyst, "Bonjour", confidentiality=Confidentiality.INTERNAL)
    response = client_for(analyst).post(
        reverse("coordination:upload_attachment", args=[case_alpha.case_id]), {}
    )
    assert response.status_code == 404  # hors perimetre a cette etape


def test_non_owner_gets_no_pdf_export(client_for, analyst, case_alpha):
    response = client_for(analyst).get(
        reverse("dashboard:export_case_pdf", args=[case_alpha.case_id])
    )
    assert response.status_code == 404


def test_api_hides_the_report_from_a_non_owner(
    client_for, analyst, coordinator, triager, case_alpha
):
    url = f"/api/v1/reports/{case_alpha.case_id}/"
    assert client_for(analyst).get(url).status_code == 404
    report = client_for(coordinator).get(url).json()["report"]
    assert "description" not in report
    report = client_for(triager).get(url).json()["report"]
    assert report["description"].startswith("Description")


# ------------------------------------------------ notification et email
def _action_required(user):
    return Notification.objects.filter(recipient=user, kind=NotificationKind.ACTION_REQUIRED)


def test_submission_notifies_only_the_triage(researcher_a, organization, vdp_program):
    triager = workflow_actor("triager")
    analyst = workflow_actor("analyst")
    coordinator = workflow_actor("coordinator")
    mail.outbox.clear()

    case = submit(build_report(researcher_a, organization, vdp_program), reporter=researcher_a)

    assert _action_required(triager).filter(case=case).exists()
    assert not _action_required(analyst).exists()
    assert not _action_required(coordinator).exists()
    assert triager.email in [address for message in mail.outbox for address in message.to]


@pytest.fixture
def second_owners(organization):
    """Un second compte par role : l'auteur d'une action n'est jamais avise de
    sa propre action, ses collegues responsables de l'etape suivante si."""
    from apps.organizations.models import MembershipRole, OrganizationMember

    users = [
        make_user("triage-2@test.bf", Role.TRIAGER),
        make_user("analyste-2@test.bf", Role.CSIRT_ANALYST),
        make_user("coordinateur-2@test.bf", Role.NATIONAL_COORDINATOR),
        make_user("dsi-2@test.bf", Role.DSI_ADMIN),
    ]
    OrganizationMember.objects.create(
        organization=organization, user=users[-1], membership_role=MembershipRole.DSI
    )
    return users


@pytest.mark.parametrize("target", MAIN_PATH[1:-1])
def test_each_step_notifies_and_emails_its_owner(case_alpha, second_owners, target):
    """A chaque etape franchie, le responsable de la suivante est avise."""
    advance(case_alpha, MAIN_PATH[MAIN_PATH.index(target) - 1])
    Notification.objects.all().delete()
    mail.outbox.clear()

    advance(case_alpha, target)

    actor_id = case_alpha.status_history.order_by("-created_at").first().actor_id
    owners = current_owner_ids(case_alpha) - {actor_id}
    assert owners, f"aucun responsable a l'etape {target}"
    notified = set(
        Notification.objects.filter(
            case=case_alpha, kind=NotificationKind.ACTION_REQUIRED
        ).values_list("recipient_id", flat=True)
    )
    assert owners <= notified
    from apps.accounts.models import User

    emails = {address for message in mail.outbox for address in message.to}
    for owner in User.objects.filter(pk__in=owners):
        assert owner.email in emails


def test_bounty_step_notifies_the_analyst(submitted_bounty_case):
    analyst = workflow_actor("analyst")
    advance(submitted_bounty_case, CaseStatus.VALIDATION_PENDING)
    Notification.objects.all().delete()

    advance(submitted_bounty_case, CaseStatus.VALIDATED)

    notification = _action_required(analyst).filter(case=submitted_bounty_case)
    assert notification.filter(title__contains="Proposer la prime").exists()


# ---------------------------------------------------------- declarant anonyme
@pytest.fixture
def anonymous_case(organization, vdp_program, sla_policy):
    vdp_program.allows_anonymous_reports = True
    vdp_program.save(update_fields=["allows_anonymous_reports"])
    report = build_report(None, organization, vdp_program, is_anonymous=True)
    return submit(report)


def test_anonymous_reporter_cannot_reply(anonymous_case):
    assert not reporter_can_reply(anonymous_case)


def test_no_information_request_to_an_anonymous_reporter(anonymous_case):
    triager = workflow_actor("triager")
    advance(anonymous_case, CaseStatus.ACKNOWLEDGED)
    with pytest.raises(TransitionNotAllowed) as excinfo:
        perform_action(
            anonymous_case, "request_information", triager, data={"comment": "Precisez."}
        )
    assert any("anonyme" in item for item in excinfo.value.missing)
    anonymous_case.refresh_from_db()
    assert anonymous_case.status == CaseStatus.ACKNOWLEDGED


def test_researcher_channel_closed_for_an_anonymous_reporter(anonymous_case):
    triager = workflow_actor("triager")
    assert Confidentiality.RESEARCHER not in writable_channels(anonymous_case, triager)
    assert Confidentiality.INTERNAL in writable_channels(anonymous_case, triager)
    with pytest.raises(PermissionDenied):
        post_message(anonymous_case, triager, "Pouvez-vous preciser ?")


def test_case_page_warns_about_the_anonymous_reporter(client_for, anonymous_case):
    content = _detail(client_for(workflow_actor("triager")), anonymous_case).content.decode()
    assert "Déclarant anonyme." in content
    assert "Demander des compléments" not in content


def test_identified_reporter_can_still_be_asked(case_alpha):
    triager = workflow_actor("triager")
    assert reporter_can_reply(case_alpha)
    perform_action(case_alpha, "request_information", triager, data={"comment": "Precisez."})
    case_alpha.refresh_from_db()
    assert case_alpha.status == CaseStatus.NEEDS_INFORMATION
