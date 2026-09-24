"""Prise en charge obligatoire avant toute action, et rappel des dossiers pris.

Un compte metier n'agit sur un dossier (bouton du workflow, message,
qualification, piece jointe) qu'apres l'avoir pris en charge. Les dossiers
pris en charge qui attendent encore son action sont listes (« Mes prises en
charge »), signales sur le tableau de bord, et rappeles par notification et
email s'ils restent sans action.
"""

import json
from datetime import timedelta

import pytest
from django.core import mail
from django.core.exceptions import PermissionDenied
from django.urls import reverse
from django.utils import timezone

from apps.audit.models import AuditAction
from apps.audit.services import log_action
from apps.coordination.constants import Confidentiality
from apps.coordination.services import (
    my_claims,
    perform_action,
    post_message,
    remind_idle_claims,
    set_severity,
)
from apps.coordination.workflow import (
    CLAIM_REQUIRED_MESSAGE,
    CaseStatus,
    TransitionNotAllowed,
    has_claim,
)
from apps.notifications.models import Notification, NotificationKind

from .conftest import act, advance, claim, evidence

pytestmark = pytest.mark.django_db


def _opened(case, user):
    log_action(AuditAction.CASE_VIEWED, actor=user, obj=case)


def _page(client, case):
    return client.get(
        reverse("coordination:case_detail", args=[case.case_id])
    ).content.decode()


# ----------------------------------------------------- action sans prise en charge
def test_engine_refuses_an_action_before_the_claim(case_alpha, triager):
    _opened(case_alpha, triager)
    with pytest.raises(TransitionNotAllowed) as excinfo:
        perform_action(case_alpha, "acknowledge", triager)
    assert CLAIM_REQUIRED_MESSAGE in excinfo.value.missing
    case_alpha.refresh_from_db()
    assert case_alpha.status == CaseStatus.SUBMITTED

    claim(case_alpha, triager)
    perform_action(case_alpha, "acknowledge", triager)
    assert case_alpha.status == CaseStatus.ACKNOWLEDGED


def test_button_is_greyed_until_the_claim(client_for, case_alpha, triager):
    client = client_for(triager)
    _opened(case_alpha, triager)
    content = _page(client, case_alpha)
    assert "Prenez d&#x27;abord le dossier en charge" in content or (
        "Prenez d'abord le dossier en charge" in content
    )
    assert "Prendre en charge" in content

    client.post(reverse("coordination:claim", args=[case_alpha.case_id]))
    content = _page(client, case_alpha)
    assert "Vous avez pris ce dossier en charge" in content


def test_web_action_is_refused_before_the_claim(client_for, case_alpha, triager):
    client = client_for(triager)
    _opened(case_alpha, triager)
    url = reverse("coordination:workflow_action", args=[case_alpha.case_id, "acknowledge"])
    client.post(url, {"comment": ""})
    case_alpha.refresh_from_db()
    assert case_alpha.status == CaseStatus.SUBMITTED

    client.post(reverse("coordination:claim", args=[case_alpha.case_id]))
    client.post(url, {"comment": ""})
    case_alpha.refresh_from_db()
    assert case_alpha.status == CaseStatus.ACKNOWLEDGED


def test_api_action_lists_the_missing_claim(client_for, case_alpha, triager):
    _opened(case_alpha, triager)
    url = f"/api/v1/reports/{case_alpha.case_id}/actions/"
    client = client_for(triager)
    payload = json.dumps({"action": "acknowledge"})

    response = client.post(url, data=payload, content_type="application/json")
    assert response.status_code == 400
    assert CLAIM_REQUIRED_MESSAGE in response.json()["missing"]

    claim(case_alpha, triager)
    response = client.post(url, data=payload, content_type="application/json")
    assert response.status_code == 200


def test_message_requires_the_claim(case_alpha, triager):
    with pytest.raises(PermissionDenied):
        post_message(case_alpha, triager, "Note", confidentiality=Confidentiality.INTERNAL)
    claim(case_alpha, triager)
    post_message(case_alpha, triager, "Note", confidentiality=Confidentiality.INTERNAL)
    assert case_alpha.messages.filter(body="Note").exists()


def test_qualification_requires_the_claim(case_alpha, analyst):
    advance(case_alpha, CaseStatus.IN_ANALYSIS)
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    with pytest.raises(PermissionDenied):
        set_severity(case_alpha, analyst, cvss_vector=vector)
    claim(case_alpha, analyst)
    set_severity(case_alpha, analyst, cvss_vector=vector)
    case_alpha.refresh_from_db()
    assert case_alpha.cvss_vector == vector


def test_upload_requires_the_claim(client_for, case_alpha, triager):
    client = client_for(triager)
    url = reverse("coordination:upload_attachment", args=[case_alpha.case_id])
    before = case_alpha.attachments.count()

    client.post(url, {"file": evidence("note.txt")})
    assert case_alpha.attachments.count() == before

    claim(case_alpha, triager)
    client.post(url, {"file": evidence("note.txt")})
    assert case_alpha.attachments.count() == before + 1


def test_reporter_never_needs_to_claim(case_alpha, triager, researcher_a):
    """Le declarant repond a une demande de complements sans prise en charge."""
    act(case_alpha, "request_information", triager, data={"comment": "Precisez."})
    assert not has_claim(case_alpha, researcher_a)
    perform_action(case_alpha, "send_information", researcher_a, data={"comment": "Voici."})
    case_alpha.refresh_from_db()
    assert case_alpha.status == CaseStatus.SUBMITTED


# ---------------------------------------------------- mes prises en charge
def test_claimed_case_is_listed_as_idle(case_alpha, triager):
    claim(case_alpha, triager)
    entries = my_claims(triager)
    assert [entry["case"] for entry in entries] == [case_alpha]
    assert entries[0]["idle"] is True
    assert entries[0]["action"].key == "acknowledge"


def test_a_message_takes_the_case_out_of_idle(case_alpha, triager):
    claim(case_alpha, triager)
    post_message(
        case_alpha, triager, "Premiere lecture", confidentiality=Confidentiality.INTERNAL
    )
    assert my_claims(triager)[0]["idle"] is False


def test_a_new_step_of_the_same_role_is_idle_again(case_alpha, triager):
    """Arrive a l'etape suivante du meme role, le dossier attend de nouveau."""
    _opened(case_alpha, triager)
    act(case_alpha, "acknowledge", triager)
    entries = my_claims(triager)
    assert [entry["case"] for entry in entries] == [case_alpha]
    assert entries[0]["action"].key == "declare_admissible"
    assert entries[0]["idle"] is True


def test_case_leaves_the_list_when_the_step_goes_to_another_role(case_alpha, triager):
    _opened(case_alpha, triager)
    act(case_alpha, "acknowledge", triager)
    act(
        case_alpha,
        "declare_admissible",
        triager,
        data={"in_scope": True, "organization_identified": True, "attachment_readable": True},
    )
    assert case_alpha.status == CaseStatus.IN_ANALYSIS
    assert my_claims(triager) == []


def test_my_claims_page_and_menu_counter(client_for, case_alpha, triager):
    claim(case_alpha, triager)
    client = client_for(triager)
    content = client.get(reverse("coordination:my_claims")).content.decode()
    assert case_alpha.case_id in content
    assert "Sans action" in content
    assert "Mes prises en charge (1)" in content


def test_dashboard_banner_reminds_the_claims(client_for, case_alpha, triager):
    claim(case_alpha, triager)
    content = client_for(triager).get(reverse("dashboard:csirt")).content.decode()
    assert "pris en charge attendent votre action" in content
    assert reverse("coordination:my_claims") in content


def test_no_banner_without_claim(client_for, case_alpha, triager):
    content = client_for(triager).get(reverse("dashboard:csirt")).content.decode()
    assert "pris en charge attendent votre action" not in content


# ------------------------------------------------------------------ rappel
def _reminders(user):
    return Notification.objects.filter(recipient=user, kind=NotificationKind.CLAIM_REMINDER)


def _waiting_for(case, user, hours):
    """Recule la prise en charge (et l'arrivee a l'etape) de `hours` heures."""
    from apps.coordination.models import CaseAssignment, CaseStatusHistory

    past = timezone.now() - timedelta(hours=hours)
    CaseAssignment.objects.filter(case=case, user=user, is_active=True).update(created_at=past)
    CaseStatusHistory.objects.filter(case=case).update(created_at=past)


def test_idle_claim_is_reminded_after_48_hours(case_alpha, triager):
    claim(case_alpha, triager)
    _waiting_for(case_alpha, triager, 49)
    mail.outbox.clear()

    assert remind_idle_claims() == 1
    assert _reminders(triager).filter(case=case_alpha).exists()
    assert triager.email in [address for message in mail.outbox for address in message.to]


def test_no_reminder_before_48_hours(case_alpha, triager):
    claim(case_alpha, triager)
    _waiting_for(case_alpha, triager, 47)
    assert remind_idle_claims() == 0
    assert not _reminders(triager).exists()


def test_reminder_is_sent_once_a_day(case_alpha, triager):
    claim(case_alpha, triager)
    _waiting_for(case_alpha, triager, 49)
    assert remind_idle_claims() == 1
    assert remind_idle_claims() == 0
    assert _reminders(triager).count() == 1


def test_no_reminder_once_the_holder_acted(case_alpha, triager):
    claim(case_alpha, triager)
    _waiting_for(case_alpha, triager, 49)
    post_message(case_alpha, triager, "En cours", confidentiality=Confidentiality.INTERNAL)
    assert remind_idle_claims() == 0
    assert not _reminders(triager).exists()


def test_reminder_honours_the_now_parameter(case_alpha, triager):
    claim(case_alpha, triager)
    assert remind_idle_claims(now=timezone.now() + timedelta(hours=49)) == 1


def test_reminder_task_runs(case_alpha, triager):
    from apps.coordination.tasks import remind_claims

    claim(case_alpha, triager)
    assert remind_claims() == 0  # prise en charge trop recente
