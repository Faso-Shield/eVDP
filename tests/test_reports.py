"""Tests de soumission via le formulaire public et du calcul CVSS."""

import pytest
from django.urls import reverse

from apps.audit.models import AuditAction, AuditLog
from apps.coordination.constants import WorkflowType
from apps.coordination.models import Case
from apps.vulnerabilities.constants import Severity
from apps.vulnerabilities.cvss import CVSSError, base_score, build_vector, evaluate

from .conftest import evidence

pytestmark = pytest.mark.django_db


def form_payload(**overrides):
    payload = {
        "title": "Faille sur le portail de demonstration",
        "product": "Portail demo",
        "affected_organization_name": "Ministere Alpha",
        "vulnerability_type": "XSS",
        "reported_severity": Severity.MEDIUM,
        "description": "Une description assez longue pour passer la validation metier.",
        "steps_to_reproduce": "1. Ouvrir la page\n2. Injecter le payload",
        "impact": "Vol de session utilisateur.",
        "accept_policy": "on",
        "attachments": evidence(),
        "contact_email": "declarant@exemple.bf",
    }
    payload.update(overrides)
    return payload


# ------------------------------------------------------------------ formulaire
def test_public_form_is_reachable(client):
    assert client.get(reverse("reports:submit")).status_code == 200


def test_anonymous_submission_creates_private_case(client, organization):
    response = client.post(reverse("reports:submit"), form_payload(), follow=True)
    assert response.status_code == 200

    case = Case.objects.get()
    assert case.status == "SUBMITTED"
    assert case.is_published is False
    assert case.reporter is None
    assert case.report.reporter_email == "declarant@exemple.bf"
    assert AuditLog.objects.filter(action=AuditAction.REPORT_SUBMITTED).exists()


def test_submission_without_contact_or_anonymity_is_refused(client):
    payload = form_payload()
    payload.pop("contact_email")
    client.post(reverse("reports:submit"), payload)
    assert Case.objects.count() == 0


def test_submission_requires_policy_acceptance(client):
    payload = form_payload()
    payload.pop("accept_policy")
    client.post(reverse("reports:submit"), payload)
    assert Case.objects.count() == 0


def test_short_description_is_refused(client):
    client.post(reverse("reports:submit"), form_payload(description="trop court"))
    assert Case.objects.count() == 0


def test_authenticated_submission_links_reporter(client_for, researcher_a, organization):
    client = client_for(researcher_a)
    payload = form_payload()
    payload.pop("contact_email", None)
    payload["affected_organization"] = str(organization.id)
    client.post(reverse("reports:submit"), payload, follow=True)

    case = Case.objects.get()
    assert case.reporter == researcher_a
    assert case.organization == organization


def test_submission_to_bounty_program_uses_bounty_workflow(
    client_for, bounty_researcher, bounty_program
):
    client = client_for(bounty_researcher)
    payload = form_payload()
    payload.pop("contact_email", None)
    payload["program"] = str(bounty_program.id)
    client.post(reverse("reports:submit"), payload, follow=True)

    case = Case.objects.get()
    assert case.workflow == WorkflowType.BUG_BOUNTY
    assert case.program == bounty_program


def test_submission_to_vdp_program_uses_vdp_workflow(client_for, researcher_a, vdp_program):
    client = client_for(researcher_a)
    payload = form_payload()
    payload.pop("contact_email", None)
    payload["program"] = str(vdp_program.id)
    client.post(reverse("reports:submit"), payload, follow=True)
    assert Case.objects.get().workflow == WorkflowType.VDP


def test_closed_program_refuses_submission(client_for, researcher_a, vdp_program):
    from apps.programs.models import ProgramStatus

    vdp_program.status = ProgramStatus.CLOSED
    vdp_program.save(update_fields=["status"])

    client = client_for(researcher_a)
    payload = form_payload()
    payload.pop("contact_email", None)
    payload["program"] = str(vdp_program.id)
    client.post(reverse("reports:submit"), payload)
    assert Case.objects.count() == 0


def test_pgp_payload_must_be_encrypted_block(client_for, researcher_a):
    client = client_for(researcher_a)
    payload = form_payload()
    payload.pop("contact_email", None)
    payload["pgp_payload"] = "juste du texte"
    client.post(reverse("reports:submit"), payload)
    assert Case.objects.count() == 0


def test_valid_pgp_payload_is_accepted(client_for, researcher_a):
    client = client_for(researcher_a)
    payload = form_payload()
    payload.pop("contact_email", None)
    payload["pgp_payload"] = "-----BEGIN PGP MESSAGE-----\nhQIMA...\n-----END PGP MESSAGE-----"
    client.post(reverse("reports:submit"), payload, follow=True)

    case = Case.objects.get()
    assert case.report.is_pgp_encrypted is True


def test_submission_creates_sla_and_timeline(client, organization):
    client.post(reverse("reports:submit"), form_payload(), follow=True)
    case = Case.objects.get()
    assert case.sla_events.count() == 2
    assert case.timeline.count() == 1


def test_submitted_report_is_not_publicly_listed(client, organization):
    """Principe 2 : un rapport est prive et n'apparait sur aucune page publique."""
    client.post(reverse("reports:submit"), form_payload(), follow=True)
    case = Case.objects.get()

    for url in ["/", "/advisories/", "/programs/", "/researchers/"]:
        assert case.case_id not in client.get(url).content.decode()


# ----------------------------------------------------------------------- CVSS
@pytest.mark.parametrize(
    "vector,expected",
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5),
        ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L", 3.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    ],
)
def test_cvss_base_score(vector, expected):
    assert base_score(vector) == expected


@pytest.mark.parametrize(
    "vector,severity",
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", Severity.CRITICAL),
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", Severity.MEDIUM),
        ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L", Severity.LOW),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", Severity.INFO),
    ],
)
def test_cvss_severity_mapping(vector, severity):
    _score, computed = evaluate(vector)
    assert computed == severity


def test_cvss_v30_is_accepted():
    assert base_score("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8


@pytest.mark.parametrize(
    "vector,expected",
    [
        # Valeurs du calculateur de reference FIRST CVSS v4.0.
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.3),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 10.0),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", 0.0),
        ("CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 8.5),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N", 5.3),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U", 8.1),
    ],
)
def test_cvss_v4_base_score(vector, expected):
    assert base_score(vector) == expected


def test_cvss_v4_severity_mapping():
    _score, severity = evaluate(
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    )
    assert severity == Severity.CRITICAL


def test_cvss_v4_missing_metric_is_rejected():
    with pytest.raises(CVSSError, match="manquantes"):
        base_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H")


def test_cvss_v4_unknown_metric_is_rejected():
    with pytest.raises(CVSSError, match="inconnue"):
        base_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/ZZ:X")


def test_cvss_missing_metric_is_rejected():
    with pytest.raises(CVSSError, match="manquantes"):
        base_score("CVSS:3.1/AV:N/AC:L")


def test_cvss_invalid_value_is_rejected():
    with pytest.raises(CVSSError, match="invalide"):
        base_score("CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")


def test_cvss_vector_is_recomputable():
    vector = build_vector(
        {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"}
    )
    assert vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert base_score(vector) == 9.8
