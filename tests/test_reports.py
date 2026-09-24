"""Tests de soumission via le formulaire public et du calcul CVSS."""

import pytest
from django.urls import reverse

from apps.audit.models import AuditAction, AuditLog
from apps.coordination.constants import SLAKind, WorkflowType
from apps.coordination.models import Case
from apps.reports.models import VulnerabilityReport
from apps.vulnerabilities.constants import Severity
from apps.vulnerabilities.cvss import CVSSError, base_score, build_vector, describe, evaluate

from .conftest import evidence

pytestmark = pytest.mark.django_db


def form_payload(files="default", **overrides):
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
        "contact_email": "declarant@exemple.bf",
    }
    # Workflow v2, etape 0 : au moins une piece jointe a la soumission.
    if files == "default":
        files = [evidence()]
    if files:
        payload["attachments"] = files
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


def test_submission_without_attachment_is_refused(client, organization):
    """La piece jointe est exigee cote serveur, pas seulement par le HTML."""
    response = client.post(reverse("reports:submit"), form_payload(files=None))
    assert response.status_code == 200
    assert Case.objects.count() == 0
    assert VulnerabilityReport.objects.count() == 0
    assert "pièce jointe est obligatoire" in response.content.decode()


def test_invalid_attachment_refuses_the_whole_submission(client, organization):
    files = [evidence(), evidence("outil.exe", b"MZ\x90\x00binaire")]
    client.post(reverse("reports:submit"), form_payload(files=files))
    assert Case.objects.count() == 0
    assert VulnerabilityReport.objects.count() == 0


def test_attachment_is_stored_with_the_case(client, organization):
    client.post(reverse("reports:submit"), form_payload(), follow=True)
    case = Case.objects.get()
    attachment = case.attachments.get()
    assert attachment.original_filename == "preuve.txt"
    assert attachment.report_id == case.report_id


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
    # La branche prime ne s'ouvre qu'a la validation (etape 4).
    assert case.bounty_stage == ""


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
    """Seule l'echeance de l'etape 1 (accuse de reception, 72 h) est ouverte."""
    client.post(reverse("reports:submit"), form_payload(), follow=True)
    case = Case.objects.get()
    assert list(case.sla_events.values_list("kind", flat=True)) == [SLAKind.ACKNOWLEDGEMENT]
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


# CVSS v4.0 : exige par SPEC-eVDP-2026-V2. Scores de reference du
# calculateur FIRST.
@pytest.mark.parametrize(
    "vector,expected,severity",
    [
        (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            9.3,
            Severity.CRITICAL,
        ),
        (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
            7.1,
            Severity.HIGH,
        ),
        ("CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N", 1.0, Severity.LOW),
    ],
)
def test_cvss_v4_is_scored(vector, expected, severity):
    assert base_score(vector) == expected
    assert evaluate(vector) == (expected, severity)


def test_cvss_v4_incomplete_vector_is_rejected():
    with pytest.raises(CVSSError, match="v4.0"):
        base_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H")


def test_cvss_v4_is_described_for_the_interface():
    metrics = describe("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
    assert [metric["code"] for metric in metrics][:5] == ["AV", "AC", "AT", "PR", "UI"]
    assert len(metrics) == 11
    assert metrics[4]["value_label"] == "Passive"


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
