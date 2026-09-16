"""Tests de soumission via le formulaire public et du calcul CVSS."""

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse

from apps.attachments.models import Attachment
from apps.audit.models import AuditAction, AuditLog
from apps.coordination.constants import WorkflowType
from apps.coordination.models import Case
from apps.vulnerabilities.constants import Severity
from apps.vulnerabilities.cvss import CVSSError, base_score, build_vector, evaluate

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


def test_submission_with_calculator_built_cvss_vector_sets_severity(client, organization):
    """Le calculateur CVSS guide (cote client) construit un vecteur au
    format exact CVSS:3.1/AV:x/AC:x/... : verifie que ce format precis est
    bien accepte et correctement transforme en severite sur le Case."""
    payload = form_payload(cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    response = client.post(reverse("reports:submit"), payload, follow=True)
    assert response.status_code == 200
    case = Case.objects.get()
    assert case.severity == Severity.CRITICAL
    assert float(case.cvss_score) == pytest.approx(9.8, abs=0.05)


def test_anonymous_submission_to_bounty_program_is_refused(client, bounty_program):
    """Un programme Bug Bounty exige une identite : propose_bounty() refuse
    deja tout dossier sans chercheur identifie, mais le formulaire doit le
    dire explicitement avant l'envoi plutot que de laisser echouer plus
    tard une recompense devenue impossible a attribuer."""
    payload = form_payload(program=str(bounty_program.pk), is_anonymous="on")
    payload.pop("contact_email")
    response = client.post(reverse("reports:submit"), payload)
    assert Case.objects.count() == 0
    assert "is_anonymous" in response.context["form"].errors


def test_unauthenticated_non_anonymous_submission_to_bounty_program_is_refused(
    client, bounty_program
):
    """Un email de contact ne suffit pas pour un Bug Bounty : aucune
    recompense, aucun anti-fraude et aucune deduplication ne tiennent sur
    une adresse jetable (norme HackerOne/Bugcrowd/Intigriti/YesWeHack)."""
    payload = form_payload(program=str(bounty_program.pk))
    response = client.post(reverse("reports:submit"), payload)
    assert Case.objects.count() == 0
    assert "program" in response.context["form"].errors


def test_unverified_email_submission_to_bounty_program_is_refused(
    client_for, bounty_researcher, bounty_program
):
    """L'email verifie n'est pas un reglage optionnel par programme pour un
    Bug Bounty : comme le compte, c'est une exigence structurelle du type
    de programme (norme HackerOne/Bugcrowd/Intigriti/YesWeHack), pour rester
    joignable au moment d'attribuer une recompense."""
    bounty_researcher.email_verified = False
    bounty_researcher.save(update_fields=["email_verified"])
    client = client_for(bounty_researcher)
    payload = form_payload(program=str(bounty_program.pk))
    payload.pop("contact_email")
    response = client.post(reverse("reports:submit"), payload)
    assert Case.objects.count() == 0
    assert "program" in response.context["form"].errors


def test_unverified_email_submission_to_vdp_program_is_accepted(
    client_for, researcher_a, vdp_program
):
    """A l'inverse, un VDP ne bloque jamais sur l'email verifie : aucune
    recompense n'est en jeu, la joignabilite pour un paiement ne s'applique
    pas."""
    researcher_a.email_verified = False
    researcher_a.save(update_fields=["email_verified"])
    client = client_for(researcher_a)
    payload = form_payload(program=str(vdp_program.pk))
    payload.pop("contact_email")
    response = client.post(reverse("reports:submit"), payload, follow=True)
    assert response.status_code == 200
    assert Case.objects.count() == 1


def test_no_mfa_submission_to_bounty_program_is_refused(
    client_for, bounty_researcher, bounty_program
):
    """Comme le compte et l'email verifie, le MFA n'est pas optionnel des
    qu'un Bug Bounty est en jeu : un compte a recompenser est une cible de
    prise de controle (norme HackerOne). On ne bloque pas tout le compte du
    chercheur (voir apps.accounts.roles.MFA_REQUIRED_ROLES, reserve aux
    roles internes) : seule la soumission a un Bug Bounty l'exige."""
    bounty_researcher.mfa_enabled = False
    bounty_researcher.save(update_fields=["mfa_enabled"])
    client = client_for(bounty_researcher)
    payload = form_payload(program=str(bounty_program.pk))
    payload.pop("contact_email")
    response = client.post(reverse("reports:submit"), payload)
    assert Case.objects.count() == 0
    assert "program" in response.context["form"].errors


def test_no_mfa_submission_to_vdp_program_is_accepted(client_for, researcher_a, vdp_program):
    """Le MFA reste optionnel pour un chercheur VDP simple : aucune
    recompense n'est en jeu."""
    assert researcher_a.mfa_enabled is False
    client = client_for(researcher_a)
    payload = form_payload(program=str(vdp_program.pk))
    payload.pop("contact_email")
    response = client.post(reverse("reports:submit"), payload, follow=True)
    assert response.status_code == 200
    assert Case.objects.count() == 1
    assert Case.objects.count() == 1


def test_authenticated_submission_to_bounty_program_is_accepted(
    client_for, bounty_researcher, bounty_program
):
    client = client_for(bounty_researcher)
    payload = form_payload(program=str(bounty_program.pk))
    payload.pop("contact_email")
    response = client.post(reverse("reports:submit"), payload, follow=True)
    assert response.status_code == 200
    assert Case.objects.count() == 1


def test_program_disabling_anonymous_reports_is_respected(client, vdp_program):
    """Regression : allows_anonymous_reports etait stocke et affiche
    publiquement mais jamais applique par le formulaire."""
    vdp_program.allows_anonymous_reports = False
    vdp_program.save(update_fields=["allows_anonymous_reports"])
    payload = form_payload(program=str(vdp_program.pk), is_anonymous="on")
    payload.pop("contact_email")
    response = client.post(reverse("reports:submit"), payload)
    assert Case.objects.count() == 0
    assert "is_anonymous" in response.context["form"].errors


def test_program_requiring_verified_email_rejects_anonymous_submission(client, vdp_program):
    vdp_program.requires_verified_email = True
    vdp_program.save(update_fields=["requires_verified_email"])
    payload = form_payload(program=str(vdp_program.pk))
    response = client.post(reverse("reports:submit"), payload)
    assert Case.objects.count() == 0
    assert "program" in response.context["form"].errors


def test_program_requiring_verified_email_accepts_verified_account(
    client_for, researcher_a, vdp_program
):
    researcher_a.email_verified = True
    researcher_a.save(update_fields=["email_verified"])
    vdp_program.requires_verified_email = True
    vdp_program.save(update_fields=["requires_verified_email"])
    client = client_for(researcher_a)
    payload = form_payload(program=str(vdp_program.pk))
    payload.pop("contact_email")
    response = client.post(reverse("reports:submit"), payload, follow=True)
    assert response.status_code == 200
    assert Case.objects.count() == 1


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


def test_truncated_pgp_payload_is_refused(client_for, researcher_a):
    """Regression : un bloc avec l'en-tete mais sans le pied de page (copier-
    coller incomplet, ou bloc corrompu) passait silencieusement avant que
    is_encrypted_blob() ne verifie aussi la fin du bloc. Le CSIRT ne le
    decouvrait qu'en tentant, bien plus tard, un dechiffrement voue a
    l'echec -- reproduit en conditions reelles avant ce correctif."""
    client = client_for(researcher_a)
    payload = form_payload()
    payload.pop("contact_email", None)
    payload["pgp_payload"] = (
        "-----BEGIN PGP MESSAGE-----\nceci n'est pas du tout un vrai bloc PGP, "
        "juste du texte au hasard, sans pied de page, corrompu"
    )
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


def test_cvss_v4_is_rejected_explicitly():
    with pytest.raises(CVSSError, match="v4.0"):
        base_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H")


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


# ------------------------------------------------------- anonymat vs credit
def test_anonymous_submission_forces_wants_credit_to_false(client):
    """Regression : l'interface permettait de cocher a la fois "anonyme" et
    "etre credite publiquement" sans le signaler. credit_for() ignorait deja
    wants_credit en mode anonyme (aucune fuite), mais rien ne garantissait
    que report.wants_credit reste coherent avec is_anonymous en base."""
    payload = form_payload(is_anonymous="on", wants_credit="on")
    payload.pop("contact_email")
    client.post(reverse("reports:submit"), payload, follow=True)

    case = Case.objects.get()
    assert case.report.is_anonymous is True
    assert case.report.wants_credit is False


def test_anonymous_submission_can_still_request_a_cve(client):
    """Un CVE identifie la vulnerabilite, pas son auteur : ca doit rester
    compatible avec un signalement anonyme, contrairement au credit."""
    payload = form_payload(is_anonymous="on", requests_cve="on")
    payload.pop("contact_email")
    client.post(reverse("reports:submit"), payload, follow=True)

    case = Case.objects.get()
    assert case.report.is_anonymous is True
    assert case.report.requests_cve is True


# --------------------------------------------------------- pieces jointes
def _files(count, size=10):
    return [
        SimpleUploadedFile(f"preuve-{i}.txt", b"x" * size, content_type="text/plain")
        for i in range(count)
    ]


def test_excess_attachments_are_dropped_with_a_warning(client, settings):
    settings.EVDP = {**settings.EVDP, "MAX_ATTACHMENTS_PER_SUBMISSION": 3}
    payload = form_payload()
    payload["attachments"] = _files(5)
    response = client.post(reverse("reports:submit"), payload, follow=True)

    assert response.status_code == 200
    case = Case.objects.get()
    assert Attachment.objects.filter(case=case).count() == 3
    warnings = [str(m) for m in response.context["messages"]]
    assert any("3 premiers fichiers" in w for w in warnings)


def test_attachments_within_limit_are_all_stored(client, settings):
    settings.EVDP = {**settings.EVDP, "MAX_ATTACHMENTS_PER_SUBMISSION": 10}
    payload = form_payload()
    payload["attachments"] = _files(4)
    client.post(reverse("reports:submit"), payload, follow=True)

    case = Case.objects.get()
    assert Attachment.objects.filter(case=case).count() == 4
