"""Tests de l'API REST v1."""

import json

import pytest

from apps.accounts.models import ApiKey
from apps.api.authentication import generate_key
from apps.coordination.models import Case
from apps.coordination.workflow import CaseStatus
from apps.programs.models import Program
from apps.reports.models import VulnerabilityReport

from .conftest import advance, evidence

pytestmark = pytest.mark.django_db

REPORT_PAYLOAD = {
    "title": "Vulnerabilite signalee via API",
    "product": "API publique",
    "vulnerability_type": "SSRF",
    "description": "Description suffisamment detaillee pour etre qualifiee correctement.",
    "steps_to_reproduce": "1. Appeler l'endpoint\n2. Observer la requete sortante",
    "impact": "Acces aux services internes.",
    "affected_organization_name": "Ministere Alpha",
}


def post_report(client, payload=None, files="default", **extra):
    """Soumission API en multipart : au moins une piece jointe est exigee."""
    data = dict(payload if payload is not None else REPORT_PAYLOAD)
    if files == "default":
        files = [evidence()]
    if files:
        data["attachments"] = files
    return client.post("/api/v1/reports/", data=data, **extra)


def _mark_opened(case, user):
    """Pre-requis de l'etape 1 : le dossier a ete ouvert au moins une fois."""
    from apps.audit.models import AuditAction
    from apps.audit.services import log_action

    log_action(AuditAction.CASE_VIEWED, actor=user, obj=case)


# ------------------------------------------------------------ acces anonyme
def test_anonymous_cannot_list_reports(client):
    assert client.get("/api/v1/reports/").status_code in (401, 403)


def test_anonymous_cannot_create_report(client):
    response = post_report(client)
    assert response.status_code in (401, 403)
    assert Case.objects.count() == 0


def test_public_endpoints_are_readable(client, vdp_program, organization):
    for url in ["/api/v1/programs/", "/api/v1/advisories/", "/api/v1/organizations/"]:
        assert client.get(url).status_code == 200


def test_schema_is_served(client):
    assert client.get("/api/schema/").status_code == 200


# --------------------------------------------------------------- soumission
def test_researcher_creates_report_and_case(client_for, researcher_a, organization):
    client = client_for(researcher_a)
    response = post_report(client)
    assert response.status_code == 201
    body = response.json()
    assert body["case_id"].startswith("EVDP-")
    case = Case.objects.get(case_id=body["case_id"])
    assert case.reporter == researcher_a
    assert case.status == CaseStatus.SUBMITTED
    # La piece jointe est enregistree et rattachee au dossier.
    assert case.attachments.count() == 1


def test_api_submission_without_attachment_is_refused(client_for, researcher_a):
    """Workflow v2, etape 0 : au moins une piece jointe, controlee cote serveur."""
    client = client_for(researcher_a)
    response = post_report(client, files=None)
    assert response.status_code == 400
    assert "attachments" in response.json()
    # Transaction : aucun rapport orphelin.
    assert Case.objects.count() == 0
    assert VulnerabilityReport.objects.count() == 0


def test_api_json_submission_is_refused_without_attachment(client_for, researcher_a):
    client = client_for(researcher_a)
    response = client.post(
        "/api/v1/reports/", data=json.dumps(REPORT_PAYLOAD), content_type="application/json"
    )
    assert response.status_code == 400
    assert VulnerabilityReport.objects.count() == 0


def test_api_invalid_attachment_refuses_the_whole_submission(client_for, researcher_a):
    client = client_for(researcher_a)
    response = post_report(
        client, files=[evidence(), evidence("outil.exe", b"MZ\x90\x00binaire")]
    )
    assert response.status_code == 400
    assert Case.objects.count() == 0
    assert VulnerabilityReport.objects.count() == 0


def test_api_accepts_several_attachments(client_for, researcher_a):
    client = client_for(researcher_a)
    response = post_report(client, files=[evidence("a.txt"), evidence("b.txt")])
    assert response.status_code == 201
    case = Case.objects.get(case_id=response.json()["case_id"])
    assert case.attachments.count() == 2


def test_api_refuses_more_than_five_attachments(client_for, researcher_a):
    client = client_for(researcher_a)
    response = post_report(client, files=[evidence(f"p{i}.txt") for i in range(6)])
    assert response.status_code == 400
    assert VulnerabilityReport.objects.count() == 0


def test_short_description_is_rejected(client_for, researcher_a):
    client = client_for(researcher_a)
    payload = {**REPORT_PAYLOAD, "description": "trop court"}
    response = post_report(client, payload)
    assert response.status_code == 400
    assert "description" in response.json()


def test_invalid_cvss_vector_is_rejected(client_for, researcher_a):
    client = client_for(researcher_a)
    payload = {**REPORT_PAYLOAD, "cvss_vector": "CVSS:3.1/AV:Z"}
    response = post_report(client, payload)
    assert response.status_code == 400


def test_mass_assignment_of_status_is_ignored(client_for, researcher_a):
    """Un client ne doit pas pouvoir imposer un statut ou une severite retenue."""
    client = client_for(researcher_a)
    payload = {**REPORT_PAYLOAD, "status": "CLOSED", "reporter": "autre"}
    response = post_report(client, payload)
    assert response.status_code == 201
    case = Case.objects.get(case_id=response.json()["case_id"])
    assert case.status == CaseStatus.SUBMITTED
    assert case.reporter == researcher_a


# ---------------------------------------------------------------- isolation
def test_report_list_is_scoped(client_for, researcher_a, case_alpha, case_beta):
    client = client_for(researcher_a)
    results = client.get("/api/v1/reports/").json()["results"]
    identifiers = {row["case_id"] for row in results}
    assert identifiers == {case_alpha.case_id}


def test_report_detail_returns_404_outside_scope(client_for, researcher_a, case_beta):
    client = client_for(researcher_a)
    response = client.get(f"/api/v1/reports/{case_beta.case_id}/")
    assert response.status_code == 404


def test_messages_endpoint_is_scoped(client_for, researcher_a, case_beta):
    client = client_for(researcher_a)
    assert client.get(f"/api/v1/reports/{case_beta.case_id}/messages/").status_code == 404


def test_internal_messages_hidden_from_researcher(
    client_for, case_alpha, triager, researcher_a
):
    from apps.coordination.constants import Confidentiality
    from apps.coordination.services import post_message

    # Etape 1 : l'agent de triage, responsable de l'etape, ecrit.
    post_message(
        case_alpha, triager, "Note interne CSIRT", confidentiality=Confidentiality.INTERNAL
    )
    post_message(case_alpha, triager, "Message au declarant")

    client = client_for(researcher_a)
    bodies = [
        row["body"]
        for row in client.get(f"/api/v1/reports/{case_alpha.case_id}/messages/").json()
    ]
    assert "Note interne CSIRT" not in bodies
    assert "Message au declarant" in bodies


# ------------------------------------------------------------------ ecriture
def test_researcher_cannot_patch_severity(client_for, researcher_a, case_alpha):
    client = client_for(researcher_a)
    response = client.patch(
        f"/api/v1/reports/{case_alpha.case_id}/",
        data=json.dumps({"severity": "CRITICAL"}),
        content_type="application/json",
    )
    assert response.status_code in (403, 404)
    case_alpha.refresh_from_db()
    assert case_alpha.severity != "CRITICAL"


def test_analyst_can_patch_severity(client_for, analyst, case_alpha):
    advance(case_alpha, CaseStatus.IN_ANALYSIS)  # etape 3 : l'analyste est responsable
    client = client_for(analyst)
    response = client.patch(
        f"/api/v1/reports/{case_alpha.case_id}/",
        data=json.dumps({"severity": "HIGH"}),
        content_type="application/json",
    )
    assert response.status_code == 200
    case_alpha.refresh_from_db()
    assert case_alpha.severity == "HIGH"


def test_analyst_cannot_patch_qualification_once_submitted(client_for, analyst, case_alpha):
    """La qualification soumise a validation ne change plus sans renvoi.

    L'etape 4 revient au valideur : le dossier sort meme du perimetre de
    l'analyste (404), qui ne peut donc plus la modifier.
    """
    advance(case_alpha, CaseStatus.VALIDATION_PENDING)
    client = client_for(analyst)
    response = client.patch(
        f"/api/v1/reports/{case_alpha.case_id}/",
        data=json.dumps({"severity": "LOW"}),
        content_type="application/json",
    )
    assert response.status_code == 404
    case_alpha.refresh_from_db()
    assert case_alpha.severity != "LOW"


def test_transition_endpoint_enforces_state_machine(client_for, triager, case_alpha):
    """Meme pour le responsable de l'etape, une transition hors table est refusee."""
    client = client_for(triager)
    response = client.post(
        f"/api/v1/reports/{case_alpha.case_id}/transition/",
        data=json.dumps({"target_status": "CLOSED"}),
        content_type="application/json",
    )
    assert response.status_code == 400
    case_alpha.refresh_from_db()
    assert case_alpha.status == CaseStatus.SUBMITTED


def test_transition_endpoint_applies_valid_transition(client_for, triager, case_alpha):
    """Compatibilite : le statut vise designe le bouton de l'etape."""
    _mark_opened(case_alpha, triager)
    client = client_for(triager)
    response = client.post(
        f"/api/v1/reports/{case_alpha.case_id}/transition/",
        data=json.dumps({"target_status": "ACKNOWLEDGED"}),
        content_type="application/json",
    )
    assert response.status_code == 200
    case_alpha.refresh_from_db()
    assert case_alpha.status == CaseStatus.ACKNOWLEDGED


def test_transition_endpoint_refuses_wrong_owner(client_for, coordinator, case_alpha):
    """Un bouton, un role : le coordinateur n'accuse pas reception.

    Hors de son etape, le dossier n'est meme pas dans son perimetre (404).
    """
    _mark_opened(case_alpha, coordinator)
    client = client_for(coordinator)
    response = client.post(
        f"/api/v1/reports/{case_alpha.case_id}/transition/",
        data=json.dumps({"target_status": "ACKNOWLEDGED"}),
        content_type="application/json",
    )
    assert response.status_code == 404
    case_alpha.refresh_from_db()
    assert case_alpha.status == CaseStatus.SUBMITTED


# ------------------------------------------------------ actions de workflow v2
def test_actions_endpoint_applies_the_step(client_for, triager, case_alpha):
    _mark_opened(case_alpha, triager)
    client = client_for(triager)
    response = client.post(
        f"/api/v1/reports/{case_alpha.case_id}/actions/",
        data=json.dumps({"action": "acknowledge"}),
        content_type="application/json",
    )
    assert response.status_code == 200
    case_alpha.refresh_from_db()
    assert case_alpha.status == CaseStatus.ACKNOWLEDGED


def test_actions_endpoint_lists_missing_prerequisites(client_for, analyst, case_alpha):
    advance(case_alpha, CaseStatus.IN_ANALYSIS)
    Case.objects.filter(pk=case_alpha.pk).update(cvss_vector="")
    client = client_for(analyst)
    response = client.post(
        f"/api/v1/reports/{case_alpha.case_id}/actions/",
        data=json.dumps({"action": "submit_qualification"}),
        content_type="application/json",
    )
    assert response.status_code == 400
    assert "Vecteur CVSS manquant" in response.json()["missing"]
    case_alpha.refresh_from_db()
    assert case_alpha.status == CaseStatus.IN_ANALYSIS


def test_actions_endpoint_requires_comment_where_needed(client_for, coordinator, case_alpha):
    advance(case_alpha, CaseStatus.VALIDATION_PENDING)
    client = client_for(coordinator)
    response = client.post(
        f"/api/v1/reports/{case_alpha.case_id}/actions/",
        data=json.dumps({"action": "validate_qualification"}),
        content_type="application/json",
    )
    assert response.status_code == 400
    assert "Commentaire manquant" in response.json()["missing"]


def test_actions_endpoint_is_scoped(client_for, researcher_a, case_beta):
    client = client_for(researcher_a)
    response = client.post(
        f"/api/v1/reports/{case_beta.case_id}/actions/",
        data=json.dumps({"action": "acknowledge"}),
        content_type="application/json",
    )
    assert response.status_code == 404


# ------------------------------------------------------ matrice de visibilite
def test_reporter_sees_simplified_status_without_scores(client_for, researcher_a, case_alpha):
    advance(case_alpha, CaseStatus.VALIDATION_PENDING)
    client = client_for(researcher_a)
    body = client.get(f"/api/v1/reports/{case_alpha.case_id}/").json()
    assert body["status"] == "ANALYSIS"
    assert body["status_label"] == "En analyse"
    for hidden in ("severity", "cvss_score", "cvss_vector"):
        assert hidden not in body
    listed = client.get("/api/v1/reports/").json()["results"][0]
    assert listed["status"] == "ANALYSIS"
    assert "cvss_score" not in listed


def test_dsi_sees_final_score_but_not_vector(client_for, dsi_alpha, case_alpha):
    advance(case_alpha, CaseStatus.VENDOR_NOTIFIED)
    client = client_for(dsi_alpha)
    body = client.get(f"/api/v1/reports/{case_alpha.case_id}/").json()
    assert body["cvss_score"] is not None
    assert "cvss_vector" not in body


def test_dsi_cannot_see_case_before_notification(client_for, dsi_alpha, case_alpha):
    advance(case_alpha, CaseStatus.VALIDATED)
    client = client_for(dsi_alpha)
    assert client.get(f"/api/v1/reports/{case_alpha.case_id}/").status_code == 404


def test_researcher_cannot_create_program(client_for, researcher_a, organization):
    client = client_for(researcher_a)
    response = client.post(
        "/api/v1/programs/",
        data=json.dumps(
            {
                "name": "Programme pirate",
                "program_type": "VDP",
                "organization": str(organization.id),
            }
        ),
        content_type="application/json",
    )
    assert response.status_code == 403


# ------------------------------------------------------------------ cle d'API
def test_api_key_authentication(client, researcher_a, organization):
    raw, prefix, key_hash = generate_key()
    ApiKey.objects.create(
        user=researcher_a, label="Integration", prefix=prefix, key_hash=key_hash
    )
    response = post_report(client, HTTP_X_EVDP_API_KEY=raw)
    assert response.status_code == 201


def test_invalid_api_key_is_refused(client):
    response = client.get("/api/v1/reports/", HTTP_X_EVDP_API_KEY="evdp_invalide")
    assert response.status_code in (401, 403)


def test_inactive_api_key_is_refused(client, researcher_a):
    raw, prefix, key_hash = generate_key()
    ApiKey.objects.create(
        user=researcher_a,
        label="Revoquee",
        prefix=prefix,
        key_hash=key_hash,
        is_active=False,
    )
    assert client.get("/api/v1/reports/", HTTP_X_EVDP_API_KEY=raw).status_code in (401, 403)


def test_api_key_is_never_stored_in_clear(researcher_a):
    raw, prefix, key_hash = generate_key()
    entry = ApiKey.objects.create(
        user=researcher_a, label="Test", prefix=prefix, key_hash=key_hash
    )
    assert raw not in entry.key_hash
    assert len(entry.key_hash) == 64


# --------------------------------------------------------------------- CSAF
CSAF_DOCUMENT = {
    "document": {
        "csaf_version": "2.0",
        "category": "csaf_security_advisory",
        "title": "Advisory editeur",
        "tracking": {"id": "VENDOR-2026-01"},
    },
    "vulnerabilities": [
        {
            "cve": "CVE-2026-1234",
            "title": "Debordement de tampon",
            "notes": [{"category": "description", "text": "Un debordement de tampon."}],
            "scores": [
                {"cvss_v3": {"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}
            ],
        }
    ],
}


def test_csaf_import_requires_capability(client_for, researcher_a):
    client = client_for(researcher_a)
    response = client.post(
        "/api/v1/import/csaf/",
        data=json.dumps(CSAF_DOCUMENT),
        content_type="application/json",
    )
    assert response.status_code == 403


def test_import_csaf_service_refuses_without_capability(researcher_a):
    """Le service est la seule autorite, pas seulement la vue DRF : un futur
    appelant (commande de gestion, tache asynchrone...) doit heriter du
    controle sans avoir a le reimplementer."""
    from django.core.exceptions import PermissionDenied

    from apps.csaf.services import import_csaf

    with pytest.raises(PermissionDenied):
        import_csaf(CSAF_DOCUMENT, researcher_a)


def test_csaf_import_creates_case(client_for, analyst):
    """L'import CSAF reste exempte de piece jointe : il reprend un avis publie."""
    client = client_for(analyst)
    response = client.post(
        "/api/v1/import/csaf/",
        data=json.dumps(CSAF_DOCUMENT),
        content_type="application/json",
    )
    assert response.status_code == 201
    assert response.json()["imported"] == 1
    case = Case.objects.get(case_id=response.json()["cases"][0])
    assert case.cve_id == "CVE-2026-1234"
    assert float(case.cvss_score) == 9.8
    assert case.attachments.count() == 0


def test_csaf_rejects_wrong_version(client_for, analyst):
    client = client_for(analyst)
    payload = json.loads(json.dumps(CSAF_DOCUMENT))
    payload["document"]["csaf_version"] = "1.2"
    response = client.post(
        "/api/v1/import/csaf/",
        data=json.dumps(payload),
        content_type="application/json",
    )
    assert response.status_code == 400
    assert Case.objects.count() == 0


def test_csaf_rejects_empty_vulnerabilities(client_for, analyst):
    client = client_for(analyst)
    payload = json.loads(json.dumps(CSAF_DOCUMENT))
    payload["vulnerabilities"] = []
    response = client.post(
        "/api/v1/import/csaf/",
        data=json.dumps(payload),
        content_type="application/json",
    )
    assert response.status_code == 400


# ------------------------------------- validation du modele sur les ecritures
# Un ModelSerializer ne declenche pas Model.clean() : sans relais explicite,
# l'API ecrivait ce que le formulaire web refuse.
def test_api_rejects_a_payload_passed_off_as_pgp(client_for, researcher_a):
    """Sans ce controle, le dossier annonce un chiffrement qui n'existe pas."""
    client = client_for(researcher_a)
    response = post_report(client, {**REPORT_PAYLOAD, "pgp_payload": "ceci n'est pas du PGP"})
    assert response.status_code == 400
    assert Case.objects.count() == 0


def test_api_accepts_a_real_pgp_block(client_for, researcher_a):
    """Le cas nominal reste ouvert : un vrai bloc chiffre passe."""
    bloc = "-----BEGIN PGP MESSAGE-----\n\nhQIMA1234\n-----END PGP MESSAGE-----"
    client = client_for(researcher_a)
    response = post_report(client, {**REPORT_PAYLOAD, "pgp_payload": bloc})
    assert response.status_code == 201
    assert Case.objects.get().report.is_pgp_encrypted


def test_api_rejects_a_program_with_inverted_dates(client_for, coordinator, organization):
    client = client_for(coordinator)
    response = client.post(
        "/api/v1/programs/",
        data=json.dumps(
            {
                "name": "Programme aux dates inversees",
                "program_type": "VDP",
                "organization": str(organization.pk),
                "starts_on": "2026-06-01",
                "ends_on": "2026-05-01",
            }
        ),
        content_type="application/json",
    )
    assert response.status_code == 400
    assert "ends_on" in response.json()


def test_api_rejects_a_bug_bounty_open_to_anonymous_reports(
    client_for, coordinator, organization
):
    """L'invariant du Bug Bounty vaut aussi pour l'API, pas seulement le form."""
    client = client_for(coordinator)
    payload = {
        "name": "Bug Bounty par API",
        "program_type": "BUG_BOUNTY",
        "organization": str(organization.pk),
        "allows_anonymous_reports": True,
    }
    refus = client.post(
        "/api/v1/programs/", data=json.dumps(payload), content_type="application/json"
    )
    assert refus.status_code == 400
    assert "allows_anonymous_reports" in refus.json()

    # Configure correctement, le meme programme passe.
    payload["allows_anonymous_reports"] = False
    response = client.post(
        "/api/v1/programs/", data=json.dumps(payload), content_type="application/json"
    )
    assert response.status_code == 201
    assert not Program.objects.get(name="Bug Bounty par API").accepts_anonymous_reports
