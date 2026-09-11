"""Tests de l'API REST v1."""

import json

import pytest

from apps.accounts.models import ApiKey
from apps.api.authentication import generate_key
from apps.coordination.models import Case
from apps.coordination.workflow import CaseStatus
from apps.programs.models import Program

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


# ------------------------------------------------------------ acces anonyme
def test_anonymous_cannot_list_reports(client):
    assert client.get("/api/v1/reports/").status_code in (401, 403)


def test_anonymous_cannot_create_report(client):
    response = client.post(
        "/api/v1/reports/",
        data=json.dumps(REPORT_PAYLOAD),
        content_type="application/json",
    )
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
    response = client.post(
        "/api/v1/reports/",
        data=json.dumps(REPORT_PAYLOAD),
        content_type="application/json",
    )
    assert response.status_code == 201
    body = response.json()
    assert body["case_id"].startswith("EVDP-")
    case = Case.objects.get(case_id=body["case_id"])
    assert case.reporter == researcher_a
    assert case.status == CaseStatus.SUBMITTED


def test_short_description_is_rejected(client_for, researcher_a):
    client = client_for(researcher_a)
    payload = {**REPORT_PAYLOAD, "description": "trop court"}
    response = client.post(
        "/api/v1/reports/", data=json.dumps(payload), content_type="application/json"
    )
    assert response.status_code == 400
    assert "description" in response.json()


def test_invalid_cvss_vector_is_rejected(client_for, researcher_a):
    client = client_for(researcher_a)
    payload = {**REPORT_PAYLOAD, "cvss_vector": "CVSS:3.1/AV:Z"}
    response = client.post(
        "/api/v1/reports/", data=json.dumps(payload), content_type="application/json"
    )
    assert response.status_code == 400


def test_mass_assignment_of_status_is_ignored(client_for, researcher_a):
    """Un client ne doit pas pouvoir imposer un statut ou une severite retenue."""
    client = client_for(researcher_a)
    payload = {**REPORT_PAYLOAD, "status": "PUBLISHED", "reporter": "autre"}
    response = client.post(
        "/api/v1/reports/", data=json.dumps(payload), content_type="application/json"
    )
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
    client_for, case_alpha, coordinator, researcher_a
):
    from apps.coordination.constants import Confidentiality
    from apps.coordination.services import post_message

    post_message(
        case_alpha, coordinator, "Note interne CSIRT", confidentiality=Confidentiality.INTERNAL
    )
    post_message(case_alpha, coordinator, "Message au declarant")

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
    client = client_for(analyst)
    response = client.patch(
        f"/api/v1/reports/{case_alpha.case_id}/",
        data=json.dumps({"severity": "HIGH"}),
        content_type="application/json",
    )
    assert response.status_code == 200
    case_alpha.refresh_from_db()
    assert case_alpha.severity == "HIGH"


def test_transition_endpoint_enforces_state_machine(client_for, coordinator, case_alpha):
    client = client_for(coordinator)
    response = client.post(
        f"/api/v1/reports/{case_alpha.case_id}/transition/",
        data=json.dumps({"target_status": "PUBLISHED"}),
        content_type="application/json",
    )
    assert response.status_code == 400
    case_alpha.refresh_from_db()
    assert case_alpha.status == CaseStatus.SUBMITTED


def test_transition_endpoint_applies_valid_transition(client_for, coordinator, case_alpha):
    client = client_for(coordinator)
    response = client.post(
        f"/api/v1/reports/{case_alpha.case_id}/transition/",
        data=json.dumps({"target_status": "TRIAGE"}),
        content_type="application/json",
    )
    assert response.status_code == 200
    case_alpha.refresh_from_db()
    assert case_alpha.status == CaseStatus.TRIAGE


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
    response = client.post(
        "/api/v1/reports/",
        data=json.dumps(REPORT_PAYLOAD),
        content_type="application/json",
        HTTP_X_EVDP_API_KEY=raw,
    )
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


def test_csaf_import_creates_case(client_for, analyst):
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
    response = client.post(
        "/api/v1/reports/",
        data=json.dumps({**REPORT_PAYLOAD, "pgp_payload": "ceci n'est pas du PGP"}),
        content_type="application/json",
    )
    assert response.status_code == 400
    assert Case.objects.count() == 0


def test_api_accepts_a_real_pgp_block(client_for, researcher_a):
    """Le cas nominal reste ouvert : un vrai bloc chiffre passe."""
    bloc = "-----BEGIN PGP MESSAGE-----\n\nhQIMA1234\n-----END PGP MESSAGE-----"
    client = client_for(researcher_a)
    response = client.post(
        "/api/v1/reports/",
        data=json.dumps({**REPORT_PAYLOAD, "pgp_payload": bloc}),
        content_type="application/json",
    )
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
