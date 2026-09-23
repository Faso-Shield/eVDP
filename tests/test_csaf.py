"""Tests de l'export CSAF 2.0 des advisories publies.

Les tests d'import CSAF vivent dans tests/test_api.py, avec les autres
endpoints d'ecriture de l'API.
"""

import json
from datetime import datetime
from decimal import Decimal

import pytest
from django.core.exceptions import ValidationError

from apps.audit.models import AuditAction, AuditLog
from apps.csaf.services import export_advisory_to_csaf
from apps.disclosures.models import AdvisoryReference, AdvisoryStatus
from apps.disclosures.services import (
    create_advisory_from_case,
    publish_advisory,
    retract_advisory,
)
from apps.vulnerabilities.constants import Severity
from apps.vulnerabilities.models import CVE

pytestmark = pytest.mark.django_db

#: Champs sensibles poses sur le rapport source : aucun ne doit ressortir.
SECRET_POC = "curl 'https://cible/?id=1 OR 1=1--'"
SECRET_STEPS = "1. Injecter le payload secret"
SECRET_URL = "https://interne.alpha.gov.bf/admin"


def _draft(case, actor, cwe):
    """Advisory complet, pret a etre approuve puis publie."""
    case.report.proof_of_concept = SECRET_POC
    case.report.steps_to_reproduce = SECRET_STEPS
    case.report.target_url = SECRET_URL
    case.report.save()

    advisory = create_advisory_from_case(case, actor, summary="Resume public assaini.")
    advisory.description = "Description publique de la faille."
    advisory.impact = "Impact publie."
    advisory.solution = "Appliquer le correctif 2.4.1."
    advisory.workaround = "Restreindre l'acces au module concerne."
    advisory.product = "Portail test"
    advisory.affected_versions = "< 2.4.1"
    advisory.fixed_versions = "2.4.1"
    advisory.cwe = cwe
    advisory.cve = CVE.objects.create(cve_id="CVE-2026-1234")
    advisory.cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    advisory.cvss_score = Decimal("9.8")
    advisory.severity = Severity.CRITICAL
    advisory.save()
    AdvisoryReference.objects.create(
        advisory=advisory, title="Bulletin editeur", url="https://exemple.bf/bulletin"
    )
    return advisory


@pytest.fixture
def published_advisory(db, case_alpha, coordinator, cwe):
    advisory = _draft(case_alpha, coordinator, cwe)
    advisory.status = AdvisoryStatus.APPROVED
    advisory.save(update_fields=["status"])
    return publish_advisory(advisory, coordinator)


# --------------------------------------------------------------- eligibilite
def test_draft_advisory_cannot_be_exported(case_alpha, coordinator, cwe):
    advisory = _draft(case_alpha, coordinator, cwe)
    with pytest.raises(ValidationError):
        export_advisory_to_csaf(advisory)


def test_retracted_advisory_cannot_be_exported(published_advisory, coordinator):
    retract_advisory(published_advisory, coordinator, reason="Publication prematuree.")
    with pytest.raises(ValidationError):
        export_advisory_to_csaf(published_advisory)


# ------------------------------------------------------------- conformite 2.0
def test_document_declares_csaf_2_0(published_advisory):
    document = export_advisory_to_csaf(published_advisory)["document"]
    assert document["csaf_version"] == "2.0"
    assert document["category"] == "csaf_security_advisory"
    assert document["title"] == published_advisory.title


def test_publisher_is_the_national_team(published_advisory, settings):
    publisher = export_advisory_to_csaf(published_advisory)["document"]["publisher"]
    assert publisher["category"] == "coordinator"
    assert publisher["name"] == settings.EVDP["NATIONAL_TEAM"]
    assert publisher["namespace"].startswith("http")


def test_tracking_carries_every_required_field(published_advisory):
    """`revision_history` est obligatoire : sans lui le document est invalide."""
    tracking = export_advisory_to_csaf(published_advisory)["document"]["tracking"]
    for field in (
        "id",
        "status",
        "version",
        "initial_release_date",
        "current_release_date",
        "revision_history",
    ):
        assert field in tracking, f"champ CSAF obligatoire manquant : {field}"
    assert tracking["id"] == published_advisory.advisory_id
    assert tracking["revision_history"][0]["number"] == "1"


def test_dates_are_timezone_aware(published_advisory):
    tracking = export_advisory_to_csaf(published_advisory)["document"]["tracking"]
    parsed = datetime.fromisoformat(tracking["initial_release_date"])
    assert parsed.tzinfo is not None


def test_scores_reference_a_declared_product(published_advisory):
    """`scores[].products` est obligatoire et doit pointer le product_tree."""
    document = export_advisory_to_csaf(published_advisory)
    score = document["vulnerabilities"][0]["scores"][0]
    declared = {
        product["product_id"] for product in document["product_tree"]["full_product_names"]
    }

    assert score["cvss_v3"]["version"] == "3.1"
    assert score["cvss_v3"]["baseScore"] == 9.8
    assert score["cvss_v3"]["baseSeverity"] == "CRITICAL"
    assert score["products"]
    assert set(score["products"]) <= declared


def test_fixed_version_is_declared_as_a_product(published_advisory):
    document = export_advisory_to_csaf(published_advisory)
    declared = {
        product["product_id"] for product in document["product_tree"]["full_product_names"]
    }
    status = document["vulnerabilities"][0]["product_status"]
    assert set(status["known_affected"]) <= declared
    assert set(status["fixed"]) <= declared


def test_credit_uses_acknowledgments(published_advisory):
    """CSAF nomme ce champ `acknowledgments` - `credits` n'existe pas."""
    vulnerability = export_advisory_to_csaf(published_advisory)["vulnerabilities"][0]
    assert "credits" not in vulnerability
    assert vulnerability["acknowledgments"] == [{"names": ["alpha-hunter"]}]


def test_cwe_and_cve_are_exported(published_advisory):
    vulnerability = export_advisory_to_csaf(published_advisory)["vulnerabilities"][0]
    assert vulnerability["cve"] == "CVE-2026-1234"
    assert vulnerability["cwe"] == {"id": "CWE-89", "name": "SQL Injection"}


def test_solution_and_workaround_become_remediations(published_advisory):
    vulnerability = export_advisory_to_csaf(published_advisory)["vulnerabilities"][0]
    categories = {item["category"]: item["details"] for item in vulnerability["remediations"]}
    assert categories["vendor_fix"] == "Appliquer le correctif 2.4.1."
    assert categories["workaround"] == "Restreindre l'acces au module concerne."


def test_references_include_the_public_advisory_page(published_advisory):
    references = export_advisory_to_csaf(published_advisory)["document"]["references"]
    assert any(reference["category"] == "self" for reference in references)
    assert any("exemple.bf/bulletin" in reference["url"] for reference in references)


# ------------------------------------------------------------------ etancheite
def test_export_never_exposes_the_private_case(published_advisory, case_alpha):
    """Principe 5 : l'export ne lit que l'advisory, jamais le case source."""
    serialized = json.dumps(export_advisory_to_csaf(published_advisory))
    assert SECRET_POC not in serialized
    assert "payload secret" not in serialized
    assert "interne.alpha.gov.bf" not in serialized
    assert case_alpha.case_id not in serialized


# -------------------------------------------------------------------- endpoint
def test_export_endpoint_is_public(client, published_advisory):
    response = client.get(f"/api/v1/export/csaf/{published_advisory.advisory_id}/")
    assert response.status_code == 200
    assert response["Content-Type"].startswith("application/json")
    assert response.json()["document"]["csaf_version"] == "2.0"


def test_export_endpoint_accepts_lowercase_identifier(client, published_advisory):
    response = client.get(f"/api/v1/export/csaf/{published_advisory.advisory_id.lower()}/")
    assert response.status_code == 200


def test_export_endpoint_hides_unpublished_advisory(client, case_alpha, coordinator, cwe):
    advisory = _draft(case_alpha, coordinator, cwe)
    response = client.get(f"/api/v1/export/csaf/{advisory.advisory_id}/")
    assert response.status_code == 404


def test_export_endpoint_is_audited(client, published_advisory):
    client.get(f"/api/v1/export/csaf/{published_advisory.advisory_id}/")
    entry = AuditLog.objects.filter(action=AuditAction.EXPORT_GENERATED).first()
    assert entry is not None
    assert entry.metadata["export_format"] == "csaf-2.0"


def test_public_advisory_page_offers_the_csaf_export(client, published_advisory):
    content = client.get(f"/advisories/{published_advisory.advisory_id}/").content.decode()
    assert f"/api/v1/export/csaf/{published_advisory.advisory_id}/" in content
