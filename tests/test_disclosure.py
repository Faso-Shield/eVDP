"""Tests de publication : advisories assainis, jamais de fuite du case prive."""

import pytest
from django.core.exceptions import PermissionDenied, ValidationError

from apps.audit.models import AuditAction, AuditLog
from apps.coordination.services import transition_case
from apps.coordination.workflow import CaseStatus
from apps.disclosures.models import Advisory, AdvisoryStatus
from apps.disclosures.services import (
    create_advisory_from_case,
    credit_for,
    publish_advisory,
    retract_advisory,
)

pytestmark = pytest.mark.django_db


def build_advisory(case, actor, **overrides):
    return create_advisory_from_case(
        case, actor, summary="Resume public assaini.", **overrides
    )


def test_advisory_id_format(case_alpha, coordinator):
    advisory = build_advisory(case_alpha, coordinator)
    assert advisory.advisory_id.startswith("EVDP-ADV-")
    assert advisory.status == AdvisoryStatus.DRAFT


def test_advisory_does_not_copy_sensitive_case_fields(case_alpha, coordinator):
    """Principe 6 : l'advisory ne recopie ni PoC ni etapes de reproduction."""
    case_alpha.report.proof_of_concept = "curl 'https://cible/?id=1 OR 1=1--'"
    case_alpha.report.steps_to_reproduce = "1. Injecter le payload secret"
    case_alpha.report.target_url = "https://interne.alpha.gov.bf/admin"
    case_alpha.report.save()

    advisory = build_advisory(case_alpha, coordinator)
    serialized = " ".join(
        str(value) for value in advisory.__dict__.values() if value is not None
    )
    assert "OR 1=1" not in serialized
    assert "payload secret" not in serialized
    assert "interne.alpha.gov.bf" not in serialized


def test_researcher_cannot_draft_advisory(case_alpha, researcher_a):
    with pytest.raises(PermissionDenied):
        build_advisory(case_alpha, researcher_a)


def test_publication_requires_summary(case_alpha, coordinator):
    advisory = create_advisory_from_case(case_alpha, coordinator, summary="")
    advisory.status = AdvisoryStatus.APPROVED
    advisory.save(update_fields=["status"])
    with pytest.raises(ValidationError):
        publish_advisory(advisory, coordinator)


def test_publication_requires_approved_state(case_alpha, coordinator):
    advisory = build_advisory(case_alpha, coordinator)
    with pytest.raises(ValidationError):
        publish_advisory(advisory, coordinator)


def test_analyst_cannot_publish(case_alpha, coordinator, analyst):
    advisory = build_advisory(case_alpha, coordinator)
    advisory.status = AdvisoryStatus.APPROVED
    advisory.save(update_fields=["status"])
    with pytest.raises(PermissionDenied):
        publish_advisory(advisory, analyst)


def test_coordinator_publishes_and_audits(case_alpha, coordinator):
    advisory = build_advisory(case_alpha, coordinator)
    advisory.status = AdvisoryStatus.APPROVED
    advisory.save(update_fields=["status"])
    publish_advisory(advisory, coordinator)
    advisory.refresh_from_db()

    assert advisory.status == AdvisoryStatus.PUBLISHED
    assert advisory.published_at is not None
    assert advisory.is_published is True
    assert AuditLog.objects.filter(action=AuditAction.ADVISORY_PUBLISHED).exists()


def test_retraction_requires_reason(case_alpha, coordinator):
    advisory = build_advisory(case_alpha, coordinator)
    advisory.status = AdvisoryStatus.APPROVED
    advisory.save(update_fields=["status"])
    publish_advisory(advisory, coordinator)
    with pytest.raises(ValidationError):
        retract_advisory(advisory, coordinator, reason="  ")


# ------------------------------------------------------------ credit chercheur
def test_credit_respects_pseudonym_choice(case_alpha, coordinator, researcher_a):
    advisory = build_advisory(case_alpha, coordinator)
    assert advisory.credit == "alpha-hunter"
    assert researcher_a.full_name not in advisory.credit


def test_credit_is_anonymous_when_refused(case_alpha, coordinator):
    case_alpha.report.wants_credit = False
    case_alpha.report.save(update_fields=["wants_credit"])
    assert credit_for(case_alpha) == "Chercheur anonyme"


def test_credit_is_anonymous_for_anonymous_report(case_alpha, coordinator):
    case_alpha.report.is_anonymous = True
    case_alpha.report.save(update_fields=["is_anonymous"])
    assert credit_for(case_alpha) == "Chercheur anonyme"


# ------------------------------------------------------------ visibilite web
def test_draft_advisory_is_not_public(client, case_alpha, coordinator):
    advisory = build_advisory(case_alpha, coordinator)
    response = client.get(f"/advisories/{advisory.advisory_id}/")
    assert response.status_code == 404


def test_draft_advisory_absent_from_public_list(client, case_alpha, coordinator):
    advisory = build_advisory(case_alpha, coordinator)
    response = client.get("/advisories/")
    assert advisory.advisory_id not in response.content.decode()


def test_published_advisory_is_public(client, case_alpha, coordinator):
    advisory = build_advisory(case_alpha, coordinator)
    advisory.status = AdvisoryStatus.APPROVED
    advisory.save(update_fields=["status"])
    publish_advisory(advisory, coordinator)

    response = client.get(f"/advisories/{advisory.advisory_id}/")
    assert response.status_code == 200
    assert advisory.title in response.content.decode()


def test_public_advisory_does_not_expose_case_id(client, case_alpha, coordinator):
    """Principe 5 : ne jamais exposer les donnees internes du case."""
    advisory = build_advisory(case_alpha, coordinator)
    advisory.status = AdvisoryStatus.APPROVED
    advisory.save(update_fields=["status"])
    publish_advisory(advisory, coordinator)

    content = client.get(f"/advisories/{advisory.advisory_id}/").content.decode()
    assert case_alpha.case_id not in content


def test_timeline_copied_only_from_public_events(case_alpha, coordinator):
    transition_case(case_alpha, CaseStatus.TRIAGE, coordinator)
    transition_case(case_alpha, CaseStatus.VALIDATED, coordinator)
    advisory = build_advisory(case_alpha, coordinator)

    public_events = case_alpha.timeline.filter(is_public=True).count()
    assert advisory.timeline.count() == public_events
    assert case_alpha.timeline.filter(is_public=False).exists()


def test_case_report_never_reachable_anonymously(client, case_alpha):
    assert client.get(f"/cases/{case_alpha.case_id}/").status_code == 302
    assert Advisory.objects.count() == 0
