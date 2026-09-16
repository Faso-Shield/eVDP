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


# --------------------------------------------------- widget date (regression)
def test_timeline_date_widget_renders_iso_format(client_for, case_alpha, coordinator):
    """Un <input type="date"> HTML5 n'accepte que le format ISO (AAAA-MM-JJ)
    dans son attribut value. Sans `format="%Y-%m-%d"` sur le widget, Django
    rend la date au format localise (JJ/MM/AAAA) : le champ parait vide au
    navigateur, se soumet vide, et bloque silencieusement l'enregistrement
    de TOUT le formulaire (advisory + formset valides ensemble) puisque
    happened_on est obligatoire. Reproduit et corrige en session."""
    transition_case(case_alpha, CaseStatus.TRIAGE, coordinator)
    transition_case(case_alpha, CaseStatus.VALIDATED, coordinator)
    advisory = build_advisory(case_alpha, coordinator)
    entry = advisory.timeline.first()
    assert entry is not None and entry.happened_on is not None

    client = client_for(coordinator)
    response = client.get(f"/advisories/manage/{advisory.advisory_id}/")
    content = response.content.decode()

    iso_value = f'value="{entry.happened_on.isoformat()}"'
    assert iso_value in content, "La date doit etre rendue au format ISO pour un input type=date"


def test_editing_advisory_with_existing_timeline_entry_saves(
    client_for, case_alpha, coordinator
):
    """Bout en bout : modifier un advisory dont la chronologie a deja une
    entree ne doit jamais faire echouer silencieusement l'enregistrement.

    Les donnees POST reprennent exactement ce qu'un navigateur soumettrait
    pour un <input type="date"> correctement rendu au format ISO."""
    transition_case(case_alpha, CaseStatus.TRIAGE, coordinator)
    transition_case(case_alpha, CaseStatus.VALIDATED, coordinator)
    advisory = build_advisory(case_alpha, coordinator)
    entry = advisory.timeline.first()

    client = client_for(coordinator)
    data = {
        "title": advisory.title,
        "summary": "Resume verifie par le test de non-regression.",
        "product": advisory.product,
        "affected_versions": advisory.affected_versions,
        "fixed_versions": advisory.fixed_versions,
        "description": advisory.description,
        "impact": advisory.impact,
        "solution": advisory.solution,
        "workaround": advisory.workaround,
        "severity": advisory.severity,
        "credit": advisory.credit,
        "timeline-TOTAL_FORMS": "1",
        "timeline-INITIAL_FORMS": "1",
        "timeline-MIN_NUM_FORMS": "0",
        "timeline-MAX_NUM_FORMS": "1000",
        "timeline-0-id": str(entry.pk),
        "timeline-0-happened_on": entry.happened_on.isoformat(),
        "timeline-0-label": entry.label,
        "timeline-0-position": entry.position,
    }
    if advisory.organization_id:
        data["organization"] = str(advisory.organization_id)

    response = client.post(f"/advisories/manage/{advisory.advisory_id}/", data)
    assert response.status_code == 302
    advisory.refresh_from_db()
    assert advisory.summary == "Resume verifie par le test de non-regression."
