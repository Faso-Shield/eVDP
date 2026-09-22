"""Tests de publication : advisories assainis, jamais de fuite du case prive."""

import pytest
from django.core.exceptions import PermissionDenied, ValidationError
from django.urls import reverse

from apps.audit.models import AuditAction, AuditLog
from apps.coordination.services import transition_case
from apps.coordination.workflow import CaseStatus
from apps.disclosures.models import Advisory, AdvisoryStatus
from apps.disclosures.services import (
    create_advisory,
    create_advisory_from_case,
    credit_for,
    publish_advisory,
    retract_advisory,
    update_advisory,
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


# --------------------------------------------------------- mutations en GET
# Regression : publish/retract/transition n'exigeaient aucune methode HTTP
# particuliere. publish_advisory ne verifiait meme pas request.method - un
# advisory deja APPROVED avec un resume rempli pouvait etre publie par un
# simple GET (donc hors protection CSRF, qui ne couvre que les methodes non
# sures). Meme classe de probleme que celle deja corrigee sur bounty et le
# portefeuille, mais avec un impact plus grave : une divulgation publique.
def test_publish_via_get_is_rejected(client_for, case_alpha, coordinator):
    advisory = build_advisory(case_alpha, coordinator)
    advisory.status = AdvisoryStatus.APPROVED
    advisory.save(update_fields=["status"])

    client = client_for(coordinator)
    response = client.get(reverse("disclosures:publish", args=[advisory.advisory_id]))
    assert response.status_code == 405
    advisory.refresh_from_db()
    assert advisory.status == AdvisoryStatus.APPROVED
    assert advisory.is_published is False


def test_retract_via_get_is_rejected(client_for, case_alpha, coordinator):
    advisory = build_advisory(case_alpha, coordinator)
    advisory.status = AdvisoryStatus.APPROVED
    advisory.save(update_fields=["status"])
    publish_advisory(advisory, coordinator)

    client = client_for(coordinator)
    response = client.get(reverse("disclosures:retract", args=[advisory.advisory_id]))
    assert response.status_code == 405
    advisory.refresh_from_db()
    assert advisory.status == AdvisoryStatus.PUBLISHED


def test_transition_via_get_is_rejected(client_for, case_alpha, coordinator):
    advisory = build_advisory(case_alpha, coordinator)

    client = client_for(coordinator)
    response = client.get(reverse("disclosures:transition", args=[advisory.advisory_id]))
    assert response.status_code == 405
    advisory.refresh_from_db()
    assert advisory.status == AdvisoryStatus.DRAFT


# -------------------------------------------------------------- administration
def test_admin_publish_goes_through_the_service(rf, case_alpha, coordinator):
    """L'admin ne doit pas reimplementer le cycle de vie : capacite, resume
    obligatoire, published_at/published_by et audit doivent etre traites
    comme via l'interface web."""
    from django.contrib.admin.sites import AdminSite
    from django.contrib.messages.storage.fallback import FallbackStorage

    from apps.disclosures.admin import AdvisoryAdmin, action_publish

    advisory = build_advisory(case_alpha, coordinator)
    advisory.status = AdvisoryStatus.APPROVED
    advisory.save(update_fields=["status"])

    request = rf.post("/admin/disclosures/advisory/")
    request.user = coordinator
    request.session = {}
    request._messages = FallbackStorage(request)

    action_publish(
        AdvisoryAdmin(Advisory, AdminSite()), request, Advisory.objects.filter(pk=advisory.pk)
    )
    advisory.refresh_from_db()

    assert advisory.status == AdvisoryStatus.PUBLISHED
    assert advisory.published_by == coordinator
    assert advisory.published_at is not None
    assert AuditLog.objects.filter(action=AuditAction.ADVISORY_PUBLISHED).exists()


def test_admin_publish_refuses_missing_capability(rf, case_alpha, coordinator, analyst):
    from django.contrib.admin.sites import AdminSite
    from django.contrib.messages.storage.fallback import FallbackStorage

    from apps.disclosures.admin import AdvisoryAdmin, action_publish

    advisory = build_advisory(case_alpha, coordinator)
    advisory.status = AdvisoryStatus.APPROVED
    advisory.save(update_fields=["status"])

    request = rf.post("/admin/disclosures/advisory/")
    request.user = analyst
    request.session = {}
    request._messages = FallbackStorage(request)

    action_publish(
        AdvisoryAdmin(Advisory, AdminSite()), request, Advisory.objects.filter(pk=advisory.pk)
    )
    advisory.refresh_from_db()

    assert advisory.status == AdvisoryStatus.APPROVED  # inchange


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


# ------------------------------------------------------- ecritures auditees
def test_manual_creation_is_audited(coordinator, organization):
    """Un advisory sans case source passe par le service, donc par l'audit."""
    advisory = create_advisory(
        Advisory(
            title="Advisory redige a la main",
            summary="Resume public.",
            organization=organization,
        ),
        coordinator,
    )

    assert advisory.created_by == coordinator
    assert AuditLog.objects.filter(
        action=AuditAction.ADVISORY_CREATED, object_id=str(advisory.pk)
    ).exists()


def test_manual_creation_requires_capability(researcher_a, organization):
    with pytest.raises(PermissionDenied):
        create_advisory(
            Advisory(title="Interdit", summary="x", organization=organization),
            researcher_a,
        )


def test_editorial_update_is_audited(case_alpha, coordinator):
    advisory = build_advisory(case_alpha, coordinator)
    advisory.summary = "Resume corrige apres relecture."
    update_advisory(advisory, coordinator)
    advisory.refresh_from_db()

    assert advisory.summary == "Resume corrige apres relecture."
    assert AuditLog.objects.filter(
        action=AuditAction.ADVISORY_UPDATED, object_id=str(advisory.pk)
    ).exists()
