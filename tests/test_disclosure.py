"""Tests de publication : advisories assainis, jamais de fuite du case prive."""

import pytest
from django.core.exceptions import PermissionDenied, ValidationError
from django.urls import reverse

from apps.audit.models import AuditAction, AuditLog
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


def test_advisory_id_format(case_alpha, coordinator, analyst):
    advisory = build_advisory(case_alpha, analyst)
    assert advisory.advisory_id.startswith("EVDP-ADV-")
    assert advisory.status == AdvisoryStatus.DRAFT


def test_advisory_does_not_copy_sensitive_case_fields(case_alpha, coordinator, analyst):
    """Principe 6 : l'advisory ne recopie ni PoC ni etapes de reproduction."""
    case_alpha.report.proof_of_concept = "curl 'https://cible/?id=1 OR 1=1--'"
    case_alpha.report.steps_to_reproduce = "1. Injecter le payload secret"
    case_alpha.report.target_url = "https://interne.alpha.gov.bf/admin"
    case_alpha.report.save()

    advisory = build_advisory(case_alpha, analyst)
    serialized = " ".join(
        str(value) for value in advisory.__dict__.values() if value is not None
    )
    assert "OR 1=1" not in serialized
    assert "payload secret" not in serialized
    assert "interne.alpha.gov.bf" not in serialized


def test_researcher_cannot_draft_advisory(case_alpha, researcher_a):
    with pytest.raises(PermissionDenied):
        build_advisory(case_alpha, researcher_a)


def test_publication_requires_summary(case_alpha, coordinator, analyst):
    advisory = create_advisory_from_case(case_alpha, analyst, summary="")
    advisory.status = AdvisoryStatus.APPROVED
    advisory.save(update_fields=["status"])
    with pytest.raises(ValidationError):
        publish_advisory(advisory, coordinator)


def test_publication_requires_approved_state(case_alpha, coordinator, analyst):
    advisory = build_advisory(case_alpha, analyst)
    with pytest.raises(ValidationError):
        publish_advisory(advisory, coordinator)


def test_analyst_cannot_publish(case_alpha, coordinator, analyst):
    advisory = build_advisory(case_alpha, analyst)
    advisory.status = AdvisoryStatus.APPROVED
    advisory.save(update_fields=["status"])
    with pytest.raises(PermissionDenied):
        publish_advisory(advisory, analyst)


def test_coordinator_publishes_and_audits(case_alpha, coordinator, analyst):
    advisory = build_advisory(case_alpha, analyst)
    advisory.status = AdvisoryStatus.APPROVED
    advisory.save(update_fields=["status"])
    publish_advisory(advisory, coordinator)
    advisory.refresh_from_db()

    assert advisory.status == AdvisoryStatus.PUBLISHED
    assert advisory.published_at is not None
    assert advisory.is_published is True
    assert AuditLog.objects.filter(action=AuditAction.ADVISORY_PUBLISHED).exists()


def test_retraction_requires_reason(case_alpha, coordinator, analyst):
    advisory = build_advisory(case_alpha, analyst)
    advisory.status = AdvisoryStatus.APPROVED
    advisory.save(update_fields=["status"])
    publish_advisory(advisory, coordinator)
    with pytest.raises(ValidationError):
        retract_advisory(advisory, coordinator, reason="  ")


# --------------------------------------------------------- mutations en GET
# Regression : publish/retract/transition vivaient dans des vues separees qui
# n'exigeaient aucune methode HTTP particuliere ; publish_advisory ne
# verifiait meme pas request.method - un advisory deja APPROVED avec un
# resume rempli pouvait etre publie par un simple GET (donc hors protection
# CSRF, qui ne couvre que les methodes non sures). Ces vues ont depuis ete
# fusionnees dans advisory_manage (_appliquer_action) : l'action de cycle de
# vie ne peut plus etre declenchee que depuis la branche POST de cette vue,
# ce qui rend la classe de probleme structurellement impossible. On le
# verifie : un GET sur la page de gestion ne change jamais le statut.
def test_manage_via_get_never_changes_status(client_for, case_alpha, coordinator, analyst):
    advisory = build_advisory(case_alpha, analyst)
    advisory.status = AdvisoryStatus.APPROVED
    advisory.save(update_fields=["status"])

    client = client_for(coordinator)
    response = client.get(reverse("disclosures:manage", args=[advisory.advisory_id]))
    assert response.status_code == 200
    advisory.refresh_from_db()
    assert advisory.status == AdvisoryStatus.APPROVED
    assert advisory.is_published is False


def _manage_request(rf, user, action, **extra):
    from django.contrib.messages.storage.fallback import FallbackStorage

    request = rf.post("/advisories/manage/", {"action": action, **extra})
    request.user = user
    request.session = {}
    request._messages = FallbackStorage(request)
    return request


def test_appliquer_action_publishes(rf, case_alpha, coordinator, analyst):
    from apps.disclosures.views import _appliquer_action

    advisory = build_advisory(case_alpha, analyst)
    advisory.case = None  # advisory autonome (un advisory de dossier suit l'etape 10)
    advisory.status = AdvisoryStatus.APPROVED
    advisory.save(update_fields=["status", "case"])

    _appliquer_action(_manage_request(rf, coordinator, "publish"), advisory)
    advisory.refresh_from_db()

    assert advisory.status == AdvisoryStatus.PUBLISHED
    assert advisory.is_published is True


def test_appliquer_action_publish_refuses_missing_capability(
    rf, case_alpha, coordinator, analyst
):
    from apps.disclosures.views import _appliquer_action

    advisory = build_advisory(case_alpha, analyst)
    advisory.status = AdvisoryStatus.APPROVED
    advisory.save(update_fields=["status"])

    _appliquer_action(_manage_request(rf, analyst, "publish"), advisory)
    advisory.refresh_from_db()

    assert advisory.status == AdvisoryStatus.APPROVED  # inchange
    assert advisory.is_published is False


def test_appliquer_action_retracts(rf, case_alpha, coordinator, analyst):
    from apps.disclosures.views import _appliquer_action

    advisory = build_advisory(case_alpha, analyst)
    advisory.status = AdvisoryStatus.APPROVED
    advisory.save(update_fields=["status"])
    publish_advisory(advisory, coordinator)

    _appliquer_action(
        _manage_request(rf, coordinator, "retract", reason="Information erronee."), advisory
    )
    advisory.refresh_from_db()

    assert advisory.status == AdvisoryStatus.RETRACTED


# -------------------------------------------------------------- administration
def test_admin_publish_goes_through_the_service(rf, case_alpha, coordinator, analyst):
    """L'admin ne doit pas reimplementer le cycle de vie : capacite, resume
    obligatoire, published_at/published_by et audit doivent etre traites
    comme via l'interface web."""
    from django.contrib.admin.sites import AdminSite
    from django.contrib.messages.storage.fallback import FallbackStorage

    from apps.disclosures.admin import AdvisoryAdmin, action_publish

    advisory = build_advisory(case_alpha, analyst)
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

    advisory = build_advisory(case_alpha, analyst)
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
def test_credit_respects_pseudonym_choice(case_alpha, coordinator, researcher_a, analyst):
    advisory = build_advisory(case_alpha, analyst)
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
def test_draft_advisory_is_not_public(client, case_alpha, coordinator, analyst):
    advisory = build_advisory(case_alpha, analyst)
    response = client.get(f"/advisories/{advisory.advisory_id}/")
    assert response.status_code == 404


def test_draft_advisory_absent_from_public_list(client, case_alpha, coordinator, analyst):
    advisory = build_advisory(case_alpha, analyst)
    response = client.get("/advisories/")
    assert advisory.advisory_id not in response.content.decode()


def test_published_advisory_is_public(client, case_alpha, coordinator, analyst):
    advisory = build_advisory(case_alpha, analyst)
    advisory.status = AdvisoryStatus.APPROVED
    advisory.save(update_fields=["status"])
    publish_advisory(advisory, coordinator)

    response = client.get(f"/advisories/{advisory.advisory_id}/")
    assert response.status_code == 200
    assert advisory.title in response.content.decode()


def test_public_advisory_does_not_expose_case_id(client, case_alpha, coordinator, analyst):
    """Principe 5 : ne jamais exposer les donnees internes du case."""
    advisory = build_advisory(case_alpha, analyst)
    advisory.status = AdvisoryStatus.APPROVED
    advisory.save(update_fields=["status"])
    publish_advisory(advisory, coordinator)

    content = client.get(f"/advisories/{advisory.advisory_id}/").content.decode()
    assert case_alpha.case_id not in content


def test_timeline_copied_only_from_public_events(case_alpha, analyst, advance):
    advance(case_alpha, CaseStatus.VALIDATED)
    advisory = build_advisory(case_alpha, analyst)

    public_events = case_alpha.timeline.filter(is_public=True).count()
    assert advisory.timeline.count() == public_events
    assert case_alpha.timeline.filter(is_public=False).exists()


def test_case_report_never_reachable_anonymously(client, case_alpha):
    assert client.get(f"/cases/{case_alpha.case_id}/").status_code == 302
    assert Advisory.objects.count() == 0


# ------------------------------------------------------- ecritures auditees
def test_manual_creation_is_audited(analyst, organization):
    """Un advisory sans case source passe par le service, donc par l'audit."""
    advisory = create_advisory(
        Advisory(
            title="Advisory redige a la main",
            summary="Resume public.",
            organization=organization,
        ),
        analyst,
    )

    assert advisory.created_by == analyst
    assert AuditLog.objects.filter(
        action=AuditAction.ADVISORY_CREATED, object_id=str(advisory.pk)
    ).exists()


def test_manual_creation_requires_capability(researcher_a, organization):
    with pytest.raises(PermissionDenied):
        create_advisory(
            Advisory(title="Interdit", summary="x", organization=organization),
            researcher_a,
        )


def test_editorial_update_is_audited(case_alpha, coordinator, analyst):
    advisory = build_advisory(case_alpha, analyst)
    advisory.summary = "Resume corrige apres relecture."
    update_advisory(advisory, analyst)
    advisory.refresh_from_db()

    assert advisory.summary == "Resume corrige apres relecture."
    assert AuditLog.objects.filter(
        action=AuditAction.ADVISORY_UPDATED, object_id=str(advisory.pk)
    ).exists()


# ------------------------------------------------- redaction depuis l'ecran
def _formulaire(advisory, action, resume, statut=None):
    """Ce que le navigateur envoie depuis la page de redaction."""
    entrees = list(advisory.timeline.all())
    donnees = {
        "title": advisory.title,
        "summary": resume,
        "organization": advisory.organization_id or "",
        "product": advisory.product,
        "affected_versions": "",
        "fixed_versions": "",
        "description": "Description publique.",
        "impact": "",
        "solution": "",
        "workaround": "",
        "severity": advisory.severity,
        "cvss_score": advisory.cvss_score or "",
        "cvss_vector": advisory.cvss_vector,
        "cwe": advisory.cwe_id or "",
        "cve": advisory.cve_id or "",
        "credit": advisory.credit,
        "scheduled_for": "",
        "action": action,
        "timeline-TOTAL_FORMS": str(len(entrees) + 1),
        "timeline-INITIAL_FORMS": str(len(entrees)),
        "timeline-MIN_NUM_FORMS": "0",
        "timeline-MAX_NUM_FORMS": "1000",
    }
    if statut:
        donnees["target_status"] = statut
    for index, entree in enumerate(entrees):
        donnees[f"timeline-{index}-id"] = str(entree.pk)
        donnees[f"timeline-{index}-happened_on"] = entree.happened_on.isoformat()
        donnees[f"timeline-{index}-label"] = entree.label
        donnees[f"timeline-{index}-position"] = str(entree.position)
    vide = len(entrees)
    donnees[f"timeline-{vide}-id"] = ""
    donnees[f"timeline-{vide}-happened_on"] = ""
    donnees[f"timeline-{vide}-label"] = ""
    donnees[f"timeline-{vide}-position"] = "0"
    return donnees


def test_summary_typed_on_screen_reaches_the_publication(
    client_for, case_alpha, coordinator, analyst
):
    """Le resume saisi part avec la demande de publication.

    Contenu et cycle de vie etaient deux formulaires : la publication ne
    voyait que la base, et refusait un resume pourtant saisi a l'ecran.
    """
    advisory = create_advisory_from_case(case_alpha, analyst)
    advisory.case = None  # advisory autonome : publie depuis l'ecran
    advisory.status = AdvisoryStatus.APPROVED
    advisory.save(update_fields=["status", "case"])
    # Spec v2 : le redacteur saisit, le Coordinateur relit puis publie.
    client_for(analyst).post(
        f"/advisories/manage/{advisory.advisory_id}/",
        _formulaire(advisory, "save", "Un resume public saisi a l'instant."),
    )
    reponse = client_for(coordinator).post(
        f"/advisories/manage/{advisory.advisory_id}/",
        {"action": "publish"},
        follow=True,
    )

    advisory.refresh_from_db()
    assert advisory.summary == "Un resume public saisi a l'instant."
    assert advisory.status == AdvisoryStatus.PUBLISHED
    assert not [m for m in reponse.context["messages"] if m.level_tag == "error"]


def test_content_survives_a_refused_transition(client_for, case_alpha, coordinator, analyst):
    """Une transition refusee ne doit pas emporter la saisie avec elle."""
    advisory = create_advisory_from_case(case_alpha, analyst)
    advisory.case = None
    advisory.save(update_fields=["case"])
    client = client_for(analyst)

    reponse = client.post(
        f"/advisories/manage/{advisory.advisory_id}/",
        _formulaire(advisory, "publish", "Resume conserve malgre le refus."),
        follow=True,
    )

    advisory.refresh_from_db()
    assert advisory.summary == "Resume conserve malgre le refus."
    assert advisory.status == AdvisoryStatus.DRAFT
    # Le refus (ici : capacite de publication) n'emporte pas la saisie.
    erreurs = [str(m) for m in reponse.context["messages"] if m.level_tag == "error"]
    assert erreurs


def test_analyst_cannot_publish_from_the_screen(client_for, case_alpha, analyst):
    """Le bouton absent n'est pas la seule garde : la vue refuse aussi."""
    advisory = create_advisory_from_case(case_alpha, analyst)
    advisory.status = AdvisoryStatus.APPROVED
    advisory.save(update_fields=["status"])

    client_for(analyst).post(
        f"/advisories/manage/{advisory.advisory_id}/",
        _formulaire(advisory, "publish", "Resume public."),
        follow=True,
    )

    advisory.refresh_from_db()
    assert advisory.summary == "Resume public."
    assert advisory.status == AdvisoryStatus.APPROVED


# ------------------------------------------------------------ workflow v2
def test_reviewer_cannot_rewrite_the_draft(client_for, case_alpha, coordinator, analyst):
    """Le Coordinateur relit le brouillon : il ne le reecrit pas."""
    advisory = create_advisory_from_case(case_alpha, analyst, summary="Texte de l'analyste.")
    client_for(coordinator).post(
        f"/advisories/manage/{advisory.advisory_id}/",
        _formulaire(advisory, "save", "Texte du coordinateur."),
    )
    advisory.refresh_from_db()
    assert advisory.summary == "Texte de l'analyste."


def test_case_advisory_is_not_published_from_the_screen(
    client_for, case_alpha, coordinator, analyst
):
    """Un advisory de dossier ouvert se publie a l'etape 10, pas a cote."""
    advisory = create_advisory_from_case(case_alpha, analyst, summary="Resume public.")
    advisory.status = AdvisoryStatus.APPROVED
    advisory.save(update_fields=["status"])
    client_for(coordinator).post(
        f"/advisories/manage/{advisory.advisory_id}/", {"action": "publish"}
    )
    advisory.refresh_from_db()
    assert advisory.status == AdvisoryStatus.APPROVED


@pytest.mark.parametrize(
    "field,text",
    [
        ("summary", "Le serveur 10.0.0.12 etait expose."),
        ("description", "Voir https://portail.alpha.gov.bf/admin?id=1"),
        ("impact", "```\n' UNION SELECT password FROM users --\n```"),
    ],
)
def test_sanitization_detects_sensitive_content(case_alpha, analyst, field, text):
    from apps.disclosures.services import sanitization_issues

    advisory = create_advisory_from_case(case_alpha, analyst, summary="Resume public.")
    setattr(advisory, field, text)
    assert sanitization_issues(advisory)


def test_unsanitized_advisory_cannot_be_published(case_alpha, analyst, coordinator):
    advisory = create_advisory_from_case(
        case_alpha, analyst, summary="Serveur 192.168.1.10 vulnerable."
    )
    advisory.status = AdvisoryStatus.APPROVED
    advisory.save(update_fields=["status"])
    with pytest.raises(ValidationError, match="assaini"):
        publish_advisory(advisory, coordinator)


def test_author_cannot_publish_own_advisory(case_alpha, analyst):
    """Quatre yeux : l'auteur d'un advisory ne le publie pas lui-meme, meme
    s'il a entre-temps recu le role de Coordinateur."""
    advisory = create_advisory(Advisory(title="Advisory", summary="Resume public."), analyst)
    advisory.status = AdvisoryStatus.APPROVED
    advisory.save(update_fields=["status"])
    analyst.role = "NATIONAL_COORDINATOR"
    analyst.save(update_fields=["role"])
    with pytest.raises(PermissionDenied, match="quatre yeux"):
        publish_advisory(advisory, analyst)
