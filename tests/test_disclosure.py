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

from .conftest import advance

pytestmark = pytest.mark.django_db


def build_advisory(case, actor, **overrides):
    return create_advisory_from_case(
        case, actor, summary="Resume public assaini.", **overrides
    )


def approved_advisory(actor, organization=None, **overrides):
    """Advisory approuve sans dossier source (redige a la main).

    Un advisory issu d'un dossier ne se publie que par l'etape 10 du
    workflow ; les tests du cycle de vie de l'advisory lui-meme partent donc
    d'un advisory autonome.
    """
    data = {"title": "Advisory autonome", "summary": "Resume public assaini."}
    data.update(overrides)
    advisory = create_advisory(Advisory(organization=organization, **data), actor)
    advisory.status = AdvisoryStatus.APPROVED
    advisory.save(update_fields=["status"])
    return advisory


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
    advisory = approved_advisory(analyst)
    publish_advisory(advisory, coordinator)
    advisory.refresh_from_db()

    assert advisory.status == AdvisoryStatus.PUBLISHED
    assert advisory.published_at is not None
    assert advisory.is_published is True
    assert AuditLog.objects.filter(action=AuditAction.ADVISORY_PUBLISHED).exists()


def test_retraction_requires_reason(case_alpha, coordinator, analyst):
    advisory = approved_advisory(analyst)
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
    advisory = approved_advisory(analyst)

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

    advisory = approved_advisory(analyst)

    _appliquer_action(_manage_request(rf, coordinator, "publish"), advisory)
    advisory.refresh_from_db()

    assert advisory.status == AdvisoryStatus.PUBLISHED
    assert advisory.is_published is True


def test_appliquer_action_publish_refuses_missing_capability(
    rf, case_alpha, coordinator, analyst
):
    from apps.disclosures.views import _appliquer_action

    advisory = approved_advisory(analyst)

    _appliquer_action(_manage_request(rf, analyst, "publish"), advisory)
    advisory.refresh_from_db()

    assert advisory.status == AdvisoryStatus.APPROVED  # inchange
    assert advisory.is_published is False


def test_appliquer_action_retracts(rf, case_alpha, coordinator, analyst):
    from apps.disclosures.views import _appliquer_action

    advisory = approved_advisory(analyst)
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

    advisory = approved_advisory(analyst)

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

    advisory = approved_advisory(analyst)

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
    advisory = approved_advisory(analyst)
    publish_advisory(advisory, coordinator)

    response = client.get(f"/advisories/{advisory.advisory_id}/")
    assert response.status_code == 200
    assert advisory.title in response.content.decode()


def test_public_advisory_does_not_expose_case_id(client, case_alpha, coordinator, analyst):
    """Principe 5 : ne jamais exposer les donnees internes du case."""
    advance(case_alpha, CaseStatus.CLOSED)
    advisory = case_alpha.advisories.get()
    assert advisory.is_published

    content = client.get(f"/advisories/{advisory.advisory_id}/").content.decode()
    assert case_alpha.case_id not in content


def test_timeline_copied_only_from_public_events(case_alpha, analyst):
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
    advisory = approved_advisory(analyst)
    client = client_for(coordinator)

    reponse = client.post(
        f"/advisories/manage/{advisory.advisory_id}/",
        _formulaire(advisory, "publish", "Un resume public saisi a l'instant."),
        follow=True,
    )

    advisory.refresh_from_db()
    assert advisory.summary == "Un resume public saisi a l'instant."
    assert advisory.status == AdvisoryStatus.PUBLISHED
    assert not [m for m in reponse.context["messages"] if m.level_tag == "error"]


def test_content_survives_a_refused_transition(client_for, case_alpha, coordinator, analyst):
    """Une transition refusee ne doit pas emporter la saisie avec elle."""
    advisory = create_advisory(
        Advisory(title="Advisory autonome", summary="Resume initial."), analyst
    )
    client = client_for(coordinator)

    reponse = client.post(
        f"/advisories/manage/{advisory.advisory_id}/",
        _formulaire(advisory, "publish", "Resume conserve malgre le refus."),
        follow=True,
    )

    advisory.refresh_from_db()
    assert advisory.summary == "Resume conserve malgre le refus."
    assert advisory.status == AdvisoryStatus.DRAFT
    # Le refus porte sur l'etat du document, pas sur un resume qui manquerait.
    erreurs = [str(m) for m in reponse.context["messages"] if m.level_tag == "error"]
    assert erreurs and "publication" in " ".join(erreurs).lower()


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


# ------------------------------------------------------- workflow v2 (etapes 9-10)
def test_coordinator_can_no_longer_draft_advisory(case_alpha, coordinator):
    """Seul l'analyste redige ; le coordinateur relit et publie."""
    with pytest.raises(PermissionDenied):
        build_advisory(case_alpha, coordinator)


def test_submit_advisory_moves_draft_to_review(case_alpha):
    """Etape 9 : soumettre l'advisory le passe en relecture."""
    case = advance(case_alpha, CaseStatus.ADVISORY_REVIEW)
    advisory = case.advisories.get()
    assert case.status == CaseStatus.ADVISORY_REVIEW
    assert advisory.status == AdvisoryStatus.IN_REVIEW
    assert advisory.is_published is False


def test_publish_and_close_publishes_advisory_and_closes_case(case_alpha):
    """Etape 10 : publier et cloturer publie l'advisory et clot le dossier."""
    case = advance(case_alpha, CaseStatus.CLOSED)
    advisory = case.advisories.get()
    assert case.status == CaseStatus.CLOSED
    assert case.is_published is True
    assert case.closed_at is not None
    assert advisory.status == AdvisoryStatus.PUBLISHED
    assert advisory.published_at is not None


def test_publish_and_close_requires_another_person(case_alpha):
    """Quatre yeux : l'auteur de l'advisory soumis ne peut pas le publier."""
    from apps.accounts.roles import Role
    from apps.coordination.services import perform_action
    from apps.coordination.workflow import OutOfScope, current_owner_ids

    from .conftest import workflow_actor

    case = advance(case_alpha, CaseStatus.ADVISORY_REVIEW)
    author = workflow_actor("analyst")
    # L'auteur recoit la capacite de publier : la regle porte sur la
    # personne, pas seulement sur le role. Exclu des responsables de
    # l'etape 10, il n'a meme plus le dossier dans son perimetre.
    author.role = Role.NATIONAL_COORDINATOR
    author.save(update_fields=["role"])
    assert author.pk not in current_owner_ids(case)
    assert workflow_actor("coordinator").pk in current_owner_ids(case)
    with pytest.raises(OutOfScope):
        perform_action(
            case,
            "publish_and_close",
            author,
            data={"comment": "Relu.", "review_done": True},
        )
    case.refresh_from_db()
    assert case.status == CaseStatus.ADVISORY_REVIEW


@pytest.mark.parametrize(
    "field,value,expected",
    [
        ("description", "Serveur vulnerable : 10.12.4.7.", "adresse IP"),
        ("description", "Voir https://intranet.alpha.local/admin.", "URL sensible"),
        ("solution", "Rejouer :\n```\nGET /?id=1 OR 1=1\n```", "preuve de concept"),
    ],
)
def test_unsanitized_draft_is_refused(case_alpha, analyst, field, value, expected):
    """Un brouillon avec IP, URL interne ou bloc de code n'est pas assaini."""
    from apps.coordination.workflow import advisory_sanitization_issues

    advisory = build_advisory(case_alpha, analyst)
    assert advisory_sanitization_issues(advisory) == []
    setattr(advisory, field, value)
    issues = advisory_sanitization_issues(advisory)
    assert any(expected in issue for issue in issues)


def test_unsanitized_draft_blocks_submission(case_alpha):
    """Etape 9 : le bouton reste bloque tant que le brouillon n'est pas assaini."""
    from apps.coordination.services import perform_action
    from apps.coordination.workflow import TransitionNotAllowed, working_advisory

    from .conftest import _prepare_step, workflow_actor

    case = advance(case_alpha, CaseStatus.FIX_VERIFIED)
    _prepare_step(case, CaseStatus.FIX_VERIFIED)
    advisory = working_advisory(case)
    advisory.description = "Hote touche : 192.168.1.20"
    advisory.save(update_fields=["description"])

    with pytest.raises(TransitionNotAllowed) as excinfo:
        perform_action(case, "submit_advisory", workflow_actor("analyst"))
    assert any("adresse IP" in item for item in excinfo.value.missing)
    case.refresh_from_db()
    assert case.status == CaseStatus.FIX_VERIFIED


# ------------------------------------------------ publication hors workflow
def test_case_advisory_cannot_be_published_beside_step_ten(case_alpha, coordinator, analyst):
    """Un advisory issu d'un dossier se publie par « Publier et cloturer ».

    Sinon la relecture, le controle du credit, la fin de la branche prime et
    la regle des quatre yeux de l'etape 10 seraient contournes.
    """
    advisory = build_advisory(case_alpha, analyst)
    advisory.status = AdvisoryStatus.APPROVED
    advisory.save(update_fields=["status"])
    with pytest.raises(ValidationError, match="Publier et"):
        publish_advisory(advisory, coordinator)
    advisory.refresh_from_db()
    assert advisory.is_published is False


def test_coordinator_reaches_the_manage_page(client_for, coordinator, analyst):
    """Matrice v2 : acces complet du coordinateur au brouillon d'advisory."""
    advisory = approved_advisory(analyst)
    client = client_for(coordinator)
    assert client.get(reverse("disclosures:manage_list")).status_code == 200
    assert (
        client.get(reverse("disclosures:manage", args=[advisory.advisory_id])).status_code
        == 200
    )
