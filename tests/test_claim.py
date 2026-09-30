"""Prise en charge d'un dossier et transfert a un collegue.

L'assignation manuelle (capacite ASSIGN_CASE) est remplacee par un
mecanisme lie au workflow : le responsable de l'etape en cours « prend en
charge » le dossier, qui sort alors de la file de ses collegues du meme
role ; il peut ensuite le « transferer » a l'un d'eux. L'attribution suit
le dossier sur les etapes de ce meme role et ne gene jamais les autres.
"""

import pytest
from django.core.exceptions import PermissionDenied, ValidationError
from django.urls import reverse

from apps.accounts.roles import Capability, Role
from apps.audit.models import AuditAction, AuditLog
from apps.coordination.models import Case
from apps.coordination.services import claim_case, transfer_case
from apps.coordination.workflow import CaseStatus, claim_holder, current_owner_ids
from apps.notifications.models import Notification, NotificationKind

from .conftest import advance, make_user

pytestmark = pytest.mark.django_db


@pytest.fixture
def analyst_b(db):
    return make_user("analyste-b@test.bf", Role.CSIRT_ANALYST)


@pytest.fixture
def analysed_case(case_alpha):
    return advance(case_alpha, CaseStatus.IN_ANALYSIS)


def _page(client, case):
    return client.get(reverse("coordination:case_detail", args=[case.case_id]))


# ------------------------------------------------------------ capacite
def test_nobody_assigns_cases_anymore():
    assert "ASSIGN_CASE" not in Capability.values


# ------------------------------------------------------ prise en charge
def test_claim_removes_the_case_from_colleagues(analyst, analyst_b, analysed_case):
    assert {analyst.pk, analyst_b.pk} <= current_owner_ids(analysed_case)

    claim_case(analysed_case, analyst)

    assert claim_holder(analysed_case) == analyst
    assert current_owner_ids(analysed_case) == {analyst.pk}
    assert analysed_case in Case.objects.visible_to(analyst)
    assert analysed_case not in Case.objects.visible_to(analyst_b)
    assert AuditLog.objects.filter(
        action=AuditAction.CASE_ASSIGNED, object_id=str(analysed_case.pk)
    ).exists()


def test_only_a_step_owner_can_claim(triager, coordinator, analysed_case):
    for outsider in (triager, coordinator):
        with pytest.raises(PermissionDenied):
            claim_case(analysed_case, outsider)


def test_a_claimed_case_cannot_be_claimed_again(analyst, analysed_case):
    claim_case(analysed_case, analyst)
    with pytest.raises(ValidationError):
        claim_case(analysed_case, analyst)


def test_claim_follows_the_case_across_the_same_role(analyst, analyst_b, analysed_case):
    """L'analyste qui a pris le dossier a l'etape 3 le retrouve a l'etape 5."""
    claim_case(analysed_case, analyst)
    advance(analysed_case, CaseStatus.VALIDATED)
    assert claim_holder(analysed_case) == analyst
    assert analysed_case not in Case.objects.visible_to(analyst_b)


def test_claim_never_blocks_another_role(analyst, coordinator, coordinator_b, analysed_case):
    claim_case(analysed_case, analyst)
    advance(analysed_case, CaseStatus.VALIDATION_PENDING)
    # Etape 4 : tous les coordinateurs en sont responsables, personne ne l'a pris.
    assert claim_holder(analysed_case) is None
    assert {coordinator.pk, coordinator_b.pk} <= current_owner_ids(analysed_case)


def test_claimed_case_no_longer_notifies_colleagues(analyst, analyst_b, case_alpha):
    """Apres prise en charge, les avis d'etape ne vont plus qu'au titulaire."""
    advance(case_alpha, CaseStatus.IN_ANALYSIS)
    claim_case(case_alpha, analyst)
    advance(case_alpha, CaseStatus.VALIDATION_PENDING)
    Notification.objects.all().delete()
    advance(case_alpha, CaseStatus.VALIDATED)

    notified = set(
        Notification.objects.filter(
            case=case_alpha, kind=NotificationKind.ACTION_REQUIRED
        ).values_list("recipient_id", flat=True)
    )
    assert analyst.pk in notified
    assert analyst_b.pk not in notified


# --------------------------------------------------------------- transfert
def test_transfer_hands_the_case_to_a_colleague(analyst, analyst_b, analysed_case):
    claim_case(analysed_case, analyst)
    transfer_case(analysed_case, analyst, analyst_b, note="Conges")

    assert claim_holder(analysed_case) == analyst_b
    assert analysed_case not in Case.objects.visible_to(analyst)
    assert Notification.objects.filter(
        recipient=analyst_b, kind=NotificationKind.CASE_ASSIGNED, case=analysed_case
    ).exists()


def test_transfer_stays_within_the_same_role(analyst, triager, coordinator, analysed_case):
    claim_case(analysed_case, analyst)
    for outsider in (triager, coordinator):
        with pytest.raises(ValidationError):
            transfer_case(analysed_case, analyst, outsider)


def test_only_the_holder_transfers(analyst, analyst_b, analysed_case):
    with pytest.raises(PermissionDenied):
        transfer_case(analysed_case, analyst, analyst_b)  # personne n'a pris le dossier


# ---------------------------------------------------------------- interface
def test_case_page_offers_the_claim_button(client_for, analyst, analyst_b, analysed_case):
    content = _page(client_for(analyst), analysed_case).content.decode()
    assert "Prendre en charge" in content
    assert "Assignation" not in content


def test_claim_and_transfer_through_the_web(client_for, analyst, analyst_b, analysed_case):
    client = client_for(analyst)
    response = client.post(reverse("coordination:claim", args=[analysed_case.case_id]))
    assert response.status_code == 302
    assert claim_holder(analysed_case) == analyst

    content = _page(client, analysed_case).content.decode()
    assert "Vous avez pris ce dossier en charge" in content
    assert "Transférer à un collègue" in content

    response = client.post(
        reverse("coordination:transfer", args=[analysed_case.case_id]),
        {"target": analyst_b.pk, "note": "Relais"},
    )
    assert response.status_code == 302
    assert claim_holder(analysed_case) == analyst_b
    assert _page(client, analysed_case).status_code == 404


def test_claim_via_get_is_rejected(client_for, analyst, analysed_case):
    response = client_for(analyst).get(
        reverse("coordination:claim", args=[analysed_case.case_id])
    )
    assert response.status_code == 405


# ------------------------------------------------ badge de participant
def _badge(case, user):
    return case.participants.get(user=user).participant_role


def test_claim_badge_reflects_the_real_role(case_alpha, triager, analyst):
    """Toute prise en charge affichait « Analyste CSIRT »."""
    from apps.coordination.constants import ParticipantRole

    claim_case(case_alpha, triager)
    assert _badge(case_alpha, triager) == ParticipantRole.TRIAGER

    advance(case_alpha, CaseStatus.VALIDATED)
    claim_case(case_alpha, analyst)
    assert _badge(case_alpha, analyst) == ParticipantRole.ANALYST


def test_migration_fixes_badges_already_stored(case_alpha, triager, analyst, coordinator):
    import importlib

    from django.apps import apps

    from apps.coordination.constants import ParticipantRole
    from apps.coordination.services import add_participant

    for user in (triager, analyst, coordinator):
        add_participant(case_alpha, user, ParticipantRole.ANALYST)
    migration = importlib.import_module(
        "apps.coordination.migrations.0009_role_participant_agent_de_triage"
    )
    migration.corriger_badges(apps, None)

    assert _badge(case_alpha, triager) == ParticipantRole.TRIAGER
    assert _badge(case_alpha, analyst) == ParticipantRole.ANALYST
    assert _badge(case_alpha, coordinator) == ParticipantRole.COORDINATOR


# ------------------------------------------------ attribution automatique
@pytest.fixture
def auto_claim_on(settings):
    settings.EVDP = {**settings.EVDP, "AUTO_CLAIM": True}


def _new_case(reporter, organization):
    from .conftest import build_report, submit

    return submit(build_report(reporter, organization))


def test_new_case_goes_to_the_least_loaded_triager(
    auto_claim_on, triager, researcher_a, researcher_b, organization, sla_policy
):
    busy = triager
    free = make_user("triage-2@test.bf", Role.TRIAGER)
    first = _new_case(researcher_a, organization)
    assert claim_holder(first) is not None
    # Le premier dossier occupe l'un des deux : le suivant va a l'autre.
    loaded = claim_holder(first)
    second = _new_case(researcher_b, organization)
    assert claim_holder(second) == ({busy, free} - {loaded}).pop()

    notified = set(
        Notification.objects.filter(
            case=second, kind=NotificationKind.ACTION_REQUIRED
        ).values_list("recipient_id", flat=True)
    )
    assert notified == {claim_holder(second).pk}
    assert second.participants.get(user=claim_holder(second)).participant_role == "TRIAGER"


def test_equal_load_goes_to_whoever_waited_longest(
    auto_claim_on, triager, researcher_a, researcher_b, organization, sla_policy
):
    from apps.coordination.models import CaseAssignment

    other = make_user("triage-2@test.bf", Role.TRIAGER)
    first = _new_case(researcher_a, organization)
    # Dossier clos : la charge redevient egale, reste l'anciennete.
    Case.objects.filter(pk=first.pk).update(status=CaseStatus.REJECTED)
    last_served = claim_holder(first)
    assert CaseAssignment.objects.filter(user=last_served).exists()
    second = _new_case(researcher_b, organization)
    assert claim_holder(second) == ({triager, other} - {last_served}).pop()


def test_validated_case_goes_to_the_least_loaded_analyst(
    auto_claim_on, settings, case_alpha, case_beta, analyst, coordinator
):
    from apps.coordination.models import CaseAssignment
    from apps.coordination.services import auto_claim

    settings.EVDP = {**settings.EVDP, "AUTO_CLAIM": False}
    advance(case_alpha, CaseStatus.VALIDATED)
    case_alpha.assignments.update(is_active=False)
    free = make_user("analyste-2@test.bf", Role.CSIRT_ANALYST)
    # `analyst` porte deja un dossier en cours.
    CaseAssignment.objects.create(case=case_beta, user=analyst, is_active=True)

    settings.EVDP = {**settings.EVDP, "AUTO_CLAIM": True}
    assert auto_claim(case_alpha) == [free]
    assert claim_holder(case_alpha) == free
    assert coordinator.pk not in set(
        case_alpha.assignments.filter(is_active=True).values_list("user_id", flat=True)
    )


def test_auto_claim_can_be_disabled(triager, researcher_a, organization, sla_policy):
    case = _new_case(researcher_a, organization)
    assert claim_holder(case) is None
