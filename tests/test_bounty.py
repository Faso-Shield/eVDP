"""Tests du module Bug Bounty : proposition, revue, approbation, paiement."""

from datetime import date
from decimal import Decimal

import pytest
from django.core.exceptions import PermissionDenied, ValidationError

from apps.audit.models import AuditAction, AuditLog
from apps.bounty.models import BountyStatus, PaymentStatus
from apps.bounty.services import (
    approve_bounty,
    propose_bounty,
    record_payment,
    reject_bounty,
    review_bounty,
    suggested_amount,
)
from apps.coordination.services import set_severity
from apps.programs.models import Program, ProgramScope, RewardTier
from apps.vulnerabilities.constants import Severity

pytestmark = pytest.mark.django_db


# ------------------------------------------------------------------- matrice
def test_suggested_amount_comes_from_program_matrix(bounty_case, coordinator):
    set_severity(bounty_case, coordinator, severity=Severity.HIGH)
    amount, currency = suggested_amount(bounty_case)
    assert amount == Decimal("750000")
    assert currency == "XOF"


def test_no_suggestion_without_reward_policy(case_alpha):
    amount, _currency = suggested_amount(case_alpha)
    assert amount == Decimal("0")


def test_reward_amounts_are_configurable(bounty_program):
    tier = bounty_program.reward_policy.tier_for(Severity.CRITICAL)
    tier.max_amount = Decimal("3000000")
    tier.save()
    assert bounty_program.reward_policy.suggested_amount(Severity.CRITICAL) == Decimal(
        "3000000"
    )


# --------------------------------------------------------------- proposition
def test_propose_bounty_creates_pending_reward(bounty_case, analyst):
    bounty = propose_bounty(bounty_case, analyst, amount=Decimal("200000"))
    assert bounty.status == BountyStatus.PENDING
    assert bounty.proposed_amount == Decimal("200000")
    assert bounty.researcher_id == bounty_case.reporter_id
    assert AuditLog.objects.filter(action=AuditAction.BOUNTY_PROPOSED).exists()


def test_bounty_refused_on_vdp_program(case_alpha, analyst):
    """Un VDP n'ouvre pas droit a recompense : les deux workflows sont distincts."""
    with pytest.raises(ValidationError, match="Bug Bounty"):
        propose_bounty(case_alpha, analyst, amount=Decimal("100000"))


def test_researcher_cannot_propose_own_bounty(bounty_case, bounty_researcher):
    with pytest.raises(PermissionDenied):
        propose_bounty(bounty_case, bounty_researcher, amount=Decimal("999999"))


def test_negative_amount_is_rejected(bounty_case, analyst):
    with pytest.raises(ValidationError):
        propose_bounty(bounty_case, analyst, amount=Decimal("-1"))


# --------------------------------------------------------------- approbation
def test_analyst_cannot_approve(bounty_case, analyst):
    bounty = propose_bounty(bounty_case, analyst, amount=Decimal("200000"))
    with pytest.raises(PermissionDenied):
        approve_bounty(bounty, analyst)


def test_coordinator_approves_bounty(bounty_case, analyst, coordinator):
    bounty = propose_bounty(bounty_case, analyst, amount=Decimal("200000"))
    approve_bounty(bounty, coordinator, amount=Decimal("250000"), note="Impact confirme")
    bounty.refresh_from_db()

    assert bounty.status == BountyStatus.APPROVED
    assert bounty.approved_amount == Decimal("250000")
    assert bounty.decided_by == coordinator
    assert bounty.decided_at is not None
    assert AuditLog.objects.filter(action=AuditAction.BOUNTY_APPROVED).exists()


def test_rejection_blocks_further_transitions(bounty_case, analyst, coordinator):
    bounty = propose_bounty(bounty_case, analyst, amount=Decimal("200000"))
    reject_bounty(bounty, coordinator, note="Hors perimetre")
    bounty.refresh_from_db()

    assert bounty.status == BountyStatus.REJECTED
    assert bounty.is_final is True
    with pytest.raises(ValidationError):
        approve_bounty(bounty, coordinator)


def test_out_of_matrix_amount_is_flagged(bounty_case, analyst, coordinator):
    set_severity(bounty_case, coordinator, severity=Severity.LOW)
    bounty = propose_bounty(bounty_case, analyst, amount=Decimal("50000"))
    approve_bounty(bounty, coordinator, amount=Decimal("5000000"))
    bounty.refresh_from_db()

    assert bounty.within_policy() is False
    assert (
        AuditLog.objects.filter(
            action=AuditAction.BOUNTY_APPROVED, metadata__warning__isnull=False
        ).exists()
        or AuditLog.objects.filter(action=AuditAction.BOUNTY_APPROVED).count() >= 2
    )


# ------------------------------------------------------------------- revue
def test_review_moves_bounty_under_review(bounty_case, analyst, coordinator):
    bounty = propose_bounty(bounty_case, analyst, amount=Decimal("200000"))
    review_bounty(bounty, coordinator, "APPROVE", comment="Favorable")
    bounty.refresh_from_db()

    assert bounty.status == BountyStatus.UNDER_REVIEW
    assert bounty.reviews.count() == 1


# ---------------------------------------------------------------- paiement
def test_payment_requires_approval(bounty_case, analyst, coordinator):
    bounty = propose_bounty(bounty_case, analyst, amount=Decimal("200000"))
    with pytest.raises(ValidationError, match="approuvee"):
        record_payment(bounty, coordinator)


def test_payment_records_trace_without_real_transfer(bounty_case, analyst, coordinator):
    bounty = propose_bounty(bounty_case, analyst, amount=Decimal("200000"))
    approve_bounty(bounty, coordinator)
    payment = record_payment(bounty, coordinator, reference="VIR-2026-001")
    bounty.refresh_from_db()

    assert bounty.status == BountyStatus.PAID
    assert payment.status == PaymentStatus.RECORDED
    assert payment.settled_at is None  # aucun versement reel n'est execute
    assert AuditLog.objects.filter(action=AuditAction.BOUNTY_PAID).exists()


def test_analyst_cannot_record_payment(bounty_case, analyst, coordinator):
    bounty = propose_bounty(bounty_case, analyst, amount=Decimal("200000"))
    approve_bounty(bounty, coordinator)
    with pytest.raises(PermissionDenied):
        record_payment(bounty, analyst)


def test_paid_bounty_updates_researcher_totals(bounty_case, analyst, coordinator):
    bounty = propose_bounty(bounty_case, analyst, amount=Decimal("200000"))
    approve_bounty(bounty, coordinator)
    record_payment(bounty, coordinator)

    profile = bounty_case.reporter.researcher_profile
    profile.refresh_from_db()
    assert profile.total_rewards == Decimal("200000.00")


# ---------------------------------------------------------------- isolation
def test_researcher_cannot_see_other_bounty(
    client_for, bounty_case, analyst, coordinator, researcher_a
):
    bounty = propose_bounty(bounty_case, analyst, amount=Decimal("200000"))
    approve_bounty(bounty, coordinator)

    client = client_for(researcher_a)
    assert client.get(f"/bounties/{bounty.pk}/").status_code == 404


def test_researcher_sees_own_bounty(client_for, bounty_case, analyst, bounty_researcher):
    bounty = propose_bounty(bounty_case, analyst, amount=Decimal("200000"))
    client = client_for(bounty_researcher)
    assert client.get(f"/bounties/{bounty.pk}/").status_code == 200


# -------------------------------------------------- recompense variable par actif
def test_asset_tier_overrides_program_default(bounty_program):
    """Un actif sensible peut valoir davantage que la grille generale."""
    api = bounty_program.scopes.get(identifier="api.exemple.bf")
    policy = bounty_program.reward_policy
    RewardTier.objects.create(
        policy=policy,
        scope=api,
        severity=Severity.CRITICAL,
        min_amount=Decimal("2000000"),
        max_amount=Decimal("5000000"),
    )
    assert policy.suggested_amount(Severity.CRITICAL) == Decimal("2000000")
    assert policy.suggested_amount(Severity.CRITICAL, api) == Decimal("5000000")


def test_asset_without_tier_falls_back_to_default(bounty_program):
    """On ne saisit une ligne par actif que la ou le montant differe."""
    vitrine = bounty_program.scopes.get(identifier="vitrine.exemple.bf")
    policy = bounty_program.reward_policy
    assert policy.suggested_amount(Severity.HIGH, vitrine) == Decimal("750000")


def test_suggestion_follows_the_case_asset(bounty_case, coordinator):
    """Le montant propose suit l'actif retenu au triage."""
    api = bounty_case.program.scopes.get(identifier="api.exemple.bf")
    RewardTier.objects.create(
        policy=bounty_case.program.reward_policy,
        scope=api,
        severity=Severity.HIGH,
        min_amount=Decimal("900000"),
        max_amount=Decimal("1800000"),
    )
    set_severity(bounty_case, coordinator, severity=Severity.HIGH)

    amount, _currency = suggested_amount(bounty_case)
    assert amount == Decimal("750000"), "sans actif, la grille par defaut s'applique"

    bounty_case.scope = api
    bounty_case.save(update_fields=["scope"])
    amount, _currency = suggested_amount(bounty_case)
    assert amount == Decimal("1800000")


def test_tier_rejects_asset_of_another_program(bounty_program, vdp_program):
    """Un palier ne peut pas viser le perimetre d'un autre programme."""
    etranger = ProgramScope.objects.create(
        program=vdp_program, identifier="autre.exemple.bf"
    )
    tier = RewardTier(
        policy=bounty_program.reward_policy,
        scope=etranger,
        severity=Severity.LOW,
        min_amount=Decimal("0"),
        max_amount=Decimal("1000"),
    )
    with pytest.raises(ValidationError, match="autre programme"):
        tier.full_clean()


def test_tier_rejects_out_of_scope_asset(bounty_program):
    """Une cible exclue du perimetre n'ouvre pas droit a recompense."""
    exclu = ProgramScope.objects.create(
        program=bounty_program, identifier="shop.exemple.bf", in_scope=False
    )
    tier = RewardTier(
        policy=bounty_program.reward_policy,
        scope=exclu,
        severity=Severity.LOW,
        min_amount=Decimal("0"),
        max_amount=Decimal("1000"),
    )
    with pytest.raises(ValidationError, match="hors perimetre"):
        tier.full_clean()


# ------------------------------------------- acces reserve aux comptes verifies
def test_unverified_researcher_cannot_join_bounty_program(
    bounty_program, bounty_researcher, organization
):
    """Un Bug Bounty exigeant un email verifie refuse la soumission."""
    from apps.reports.services import submit_report

    from .conftest import build_report

    bounty_researcher.email_verified = False
    bounty_researcher.save(update_fields=["email_verified"])

    with pytest.raises(ValidationError, match="adresse email verifiee"):
        submit_report(
            build_report(bounty_researcher, organization, bounty_program),
            reporter=bounty_researcher,
        )


def test_anonymous_report_refused_when_verification_required(
    bounty_program, organization
):
    """Sans compte, aucune adresse n'est verifiee : le programme refuse."""
    from apps.reports.services import submit_report

    from .conftest import build_report

    report = build_report(None, organization, bounty_program)
    report.reporter = None
    report.is_anonymous = True
    with pytest.raises(ValidationError, match="chercheur identifie"):
        submit_report(report)


def test_verified_researcher_is_admitted(bounty_program, bounty_researcher, organization):
    """Le cas nominal reste inchange : un compte verifie passe."""
    from apps.reports.services import submit_report

    from .conftest import build_report

    case = submit_report(
        build_report(bounty_researcher, organization, bounty_program),
        reporter=bounty_researcher,
    )
    assert case.program_id == bounty_program.id


def test_vdp_may_waive_the_verification_requirement(
    vdp_program, researcher_a, organization
):
    """Hors Bug Bounty, l'exigence reste une politique propre au programme."""
    from apps.reports.services import submit_report

    from .conftest import build_report

    vdp_program.requires_verified_email = False
    vdp_program.save(update_fields=["requires_verified_email"])
    researcher_a.email_verified = False
    researcher_a.save(update_fields=["email_verified"])

    case = submit_report(
        build_report(researcher_a, organization, vdp_program), reporter=researcher_a
    )
    assert case.program_id == vdp_program.id


def test_anonymous_vdp_report_still_accepted(vdp_program, organization):
    """Le signalement anonyme reste possible sur un VDP qui l'autorise.

    C'est une promesse centrale de la plateforme : la verification d'adresse
    ne doit pas la supprimer par effet de bord.
    """
    from apps.reports.services import submit_report

    from .conftest import build_report

    assert vdp_program.allows_anonymous_reports
    assert vdp_program.requires_verified_email, "defaut du modele"

    report = build_report(None, organization, vdp_program)
    report.reporter = None
    report.is_anonymous = True
    case = submit_report(report)
    assert case.program_id == vdp_program.id


def test_bug_bounty_cannot_be_configured_without_identification(bounty_program):
    """Invariant : pas de recompense sans chercheur identifie et verifie."""
    bounty_program.allows_anonymous_reports = True
    with pytest.raises(ValidationError, match="signalement anonyme"):
        bounty_program.full_clean()

    bounty_program.allows_anonymous_reports = False
    bounty_program.requires_verified_email = False
    with pytest.raises(ValidationError, match="adresse email verifiee"):
        bounty_program.full_clean()


def test_bounty_refused_to_unverified_researcher(bounty_case, analyst):
    """Second garde-fou : le programme a pu devenir exigeant apres coup."""
    bounty_case.reporter.email_verified = False
    bounty_case.reporter.save(update_fields=["email_verified"])

    with pytest.raises(ValidationError, match="verifie son adresse email"):
        propose_bounty(bounty_case, analyst, amount=Decimal("100000"))


def test_bug_bounty_never_advertises_anonymous_reports(bounty_program):
    """Le reglage brut peut mentir : la regle affichee est celle qui s'applique.

    `Program.clean` ne garde que les enregistrements passes par un
    formulaire. Une ligne ecrite en masse pourrait donc porter
    `allows_anonymous_reports=True` sur un Bug Bounty et annoncer sur sa
    fiche un signalement anonyme que l'envoi refusera.
    """
    Program.objects.filter(pk=bounty_program.pk).update(allows_anonymous_reports=True)
    bounty_program.refresh_from_db()

    assert bounty_program.allows_anonymous_reports
    assert not bounty_program.accepts_anonymous_reports
    assert "chercheur identifie" in bounty_program.reporter_rejection()


def test_program_dates_are_still_validated(bounty_program):
    """L'invariant Bug Bounty ne doit pas avoir evince les autres controles."""
    bounty_program.starts_on = date(2026, 6, 1)
    bounty_program.ends_on = date(2026, 5, 1)
    with pytest.raises(ValidationError, match="date de fin"):
        bounty_program.full_clean()


def test_submit_page_announces_the_refusal_to_a_visitor_without_account(
    client, bounty_program
):
    """Le refus est annonce a l'arrivee, pas apres redaction du rapport."""
    response = client.get(f"/report/?program={bounty_program.slug}")
    page = response.content.decode()

    assert "chercheur identifie" in page
    assert "Vous pouvez signaler sans compte" not in page


def test_program_page_sends_a_visitor_without_account_to_the_login(
    client, bounty_program
):
    """Le bouton d'appel ne mene pas a un formulaire qui refusera l'envoi."""
    page = client.get(f"/programs/{bounty_program.slug}/").content.decode()

    assert "Se connecter pour signaler" in page
    assert "%3Fprogram%3D" in page
