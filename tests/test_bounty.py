"""Tests du module Bug Bounty : proposition, revue, approbation, paiement."""

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

#ici
def test_proposer_cannot_approve_own_bounty(bounty_case, coordinator):
    bounty = propose_bounty(bounty_case, coordinator, amount=Decimal("200000"))
    with pytest.raises(PermissionDenied):
        approve_bounty(bounty, coordinator)

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
