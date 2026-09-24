"""Tests du module Bug Bounty : proposition, revue, approbation, paiement."""

from datetime import date
from decimal import Decimal

import pytest
from django.core.exceptions import PermissionDenied, ValidationError
from django.urls import reverse

from apps.audit.models import AuditAction, AuditLog
from apps.bounty.models import Bounty, BountyStatus, PaymentStatus, ReviewDecision
from apps.bounty.services import (
    approve_bounty,
    budget_status,
    confirm_settlement,
    mark_payment_failed,
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


def test_proposer_cannot_approve_own_bounty(bounty_case, coordinator):
    bounty = propose_bounty(bounty_case, coordinator, amount=Decimal("200000"))
    with pytest.raises(PermissionDenied):
        approve_bounty(bounty, coordinator)


def test_approve_button_hidden_for_proposer(client_for, bounty_case, coordinator):
    bounty = propose_bounty(bounty_case, coordinator, amount=Decimal("200000"))
    client = client_for(coordinator)
    response = client.get(reverse("bounty:detail", args=[bounty.pk]))
    assert response.context["can_approve"] is False


def test_approve_button_visible_for_other_coordinator(
    client_for, bounty_case, coordinator, coordinator_b
):
    bounty = propose_bounty(bounty_case, coordinator, amount=Decimal("200000"))
    client = client_for(coordinator_b)
    response = client.get(reverse("bounty:detail", args=[bounty.pk]))
    assert response.context["can_approve"] is True


def test_proposer_cannot_reject_own_bounty(bounty_case, coordinator):
    bounty = propose_bounty(bounty_case, coordinator, amount=Decimal("200000"))
    with pytest.raises(PermissionDenied):
        reject_bounty(bounty, coordinator)


def test_another_coordinator_can_approve(bounty_case, coordinator, coordinator_b):
    """La separation vise le proposant, pas le role : un pair peut statuer."""
    bounty = propose_bounty(bounty_case, coordinator, amount=Decimal("200000"))
    approve_bounty(bounty, coordinator_b)
    bounty.refresh_from_db()

    assert bounty.status == BountyStatus.APPROVED
    assert bounty.decided_by == coordinator_b


def test_rejection_blocks_further_transitions(bounty_case, analyst, coordinator):
    bounty = propose_bounty(bounty_case, analyst, amount=Decimal("200000"))
    reject_bounty(bounty, coordinator, note="Hors perimetre")
    bounty.refresh_from_db()

    assert bounty.status == BountyStatus.REJECTED
    assert bounty.is_final is True


# --------------------------------------------------------- mutations en GET
# Regression : approve/reject n'exigeaient aucune methode HTTP particuliere,
# et BountyDecisionForm a tous ses champs facultatifs - un simple GET (donc
# hors protection CSRF, qui ne couvre que les methodes non sures) suffisait
# a declencher la decision. Meme classe de probleme que celle deja corrigee
# sur le portefeuille (payout_method_remove/set_primary).
def test_approve_via_get_is_rejected(client_for, bounty_case, coordinator, coordinator_b):
    bounty = propose_bounty(bounty_case, coordinator, amount=Decimal("200000"))
    client = client_for(coordinator_b)
    response = client.get(reverse("bounty:approve", args=[bounty.pk]))
    assert response.status_code == 405
    bounty.refresh_from_db()
    assert bounty.status == BountyStatus.PENDING


def test_reject_via_get_is_rejected(client_for, bounty_case, coordinator, coordinator_b):
    bounty = propose_bounty(bounty_case, coordinator, amount=Decimal("200000"))
    client = client_for(coordinator_b)
    response = client.get(reverse("bounty:reject", args=[bounty.pk]))
    assert response.status_code == 405
    bounty.refresh_from_db()
    assert bounty.status == BountyStatus.PENDING


def test_review_via_get_is_rejected(client_for, bounty_case, analyst):
    bounty = propose_bounty(bounty_case, analyst, amount=Decimal("200000"))
    client = client_for(analyst)
    response = client.get(reverse("bounty:review", args=[bounty.pk]))
    assert response.status_code == 405


def test_payment_via_get_is_rejected(client_for, bounty_case, analyst, coordinator):
    bounty = propose_bounty(bounty_case, analyst, amount=Decimal("200000"))
    approve_bounty(bounty, coordinator)
    client = client_for(coordinator)
    response = client.get(reverse("bounty:payment", args=[bounty.pk]))
    assert response.status_code == 405
    bounty.refresh_from_db()
    assert bounty.status == BountyStatus.APPROVED
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
    with pytest.raises(ValidationError, match="approuvée"):
        record_payment(bounty, coordinator)


def test_payment_records_trace_without_real_transfer(bounty_case, analyst, coordinator):
    bounty = propose_bounty(bounty_case, analyst, amount=Decimal("200000"))
    approve_bounty(bounty, coordinator)
    payment = record_payment(bounty, coordinator, reference="VIR-2026-001")
    bounty.refresh_from_db()

    # PAYMENT_PENDING, pas PAID : un simple enregistrement n'est jamais un
    # statut positif tant qu'aucune preuve ne confirme le reglement (voir
    # confirm_settlement, plus bas).
    assert bounty.status == BountyStatus.PAYMENT_PENDING
    assert payment.status == PaymentStatus.RECORDED
    assert payment.settled_at is None  # aucun versement reel n'est execute
    assert AuditLog.objects.filter(action=AuditAction.BOUNTY_PAYMENT_RECORDED).exists()


def test_analyst_cannot_record_payment(bounty_case, analyst, coordinator):
    bounty = propose_bounty(bounty_case, analyst, amount=Decimal("200000"))
    approve_bounty(bounty, coordinator)
    with pytest.raises(PermissionDenied):
        record_payment(bounty, analyst)


def test_payment_pending_does_not_update_researcher_totals(bounty_case, analyst, coordinator):
    """Un versement seulement enregistre ne doit rien compter : voir
    test_settled_bounty_updates_researcher_totals pour le cas confirme."""
    bounty = propose_bounty(bounty_case, analyst, amount=Decimal("200000"))
    approve_bounty(bounty, coordinator)
    record_payment(bounty, coordinator)

    profile = bounty_case.reporter.researcher_profile
    profile.refresh_from_db()
    assert profile.total_rewards == Decimal("0.00")


def test_settled_bounty_updates_researcher_totals(bounty_case, analyst, coordinator):
    from django.core.files.uploadedfile import SimpleUploadedFile

    bounty = propose_bounty(bounty_case, analyst, amount=Decimal("200000"))
    approve_bounty(bounty, coordinator)
    payment = record_payment(bounty, coordinator)
    _verify_the_fix(bounty_case, coordinator)
    confirm_settlement(
        payment,
        coordinator,
        proof_file=SimpleUploadedFile(
            "recu.pdf", b"%PDF-1.4 recu", content_type="application/pdf"
        ),
    )

    profile = bounty_case.reporter.researcher_profile
    profile.refresh_from_db()
    assert profile.total_rewards == Decimal("200000.00")


# ------------------------------------------------- portefeuille du chercheur
# Simple copie a titre indicatif (voir apps.bounty.services.record_payment) :
# jamais une reference forte vers apps.researchers.PayoutMethod, jamais
# bloquant si le portefeuille est incomplet ou absent, mais jamais silencieux
# non plus (avertissement journalise + affiche a l'agent qui enregistre).
def test_payment_snapshots_the_researchers_primary_method(bounty_case, analyst, coordinator):
    from django.core.files.uploadedfile import SimpleUploadedFile

    from apps.researchers.models import PayoutMethod, PayoutMethodType
    from apps.researchers.services import (
        add_payout_method,
        attach_id_document,
        get_or_create_payout_profile,
    )

    researcher = bounty_case.reporter
    profile = get_or_create_payout_profile(researcher)
    profile.legal_full_name = "Fatou Kone"
    profile.contact_phone = "+22670000001"
    profile.accepted_terms = True
    profile.save()
    attach_id_document(
        profile,
        researcher,
        SimpleUploadedFile(
            "cnib.pdf", b"%PDF-1.4 contenu de test", content_type="application/pdf"
        ),
    )
    profile.refresh_from_db()
    add_payout_method(
        profile,
        researcher,
        PayoutMethod(
            method_type=PayoutMethodType.MOBILE_MONEY,
            mobile_operator="ORANGE_MONEY",
            mobile_number="70000001",
            mobile_holder_name="Fatou Kone",
        ),
    )

    bounty = propose_bounty(bounty_case, analyst, amount=Decimal("200000"))
    approve_bounty(bounty, coordinator)
    payment = record_payment(bounty, coordinator)

    assert "Orange Money" in payment.payout_snapshot
    assert "70000001" not in payment.payout_snapshot  # masque
    assert payment.payout_warning == ""


def test_payment_warns_without_any_payout_profile(bounty_case, analyst, coordinator):
    bounty = propose_bounty(bounty_case, analyst, amount=Decimal("200000"))
    approve_bounty(bounty, coordinator)
    payment = record_payment(bounty, coordinator)

    assert payment.payout_snapshot == ""
    assert "incomplet" in payment.payout_warning
    assert "aucun moyen" in payment.payout_warning
    warnings = [
        entry.metadata.get("warning", "")
        for entry in AuditLog.objects.filter(action=AuditAction.BOUNTY_PAYMENT_RECORDED)
    ]
    assert any("incomplet" in warning for warning in warnings)


def test_payment_warns_when_profile_incomplete_despite_a_method(
    bounty_case, analyst, coordinator
):
    from apps.researchers.models import PayoutMethod, PayoutMethodType
    from apps.researchers.services import add_payout_method, get_or_create_payout_profile

    researcher = bounty_case.reporter
    profile = get_or_create_payout_profile(researcher)  # accepted_terms jamais coche
    add_payout_method(
        profile,
        researcher,
        PayoutMethod(
            method_type=PayoutMethodType.MOBILE_MONEY,
            mobile_operator="ORANGE_MONEY",
            mobile_number="70000001",
            mobile_holder_name="Fatou Kone",
        ),
    )

    bounty = propose_bounty(bounty_case, analyst, amount=Decimal("200000"))
    approve_bounty(bounty, coordinator)
    payment = record_payment(bounty, coordinator)

    # Le moyen existe : la copie a titre indicatif reste utile...
    assert "Orange Money" in payment.payout_snapshot
    # ... mais le profil est incomplet (conditions non acceptees) : averti quand meme.
    assert "incomplet" in payment.payout_warning


def test_payment_view_flashes_the_payout_warning(
    client_for, bounty_case, analyst, coordinator
):
    bounty = propose_bounty(bounty_case, analyst, amount=Decimal("200000"))
    approve_bounty(bounty, coordinator)

    client = client_for(coordinator)
    response = client.post(
        reverse("bounty:payment", args=[bounty.pk]), {"method": "BANK_TRANSFER"}, follow=True
    )
    content = response.content.decode()
    assert "portefeuille" in content.lower()


# ------------------------------------------------------------- reglement
# La comptabilite agit hors plateforme et notifie l'agent par email avec une
# preuve (recu, confirmation bancaire...) : cette preuve doit etre televersee
# ici pour confirmer qu'un versement enregistre a reellement ete regle -
# jamais sur une simple declaration.
def _proof():
    from django.core.files.uploadedfile import SimpleUploadedFile

    return SimpleUploadedFile(
        "recu.pdf", b"%PDF-1.4 recu de virement", content_type="application/pdf"
    )


def _verify_the_fix(case, actor):
    """Fait avancer le dossier jusqu'a FIX_VERIFIED (chemin nominal Bug Bounty).

    Necessaire pour confirmer un reglement : voir SETTLEMENT_ELIGIBLE_CASE_
    STATUSES, le paiement ne doit jamais etre effectue avant que tout le
    processus de remediation soit lui-meme termine.
    """
    from apps.coordination.services import transition_case
    from apps.coordination.workflow import CaseStatus

    for target in (
        CaseStatus.TRIAGE,
        CaseStatus.VALIDATED,
        CaseStatus.SEVERITY_ASSIGNED,
        CaseStatus.BOUNTY_REVIEW,
        CaseStatus.REWARD_APPROVED,
        CaseStatus.REMEDIATION,
        CaseStatus.FIX_AVAILABLE,
        CaseStatus.VERIFICATION,
        CaseStatus.FIX_VERIFIED,
    ):
        transition_case(case, target, actor)
    case.refresh_from_db()
    return case


def _recorded_payment(bounty_case, analyst, coordinator, amount=Decimal("200000")):
    """Versement pret a etre confirme : dossier deja verifie par defaut.

    Les tests qui portent specifiquement sur l'etat du dossier (verification
    pas encore faite) construisent leur propre scenario plutot que d'utiliser
    ce raccourci - voir test_confirm_settlement_requires_a_verified_case.
    """
    bounty = propose_bounty(bounty_case, analyst, amount=amount)
    approve_bounty(bounty, coordinator)
    _verify_the_fix(bounty_case, coordinator)
    return record_payment(bounty, coordinator)


def test_confirm_settlement_requires_a_proof(bounty_case, analyst, coordinator):
    payment = _recorded_payment(bounty_case, analyst, coordinator)
    with pytest.raises(ValidationError):
        confirm_settlement(payment, coordinator, proof_file=None)


def test_confirm_settlement_requires_a_verified_fix(bounty_case, analyst, coordinator):
    """L'argent ne doit jamais sortir avant que tout le processus de
    remediation soit lui-meme termine - pas seulement la decision de
    recompense. Un dossier encore SUBMITTED, meme avec un versement
    enregistre, ne peut pas etre confirme regle."""
    bounty = propose_bounty(bounty_case, analyst, amount=Decimal("200000"))
    approve_bounty(bounty, coordinator)
    payment = record_payment(bounty, coordinator)  # dossier toujours SUBMITTED

    with pytest.raises(ValidationError, match="correctif"):
        confirm_settlement(payment, coordinator, proof_file=_proof())
    payment.refresh_from_db()
    assert payment.status == PaymentStatus.RECORDED


def test_confirm_settlement_succeeds_once_the_fix_is_verified(
    bounty_case, analyst, coordinator
):
    bounty = propose_bounty(bounty_case, analyst, amount=Decimal("200000"))
    approve_bounty(bounty, coordinator)
    payment = record_payment(bounty, coordinator)
    _verify_the_fix(bounty_case, coordinator)

    confirm_settlement(payment, coordinator, proof_file=_proof())
    payment.refresh_from_db()
    assert payment.status == PaymentStatus.SETTLED


def test_mark_payment_failed_also_requires_a_verified_fix(bounty_case, analyst, coordinator):
    """Ni la confirmation ni l'echec ne doivent pouvoir statuer sur un
    versement tant que le processus de remediation n'est pas termine : le
    versement reste simplement "Enregistre" jusque-la, dans les deux sens."""
    bounty = propose_bounty(bounty_case, analyst, amount=Decimal("200000"))
    approve_bounty(bounty, coordinator)
    payment = record_payment(bounty, coordinator)  # dossier toujours SUBMITTED

    with pytest.raises(ValidationError, match="correctif"):
        mark_payment_failed(payment, coordinator, reason="Compte errone")
    payment.refresh_from_db()
    assert payment.status == PaymentStatus.RECORDED


def test_mark_payment_failed_succeeds_once_the_fix_is_verified(
    bounty_case, analyst, coordinator
):
    bounty = propose_bounty(bounty_case, analyst, amount=Decimal("200000"))
    approve_bounty(bounty, coordinator)
    payment = record_payment(bounty, coordinator)
    _verify_the_fix(bounty_case, coordinator)

    mark_payment_failed(payment, coordinator, reason="Compte errone")
    payment.refresh_from_db()
    assert payment.status == PaymentStatus.FAILED


def test_settlement_eligible_flag_reflects_the_case_status(
    client_for, bounty_case, analyst, coordinator
):
    bounty = propose_bounty(bounty_case, analyst, amount=Decimal("200000"))
    approve_bounty(bounty, coordinator)
    record_payment(bounty, coordinator)

    client = client_for(coordinator)
    response = client.get(reverse("bounty:detail", args=[bounty.pk]))
    assert response.context["settlement_eligible"] is False
    assert "pas encore vérifié" in response.content.decode()

    _verify_the_fix(bounty_case, coordinator)
    response = client.get(reverse("bounty:detail", args=[bounty.pk]))
    assert response.context["settlement_eligible"] is True


def test_confirm_settlement_marks_the_payment_settled(bounty_case, analyst, coordinator):
    payment = _recorded_payment(bounty_case, analyst, coordinator)
    confirm_settlement(payment, coordinator, proof_file=_proof(), note="Confirme par email")
    payment.refresh_from_db()

    assert payment.status == PaymentStatus.SETTLED
    assert payment.settled_at is not None
    assert payment.proof_original_filename == "recu.pdf"
    assert payment.proof_sha256
    assert payment.note == "Confirme par email"
    assert payment.bounty.status == BountyStatus.PAID
    assert AuditLog.objects.filter(action=AuditAction.BOUNTY_PAYMENT_SETTLED).exists()


def test_confirm_settlement_requires_capability(bounty_case, analyst, coordinator):
    payment = _recorded_payment(bounty_case, analyst, coordinator)
    with pytest.raises(PermissionDenied):
        confirm_settlement(payment, analyst, proof_file=_proof())


def test_confirm_settlement_refuses_an_already_settled_payment(
    bounty_case, analyst, coordinator
):
    payment = _recorded_payment(bounty_case, analyst, coordinator)
    confirm_settlement(payment, coordinator, proof_file=_proof())
    with pytest.raises(ValidationError):
        confirm_settlement(payment, coordinator, proof_file=_proof())


def test_mark_payment_failed_requires_a_reason(bounty_case, analyst, coordinator):
    payment = _recorded_payment(bounty_case, analyst, coordinator)
    with pytest.raises(ValidationError):
        mark_payment_failed(payment, coordinator, reason="  ")


def test_mark_payment_failed_marks_the_payment(bounty_case, analyst, coordinator):
    payment = _recorded_payment(bounty_case, analyst, coordinator)
    mark_payment_failed(payment, coordinator, reason="Compte beneficiaire errone")
    payment.refresh_from_db()

    assert payment.status == PaymentStatus.FAILED
    assert payment.failure_reason == "Compte beneficiaire errone"
    # Retour a APPROVED : la recompense reste due, un nouveau versement peut
    # etre enregistre - ce n'est pas un etat terminal.
    assert payment.bounty.status == BountyStatus.APPROVED
    assert AuditLog.objects.filter(action=AuditAction.BOUNTY_PAYMENT_FAILED).exists()


def test_new_payment_can_be_recorded_after_a_failure(bounty_case, analyst, coordinator):
    payment = _recorded_payment(bounty_case, analyst, coordinator)
    mark_payment_failed(payment, coordinator, reason="Mauvais compte")
    payment.bounty.refresh_from_db()

    second = record_payment(payment.bounty, coordinator, reference="VIR-CORRECTIF")
    assert second.pk != payment.pk
    payment.bounty.refresh_from_db()
    assert payment.bounty.status == BountyStatus.PAYMENT_PENDING


def test_settle_payment_via_get_is_rejected(client_for, bounty_case, analyst, coordinator):
    payment = _recorded_payment(bounty_case, analyst, coordinator)
    client = client_for(coordinator)
    response = client.get(reverse("bounty:settle_payment", args=[payment.pk]))
    assert response.status_code == 405
    payment.refresh_from_db()
    assert payment.status == PaymentStatus.RECORDED


def test_settle_payment_view_uploads_the_proof(client_for, bounty_case, analyst, coordinator):
    payment = _recorded_payment(bounty_case, analyst, coordinator)
    client = client_for(coordinator)
    response = client.post(
        reverse("bounty:settle_payment", args=[payment.pk]),
        {"proof_file": _proof(), "note": ""},
    )
    assert response.status_code == 302
    payment.refresh_from_db()
    assert payment.status == PaymentStatus.SETTLED
    assert payment.proof_file.name


def test_fail_payment_view(client_for, bounty_case, analyst, coordinator):
    payment = _recorded_payment(bounty_case, analyst, coordinator)
    client = client_for(coordinator)
    response = client.post(
        reverse("bounty:fail_payment", args=[payment.pk]),
        {"reason": "Virement rejete par la banque"},
    )
    assert response.status_code == 302
    payment.refresh_from_db()
    assert payment.status == PaymentStatus.FAILED


def test_payment_proof_download_requires_capability(
    client_for, bounty_case, analyst, coordinator
):
    payment = _recorded_payment(bounty_case, analyst, coordinator)
    confirm_settlement(payment, coordinator, proof_file=_proof())

    client = client_for(analyst)
    response = client.get(reverse("bounty:payment_proof", args=[payment.pk]))
    assert response.status_code == 403


def test_payment_proof_download_works_for_recorder(
    client_for, bounty_case, analyst, coordinator
):
    payment = _recorded_payment(bounty_case, analyst, coordinator)
    confirm_settlement(payment, coordinator, proof_file=_proof())

    client = client_for(coordinator)
    response = client.get(reverse("bounty:payment_proof", args=[payment.pk]))
    assert response.status_code == 200
    assert AuditLog.objects.filter(action=AuditAction.BOUNTY_PROOF_DOWNLOADED).exists()


def test_payment_without_proof_download_is_404(client_for, bounty_case, analyst, coordinator):
    payment = _recorded_payment(bounty_case, analyst, coordinator)
    client = client_for(coordinator)
    response = client.get(reverse("bounty:payment_proof", args=[payment.pk]))
    assert response.status_code == 404


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


# ------------------------------------------------------------------- budget
def test_no_budget_status_without_declared_budget(bounty_case, analyst):
    bounty = propose_bounty(bounty_case, analyst, amount=Decimal("200000"))
    assert budget_status(bounty) is None


def test_budget_status_projects_the_decision(bounty_case, analyst, bounty_program):
    policy = bounty_program.reward_policy
    policy.total_budget = Decimal("1000000")
    policy.save(update_fields=["total_budget"])

    bounty = propose_bounty(bounty_case, analyst, amount=Decimal("200000"))
    status = budget_status(bounty)

    assert status["consumed"] == Decimal("0")
    assert status["projected"] == Decimal("200000")
    assert status["remaining"] == Decimal("800000")
    assert status["exceeded"] is False


def test_budget_overrun_is_allowed_but_audited(
    bounty_case, analyst, coordinator, bounty_program
):
    """Meme traitement que le hors-matrice : jamais bloquant, jamais silencieux."""
    policy = bounty_program.reward_policy
    policy.total_budget = Decimal("100000")
    policy.save(update_fields=["total_budget"])

    bounty = propose_bounty(bounty_case, analyst, amount=Decimal("250000"))
    approve_bounty(bounty, coordinator)
    bounty.refresh_from_db()

    assert bounty.status == BountyStatus.APPROVED
    warnings = [
        entry.metadata.get("warning", "")
        for entry in AuditLog.objects.filter(action=AuditAction.BOUNTY_APPROVED)
    ]
    assert any("budget" in warning for warning in warnings)


def test_approved_bounty_is_not_counted_twice(
    bounty_case, analyst, coordinator, bounty_program
):
    policy = bounty_program.reward_policy
    policy.total_budget = Decimal("1000000")
    policy.save(update_fields=["total_budget"])

    bounty = propose_bounty(bounty_case, analyst, amount=Decimal("200000"))
    approve_bounty(bounty, coordinator)
    bounty.refresh_from_db()

    status = budget_status(bounty)
    assert status["projected"] == Decimal("200000")
    assert status["exceeded"] is False


# ------------------------------------------------------------ administration
def _admin_request(rf, user):
    """Requete d'administration minimale (le framework messages est requis)."""
    from django.contrib.messages.storage.fallback import FallbackStorage

    request = rf.post("/admin/bounty/bounty/")
    request.user = user
    request.session = {}
    request._messages = FallbackStorage(request)
    return request


def _bounty_admin():
    from django.contrib.admin.sites import AdminSite

    from apps.bounty.admin import BountyAdmin

    return BountyAdmin(Bounty, AdminSite())


def test_admin_approval_goes_through_the_service(rf, bounty_case, analyst, coordinator):
    """L'admin ne doit pas reimplementer le cycle de vie : montant, audit,
    notification et profil doivent etre traites comme via l'interface web."""
    from apps.bounty.admin import action_approve

    bounty = propose_bounty(bounty_case, analyst, amount=Decimal("200000"))
    action_approve(
        _bounty_admin(),
        _admin_request(rf, coordinator),
        Bounty.objects.filter(pk=bounty.pk),
    )
    bounty.refresh_from_db()

    assert bounty.status == BountyStatus.APPROVED
    assert bounty.approved_amount == Decimal("200000")
    assert bounty.decided_by == coordinator
    assert AuditLog.objects.filter(action=AuditAction.BOUNTY_APPROVED).exists()


def test_admin_approval_refuses_self_approval(rf, bounty_case, coordinator):
    from apps.bounty.admin import action_approve

    bounty = propose_bounty(bounty_case, coordinator, amount=Decimal("200000"))
    action_approve(
        _bounty_admin(),
        _admin_request(rf, coordinator),
        Bounty.objects.filter(pk=bounty.pk),
    )
    bounty.refresh_from_db()

    assert bounty.status == BountyStatus.PENDING


def test_admin_payment_records_an_accounting_trace(rf, bounty_case, analyst, coordinator):
    from apps.bounty.admin import action_record_payment

    bounty = propose_bounty(bounty_case, analyst, amount=Decimal("200000"))
    approve_bounty(bounty, coordinator)
    action_record_payment(
        _bounty_admin(),
        _admin_request(rf, coordinator),
        Bounty.objects.filter(pk=bounty.pk),
    )
    bounty.refresh_from_db()

    assert bounty.status == BountyStatus.PAYMENT_PENDING
    assert bounty.payments.count() == 1
    assert bounty.payments.first().status == PaymentStatus.RECORDED


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
    etranger = ProgramScope.objects.create(program=vdp_program, identifier="autre.exemple.bf")
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
    with pytest.raises(ValidationError, match="hors périmètre"):
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

    with pytest.raises(ValidationError, match="adresse email vérifiée"):
        submit_report(
            build_report(bounty_researcher, organization, bounty_program),
            reporter=bounty_researcher,
        )


def test_anonymous_report_refused_when_verification_required(bounty_program, organization):
    """Sans compte, aucune adresse n'est verifiee : le programme refuse."""
    from apps.reports.services import submit_report

    from .conftest import build_report

    report = build_report(None, organization, bounty_program)
    report.reporter = None
    report.is_anonymous = True
    with pytest.raises(ValidationError, match="chercheur identifié"):
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


def test_vdp_may_waive_the_verification_requirement(vdp_program, researcher_a, organization):
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
    with pytest.raises(ValidationError, match="adresse email vérifiée"):
        bounty_program.full_clean()


def test_bounty_refused_to_unverified_researcher(bounty_case, analyst):
    """Second garde-fou : le programme a pu devenir exigeant apres coup."""
    bounty_case.reporter.email_verified = False
    bounty_case.reporter.save(update_fields=["email_verified"])

    with pytest.raises(ValidationError, match="vérifié son adresse email"):
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
    assert "chercheur identifié" in bounty_program.reporter_rejection()


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

    assert "chercheur identifié" in page
    assert "Vous pouvez signaler sans compte" not in page


def test_program_page_sends_a_visitor_without_account_to_the_login(client, bounty_program):
    """Le bouton d'appel ne mene pas a un formulaire qui refusera l'envoi."""
    page = client.get(f"/programs/{bounty_program.slug}/").content.decode()

    assert "Se connecter pour signaler" in page
    assert "%3Fprogram%3D" in page


# ------------------------------------------------------- vue du beneficiaire
def test_researcher_sees_his_reward_without_the_deciders(
    client_for, bounty_case, analyst, coordinator, bounty_researcher
):
    """Le beneficiaire voit ce qui le concerne, jamais qui a tranche.

    La deliberation - proposition, avis, signature - appartient a
    l'instruction. Le chercheur en recoit le resultat, pas le detail.
    """
    bounty = propose_bounty(
        bounty_case, analyst, amount=Decimal("200000"), justification="Impact confirme"
    )
    review_bounty(bounty, coordinator, ReviewDecision.APPROVE, comment="Avis favorable")

    page = client_for(bounty_researcher).get(f"/bounties/{bounty.pk}/").content.decode()

    assert "200 000" in page or "200000" in page
    assert bounty_case.case_id in page
    assert analyst.display_name not in page
    assert coordinator.display_name not in page
    assert "Proposé par" not in page
    assert "Décidé par" not in page
    assert "Revues" not in page
    assert "Avis favorable" not in page
    assert "Impact confirme" not in page


def test_researcher_gets_no_lever_on_his_reward(
    client_for, bounty_case, analyst, bounty_researcher
):
    """Aucune commande n'est offerte au beneficiaire, ni servie s'il insiste."""
    bounty = propose_bounty(bounty_case, analyst, amount=Decimal("200000"))
    client = client_for(bounty_researcher)

    page = client.get(f"/bounties/{bounty.pk}/").content.decode()
    assert "Approuver" not in page
    assert "Enregistrer l'avis" not in page
    assert "Enregistrer un versement" not in page

    for chemin in (
        f"/bounties/{bounty.pk}/review/",
        f"/bounties/{bounty.pk}/approve/",
        f"/bounties/{bounty.pk}/payment/",
        f"/bounties/case/{bounty_case.case_id}/propose/",
    ):
        assert client.post(chemin, {}).status_code == 403, chemin


def test_analyst_still_sees_the_deciders(client_for, bounty_case, analyst, coordinator):
    """La restriction vise le beneficiaire, pas ceux qui instruisent."""
    bounty = propose_bounty(bounty_case, analyst, amount=Decimal("200000"))
    review_bounty(bounty, coordinator, ReviewDecision.APPROVE, comment="Avis favorable")

    page = client_for(analyst).get(f"/bounties/{bounty.pk}/").content.decode()

    assert "Proposé par" in page
    assert "Revues" in page
    assert "Avis favorable" in page


def test_reward_list_hides_other_researchers_column(
    client_for, bounty_case, analyst, bounty_researcher
):
    propose_bounty(bounty_case, analyst, amount=Decimal("200000"))

    page_chercheur = client_for(bounty_researcher).get("/bounties/").content.decode()
    page_analyste = client_for(analyst).get("/bounties/").content.decode()

    assert "<th>Chercheur</th>" not in page_chercheur
    assert "<th>Chercheur</th>" in page_analyste
