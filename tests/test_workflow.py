"""Tests du moteur de workflow v2 (11 etapes, branche prime, exceptions).

Reference : « Workflow v2 & Matrice RBAC ». Chaque etape a un seul
proprietaire, des pre-requis bloquants, et la regle des quatre yeux porte
sur l'utilisateur, pas seulement sur le role.
"""

from datetime import timedelta
from decimal import Decimal
from types import SimpleNamespace

import pytest
from django.urls import reverse
from django.utils import timezone

from apps.accounts.models import User
from apps.accounts.roles import ROLE_CAPABILITIES, Capability, Role
from apps.audit.models import AuditAction, AuditLog
from apps.audit.services import log_action
from apps.bounty.services import wallet_balance
from apps.coordination.constants import Confidentiality, SLAKind, SLAState
from apps.coordination.models import SLAEvent
from apps.coordination.selectors import sla_color
from apps.coordination.services import (
    escalate_case,
    mark_duplicate,
    perform_action,
    set_severity,
    transition_case,
)
from apps.coordination.workflow import (
    MAIN_PATH,
    PRIMARY,
    VDP_TRANSITIONS,
    BountyStage,
    CaseStatus,
    OutOfScope,
    TransitionNotAllowed,
    allowed_targets,
    author_of,
    available_actions,
    current_owner_ids,
    get_action,
    primary_action,
    remediation_limit_days,
)
from apps.disclosures.services import create_advisory_from_case
from apps.vulnerabilities.constants import Severity

from .conftest import PASSWORD, advance, make_user, workflow_actor

pytestmark = pytest.mark.django_db

LOW_VECTOR = "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N"
HIGH_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"


# ------------------------------------------------------------------ helpers
def opened(case, user):
    """Trace d'ouverture du dossier (pre-requis de l'accuse de reception)."""
    log_action(AuditAction.CASE_VIEWED, actor=user, obj=case)


def qualify(case, analyst, cwe, vector=HIGH_VECTOR):
    """Saisit CVSS et CWE comme l'analyste avant de soumettre (etape 3)."""
    set_severity(case, analyst, cvss_vector=vector)
    case.cwe = cwe
    case.save(update_fields=["cwe", "updated_at"])


def missing_of(callable_):
    with pytest.raises(TransitionNotAllowed) as info:
        callable_()
    return info.value.missing


def draft_advisory(case, analyst, **overrides):
    overrides.setdefault("summary", "Une vulnerabilite corrigee affectait le portail.")
    return create_advisory_from_case(case, analyst, **overrides)


def plan_data(days=20):
    return {
        "remediation_plan": "Corriger la requete et deployer.",
        "remediation_target_date": timezone.localdate() + timedelta(days=days),
    }


# ---------------------------------------------------------- table declarative
def test_main_path_has_eleven_steps_chained_in_table():
    assert len(MAIN_PATH) == 11
    assert MAIN_PATH[0] == CaseStatus.SUBMITTED
    assert MAIN_PATH[-1] == CaseStatus.CLOSED
    for current, following in zip(MAIN_PATH, MAIN_PATH[1:], strict=False):
        assert following in VDP_TRANSITIONS[current]


def test_closed_is_terminal():
    assert allowed_targets(CaseStatus.CLOSED) == []
    assert CaseStatus.CLOSED not in VDP_TRANSITIONS


def test_one_primary_button_per_main_path_status():
    for index, status in enumerate(MAIN_PATH[:-1]):
        fake = SimpleNamespace(status=status, bounty_stage="", deadline_disclosure_at=None)
        buttons = [
            action
            for action in available_actions(fake, kind=PRIMARY)
            if action.track == "case"
        ]
        assert len(buttons) == 1, status
        assert primary_action(fake).target == MAIN_PATH[index + 1]


def test_forbidden_transition_is_rejected(case_alpha, coordinator):
    with pytest.raises(TransitionNotAllowed):
        transition_case(case_alpha, CaseStatus.CLOSED, coordinator)


def test_cannot_transition_to_same_state(case_alpha, triager):
    with pytest.raises(TransitionNotAllowed):
        transition_case(case_alpha, CaseStatus.SUBMITTED, triager)


def test_unknown_action_is_refused(case_alpha, triager):
    with pytest.raises(TransitionNotAllowed):
        perform_action(case_alpha, "tout_publier", triager)


# --------------------------------------------------------------- cote service
def test_case_is_created_from_report(case_alpha, researcher_a):
    assert case_alpha.case_id.startswith("EVDP-")
    assert case_alpha.status == CaseStatus.SUBMITTED
    assert case_alpha.reporter == researcher_a
    assert case_alpha.timeline.count() == 1
    assert case_alpha.bounty_stage == BountyStage.NONE


def test_case_id_is_sequential(case_alpha, case_beta):
    assert case_alpha.case_id != case_beta.case_id
    numbers = sorted(int(case.case_id.rsplit("-", 1)[1]) for case in (case_alpha, case_beta))
    assert numbers[1] == numbers[0] + 1


def test_action_records_history_and_audit(case_alpha, triager):
    opened(case_alpha, triager)
    perform_action(case_alpha, "acknowledge", triager, data={"comment": "Recu"})
    case_alpha.refresh_from_db()

    assert case_alpha.status == CaseStatus.ACKNOWLEDGED
    assert case_alpha.acknowledged_at is not None
    entry = case_alpha.status_history.get(to_status=CaseStatus.ACKNOWLEDGED)
    assert entry.actor == triager
    assert entry.comment == "Recu"
    assert AuditLog.objects.filter(
        action=AuditAction.STATUS_CHANGED, object_id=str(case_alpha.pk), result="SUCCESS"
    ).exists()


def test_denied_action_is_audited_and_changes_nothing(case_alpha, researcher_a):
    with pytest.raises(TransitionNotAllowed):
        perform_action(case_alpha, "acknowledge", researcher_a)
    case_alpha.refresh_from_db()
    assert case_alpha.status == CaseStatus.SUBMITTED
    assert AuditLog.objects.filter(
        action=AuditAction.STATUS_CHANGED, object_id=str(case_alpha.pk), result="DENIED"
    ).exists()


def test_validation_sets_timestamp_and_reputation(case_alpha, analyst, cwe, researcher_a):
    advance(case_alpha, CaseStatus.IN_ANALYSIS)
    qualify(case_alpha, analyst, cwe, vector=LOW_VECTOR)
    advance(case_alpha, CaseStatus.VALIDATED)
    profile = researcher_a.researcher_profile
    profile.refresh_from_db()

    assert case_alpha.validated_at is not None
    assert profile.reputation == 10
    assert profile.reports_validated == 1


def test_reputation_is_not_granted_twice(case_alpha, coordinator, researcher_a):
    from apps.researchers.services import award_reputation

    advance(case_alpha, CaseStatus.VALIDATED)
    profile = researcher_a.researcher_profile
    profile.refresh_from_db()
    first = profile.reputation

    award_reputation(researcher_a, case_alpha, granted_by=coordinator)
    profile.refresh_from_db()
    assert profile.reputation == first


def test_critical_severity_grants_bonus(case_alpha, researcher_a):
    # Le vecteur par defaut des helpers (C:H/I:H) vaut 9.1 : critique.
    advance(case_alpha, CaseStatus.VALIDATED)
    assert case_alpha.severity == Severity.CRITICAL
    profile = researcher_a.researcher_profile
    profile.refresh_from_db()
    # 10 (valide) + 50 (critique)
    assert profile.reputation == 60


# ------------------------------------------------- un bouton, un proprietaire
def test_step1_acknowledge_owned_by_triager(case_alpha, triager, analyst):
    opened(case_alpha, triager)
    with pytest.raises(TransitionNotAllowed):
        perform_action(case_alpha, "acknowledge", analyst)
    perform_action(case_alpha, "acknowledge", triager)
    assert case_alpha.status == CaseStatus.ACKNOWLEDGED


def test_step2_admissibility_owned_by_triager(case_alpha, triager, analyst):
    advance(case_alpha, CaseStatus.ACKNOWLEDGED)
    checklist = {
        "in_scope": True,
        "organization_identified": True,
        "attachment_readable": True,
    }
    with pytest.raises(TransitionNotAllowed):
        perform_action(case_alpha, "declare_admissible", analyst, data=checklist)
    perform_action(case_alpha, "declare_admissible", triager, data=checklist)
    assert case_alpha.status == CaseStatus.IN_ANALYSIS
    assert case_alpha.admissibility_checklist == checklist


def test_step3_qualification_owned_by_analyst(case_alpha, triager, analyst, cwe):
    advance(case_alpha, CaseStatus.IN_ANALYSIS)
    qualify(case_alpha, analyst, cwe)
    with pytest.raises(TransitionNotAllowed):
        perform_action(case_alpha, "submit_qualification", triager)
    perform_action(case_alpha, "submit_qualification", analyst)
    assert case_alpha.status == CaseStatus.VALIDATION_PENDING


def test_step4_validation_owned_by_coordinator(case_alpha, analyst, dsi_alpha, coordinator):
    advance(case_alpha, CaseStatus.VALIDATION_PENDING)
    data = {"comment": "Relu"}
    # La DSI ne voit meme pas le dossier avant l'etape 5.
    with pytest.raises(OutOfScope):
        perform_action(case_alpha, "validate_qualification", dsi_alpha, data=data)
    with pytest.raises(TransitionNotAllowed):
        perform_action(case_alpha, "validate_qualification", analyst, data=data)
    perform_action(case_alpha, "validate_qualification", coordinator, data=data)
    assert case_alpha.status == CaseStatus.VALIDATED


def test_step5_vendor_notification_owned_by_analyst(case_alpha, analyst, coordinator):
    advance(case_alpha, CaseStatus.VALIDATED)
    with pytest.raises(TransitionNotAllowed):
        perform_action(case_alpha, "notify_vendor", coordinator)
    perform_action(case_alpha, "notify_vendor", analyst)
    assert case_alpha.status == CaseStatus.VENDOR_NOTIFIED
    assert case_alpha.vendor_notified_at is not None


def test_step6_remediation_plan_owned_by_dsi(case_alpha, analyst, dsi_alpha):
    advance(case_alpha, CaseStatus.VENDOR_NOTIFIED)
    with pytest.raises(TransitionNotAllowed):
        perform_action(case_alpha, "submit_remediation_plan", analyst, data=plan_data())
    perform_action(case_alpha, "submit_remediation_plan", dsi_alpha, data=plan_data())
    assert case_alpha.status == CaseStatus.REMEDIATION_IN_PROGRESS
    assert case_alpha.remediation_target_date == plan_data()["remediation_target_date"]


def test_step7_fix_owned_by_dsi(case_alpha, analyst, dsi_alpha):
    advance(case_alpha, CaseStatus.REMEDIATION_IN_PROGRESS)
    data = {"fix_description": "Requetes parametrees.", "fix_version": "2.0.1"}
    with pytest.raises(TransitionNotAllowed):
        perform_action(case_alpha, "declare_fix", analyst, data=data)
    perform_action(case_alpha, "declare_fix", dsi_alpha, data=data)
    assert case_alpha.status == CaseStatus.FIX_AVAILABLE
    assert case_alpha.remediated_at is not None


def test_step8_fix_confirmation_owned_by_analyst(case_alpha, analyst, dsi_alpha):
    advance(case_alpha, CaseStatus.FIX_AVAILABLE)
    data = {"verification_report": "Non reproductible."}
    with pytest.raises(TransitionNotAllowed):
        perform_action(case_alpha, "confirm_fix", dsi_alpha, data=data)
    perform_action(case_alpha, "confirm_fix", analyst, data=data)
    assert case_alpha.status == CaseStatus.FIX_VERIFIED


def test_step9_advisory_owned_by_analyst(case_alpha, analyst, coordinator):
    advance(case_alpha, CaseStatus.FIX_VERIFIED)
    draft_advisory(case_alpha, analyst)
    with pytest.raises(TransitionNotAllowed):
        perform_action(case_alpha, "submit_advisory", coordinator)
    perform_action(case_alpha, "submit_advisory", analyst)
    assert case_alpha.status == CaseStatus.ADVISORY_REVIEW
    assert case_alpha.advisories.get().status == "IN_REVIEW"


def test_step10_publication_owned_by_coordinator(case_alpha, analyst, coordinator):
    advance(case_alpha, CaseStatus.ADVISORY_REVIEW)
    data = {"comment": "Relu", "review_done": True}
    with pytest.raises(TransitionNotAllowed):
        perform_action(case_alpha, "publish_and_close", analyst, data=data)
    perform_action(case_alpha, "publish_and_close", coordinator, data=data)
    assert case_alpha.status == CaseStatus.CLOSED
    assert case_alpha.is_published
    assert case_alpha.closed_at is not None
    assert case_alpha.advisories.get().status == "PUBLISHED"


def test_super_admin_has_no_button_and_does_not_see_case(case_alpha):
    admin = User.objects.create_superuser(
        email="root@test.bf", password=PASSWORD, full_name="Root"
    )
    assert not case_alpha.is_visible_to(admin)
    for action in ("acknowledge", "request_information", "propose_rejection"):
        assert not admin.has_capability(get_action(action).capability)
    opened(case_alpha, admin)
    with pytest.raises(OutOfScope):
        perform_action(case_alpha, "acknowledge", admin)


# --------------------------------------------------------- pre-requis bloquants
def test_acknowledge_requires_case_opened(case_alpha, triager):
    missing = missing_of(lambda: perform_action(case_alpha, "acknowledge", triager))
    assert missing == ["Dossier jamais ouvert"]


def test_admissibility_requires_checklist(case_alpha, triager):
    advance(case_alpha, CaseStatus.ACKNOWLEDGED)
    missing = missing_of(lambda: perform_action(case_alpha, "declare_admissible", triager))
    assert len([item for item in missing if item.startswith("Checklist")]) == 3


def test_admissibility_requires_readable_attachment(case_alpha, triager):
    advance(case_alpha, CaseStatus.ACKNOWLEDGED)
    case_alpha.attachments.update(scan_status="INFECTED")
    data = {"in_scope": True, "organization_identified": True, "attachment_readable": True}
    missing = missing_of(
        lambda: perform_action(case_alpha, "declare_admissible", triager, data=data)
    )
    assert "Aucune pièce jointe lisible" in missing


def test_qualification_requires_cvss_and_cwe(case_alpha, analyst):
    advance(case_alpha, CaseStatus.IN_ANALYSIS)
    missing = missing_of(lambda: perform_action(case_alpha, "submit_qualification", analyst))
    assert "Vecteur CVSS manquant" in missing
    assert "CWE manquant" in missing


def test_remediation_plan_requires_target_date(case_alpha, dsi_alpha):
    advance(case_alpha, CaseStatus.VENDOR_NOTIFIED)
    data = {"remediation_plan": "Corriger."}
    missing = missing_of(
        lambda: perform_action(case_alpha, "submit_remediation_plan", dsi_alpha, data=data)
    )
    assert missing == ["Date cible manquante"]


def test_remediation_target_date_capped_by_severity(case_alpha, dsi_alpha):
    advance(case_alpha, CaseStatus.VENDOR_NOTIFIED)
    assert case_alpha.severity == Severity.CRITICAL
    missing = missing_of(
        lambda: perform_action(
            case_alpha, "submit_remediation_plan", dsi_alpha, data=plan_data(days=45)
        )
    )
    assert any("délai de la sévérité" in item for item in missing)


def test_remediation_limit_follows_severity(case_alpha):
    expected = {
        Severity.CRITICAL: 30,
        Severity.HIGH: 60,
        Severity.MEDIUM: 90,
        Severity.LOW: 90,
    }
    for severity, days in expected.items():
        case_alpha.severity = severity
        assert remediation_limit_days(case_alpha) == days


def test_fix_requires_version_or_date(case_alpha, dsi_alpha):
    advance(case_alpha, CaseStatus.REMEDIATION_IN_PROGRESS)
    data = {"fix_description": "Corrige."}
    missing = missing_of(
        lambda: perform_action(case_alpha, "declare_fix", dsi_alpha, data=data)
    )
    assert missing == ["Version ou date de déploiement du correctif manquante"]
    data["fix_deployed_on"] = timezone.localdate()
    perform_action(case_alpha, "declare_fix", dsi_alpha, data=data)
    assert case_alpha.status == CaseStatus.FIX_AVAILABLE


def test_fix_confirmation_requires_report(case_alpha, analyst):
    advance(case_alpha, CaseStatus.FIX_AVAILABLE)
    missing = missing_of(lambda: perform_action(case_alpha, "confirm_fix", analyst))
    assert missing == ["Compte rendu de contre-vérification manquant"]


def test_advisory_submission_requires_a_draft(case_alpha, analyst):
    advance(case_alpha, CaseStatus.FIX_VERIFIED)
    missing = missing_of(lambda: perform_action(case_alpha, "submit_advisory", analyst))
    assert missing == ["Aucun brouillon d'advisory"]


@pytest.mark.parametrize(
    "description, expected",
    [
        ("Serveur expose en 10.0.0.5.", "adresse IP"),
        ("Voir http://intranet.local/admin pour details.", "URL sensible"),
        ("```\nGET /?id=1' or 1=1\n```", "preuve de concept"),
    ],
)
def test_advisory_must_be_sanitized(case_alpha, analyst, description, expected):
    advance(case_alpha, CaseStatus.FIX_VERIFIED)
    draft_advisory(case_alpha, analyst, description=description)
    missing = missing_of(lambda: perform_action(case_alpha, "submit_advisory", analyst))
    assert any(expected in item for item in missing), missing


def test_publication_requires_review_confirmation(case_alpha, coordinator):
    advance(case_alpha, CaseStatus.ADVISORY_REVIEW)
    missing = missing_of(
        lambda: perform_action(
            case_alpha, "publish_and_close", coordinator, data={"comment": "Relu"}
        )
    )
    assert missing == ["Relecture non confirmée"]


def test_publication_requires_credit_matching_researcher_choice(case_alpha, coordinator):
    advance(case_alpha, CaseStatus.ADVISORY_REVIEW)
    case_alpha.advisories.update(credit="Quelqu'un d'autre")
    data = {"comment": "Relu", "review_done": True}
    missing = missing_of(
        lambda: perform_action(case_alpha, "publish_and_close", coordinator, data=data)
    )
    assert "Crédit non conforme au choix du chercheur" in missing


def test_publication_requires_finished_bounty_branch(bounty_case, coordinator):
    advance(bounty_case, CaseStatus.ADVISORY_REVIEW)
    assert bounty_case.bounty_stage == BountyStage.ELIGIBLE
    data = {"comment": "Relu", "review_done": True}
    missing = missing_of(
        lambda: perform_action(bounty_case, "publish_and_close", coordinator, data=data)
    )
    assert "Branche prime non terminée" in missing


# ---------------------------------------------------------------- quatre yeux
def test_senior_analyst_cannot_validate_own_qualification(case_alpha, cwe):
    senior = make_user("senior-a@test.bf", Role.CSIRT_ANALYST, is_senior_analyst=True)
    other = make_user("senior-b@test.bf", Role.CSIRT_ANALYST, is_senior_analyst=True)
    assert senior.has_capability(Capability.VALIDATE_SEVERITY)

    advance(case_alpha, CaseStatus.IN_ANALYSIS)
    qualify(case_alpha, senior, cwe)
    perform_action(case_alpha, "submit_qualification", senior)

    # Auteur de la qualification, il n'est pas responsable de l'etape 4 : le
    # dossier sort meme de son perimetre (refus « introuvable »).
    with pytest.raises(TransitionNotAllowed):
        perform_action(case_alpha, "validate_qualification", senior, data={"comment": "Ok"})
    perform_action(case_alpha, "validate_qualification", other, data={"comment": "Ok"})
    assert case_alpha.status == CaseStatus.VALIDATED


def test_plain_analyst_cannot_validate(case_alpha, analyst):
    assert not analyst.has_capability(Capability.VALIDATE_SEVERITY)


def test_advisory_author_cannot_publish(case_alpha, monkeypatch):
    advance(case_alpha, CaseStatus.ADVISORY_REVIEW)
    author = workflow_actor("analyst")
    assert author_of(case_alpha, get_action("publish_and_close")) == author.pk
    # Meme dote de la capacite, l'auteur reste bloque : le controle porte
    # sur l'utilisateur, pas sur le role.
    monkeypatch.setitem(
        ROLE_CAPABILITIES,
        Role.CSIRT_ANALYST,
        ROLE_CAPABILITIES[Role.CSIRT_ANALYST] | {Capability.PUBLISH_ADVISORY},
    )
    data = {"comment": "Relu", "review_done": True}
    with pytest.raises(TransitionNotAllowed):
        perform_action(case_alpha, "publish_and_close", author, data=data)


def test_rejection_proposer_cannot_confirm(case_alpha, triager, monkeypatch):
    advance(case_alpha, CaseStatus.ACKNOWLEDGED)
    perform_action(case_alpha, "propose_rejection", triager, data={"comment": "Hors sujet"})
    assert author_of(case_alpha, get_action("confirm_rejection")) == triager.pk
    monkeypatch.setitem(
        ROLE_CAPABILITIES,
        Role.TRIAGER,
        ROLE_CAPABILITIES[Role.TRIAGER] | {Capability.ARBITRATE_CASE},
    )
    with pytest.raises(TransitionNotAllowed):
        perform_action(case_alpha, "confirm_rejection", triager, data={"comment": "Ok"})


def test_bounty_proposer_cannot_approve(bounty_case, analyst, monkeypatch):
    perform_action(bounty_case, "propose_bounty", analyst)
    monkeypatch.setitem(
        ROLE_CAPABILITIES,
        Role.CSIRT_ANALYST,
        ROLE_CAPABILITIES[Role.CSIRT_ANALYST] | {Capability.APPROVE_BOUNTY},
    )
    with pytest.raises(TransitionNotAllowed, match="quatre yeux"):
        perform_action(bounty_case, "approve_bounty", analyst, data={"comment": "Ok"})
    bounty_case.refresh_from_db()
    assert bounty_case.bounty_stage == BountyStage.PROPOSED


# ------------------------------------------------------- commentaire exige
@pytest.mark.parametrize(
    "status, action, role",
    [
        (CaseStatus.VALIDATION_PENDING, "validate_qualification", "coordinator"),
        (CaseStatus.ADVISORY_REVIEW, "publish_and_close", "coordinator"),
        (CaseStatus.ACKNOWLEDGED, "request_information", "triager"),
        (CaseStatus.ACKNOWLEDGED, "propose_rejection", "triager"),
    ],
)
def test_comment_is_mandatory(case_alpha, status, action, role):
    advance(case_alpha, status)
    data = {"review_done": True}
    missing = missing_of(
        lambda: perform_action(case_alpha, action, workflow_actor(role), data=data)
    )
    assert missing == ["Commentaire manquant"]


def test_comment_is_mandatory_for_deadline_disclosure(case_alpha):
    """Decision du Coordinateur sur un dossier escalade : commentaire exige."""
    advance(case_alpha, CaseStatus.VENDOR_NOTIFIED)
    type(case_alpha).objects.filter(pk=case_alpha.pk).update(
        vendor_notified_at=timezone.now() - timedelta(days=91)
    )
    case_alpha.refresh_from_db()
    escalate_case(case_alpha, None, "SLA depasse")
    missing = missing_of(
        lambda: perform_action(
            case_alpha, "decide_deadline_disclosure", workflow_actor("coordinator"), data={}
        )
    )
    assert missing == ["Commentaire manquant"]


def test_comment_is_mandatory_for_bounty_approval(bounty_case, analyst, coordinator):
    perform_action(bounty_case, "propose_bounty", analyst)
    missing = missing_of(lambda: perform_action(bounty_case, "approve_bounty", coordinator))
    assert missing == ["Commentaire manquant"]


# ----------------------------------------------------------------- exceptions
def test_information_request_suspends_and_resumes_sla(case_alpha, triager, researcher_a):
    advance(case_alpha, CaseStatus.ACKNOWLEDGED)
    triage_due = case_alpha.sla_events.get(kind=SLAKind.TRIAGE).due_at

    perform_action(
        case_alpha, "request_information", triager, data={"comment": "Quel navigateur ?"}
    )
    assert case_alpha.status == CaseStatus.NEEDS_INFORMATION
    assert case_alpha.return_status == CaseStatus.ACKNOWLEDGED
    assert case_alpha.sla_paused_at is not None
    assert case_alpha.messages.filter(
        confidentiality=Confidentiality.RESEARCHER, is_system=True
    ).exists()

    # Deux jours de suspension : l'echeance est reportee d'autant.
    type(case_alpha).objects.filter(pk=case_alpha.pk).update(
        sla_paused_at=timezone.now() - timedelta(days=2)
    )
    case_alpha.refresh_from_db()
    perform_action(case_alpha, "send_information", researcher_a, data={"comment": "Firefox"})
    case_alpha.refresh_from_db()

    assert case_alpha.status == CaseStatus.ACKNOWLEDGED
    assert case_alpha.return_status == ""
    assert case_alpha.sla_paused_at is None
    delay = case_alpha.sla_events.get(kind=SLAKind.TRIAGE).due_at - triage_due
    assert timedelta(days=2) - timedelta(minutes=5) < delay < timedelta(days=2, minutes=5)


def test_only_reporter_sends_information(case_alpha, triager, researcher_b, analyst):
    advance(case_alpha, CaseStatus.ACKNOWLEDGED)
    perform_action(case_alpha, "request_information", triager, data={"comment": "Precisez"})
    with pytest.raises(TransitionNotAllowed):
        perform_action(case_alpha, "send_information", analyst, data={"comment": "x"})
    with pytest.raises(TransitionNotAllowed):
        perform_action(case_alpha, "send_information", researcher_b, data={"comment": "x"})


def test_no_answer_after_30_days_proposes_rejection(case_alpha, triager, coordinator):
    from apps.coordination.tasks import sweep_needs_information

    advance(case_alpha, CaseStatus.ACKNOWLEDGED)
    perform_action(case_alpha, "request_information", triager, data={"comment": "Precisez"})
    type(case_alpha).objects.filter(pk=case_alpha.pk).update(
        sla_paused_at=timezone.now() - timedelta(days=31)
    )

    assert sweep_needs_information() == 1
    case_alpha.refresh_from_db()
    assert case_alpha.status == CaseStatus.REJECTION_PENDING
    assert case_alpha.return_status == CaseStatus.ACKNOWLEDGED
    # Seulement propose : le Coordinateur peut renvoyer a l'origine.
    perform_action(case_alpha, "return_rejection", coordinator, data={"comment": "Relancer"})
    assert case_alpha.status == CaseStatus.ACKNOWLEDGED


def test_recent_information_request_is_not_swept(case_alpha, triager):
    from apps.coordination.tasks import sweep_needs_information

    advance(case_alpha, CaseStatus.ACKNOWLEDGED)
    perform_action(case_alpha, "request_information", triager, data={"comment": "Precisez"})
    assert sweep_needs_information() == 0


def test_rejection_is_confirmed_by_coordinator(case_alpha, analyst, coordinator):
    advance(case_alpha, CaseStatus.IN_ANALYSIS)
    perform_action(
        case_alpha, "propose_rejection", analyst, data={"comment": "Non reproductible"}
    )
    assert case_alpha.status == CaseStatus.REJECTION_PENDING
    perform_action(case_alpha, "confirm_rejection", coordinator, data={"comment": "Confirme"})
    assert case_alpha.status == CaseStatus.REJECTED
    assert case_alpha.closed_at is not None
    assert not case_alpha.sla_events.filter(state=SLAState.PENDING).exists()
    assert AuditLog.objects.filter(action=AuditAction.REPORT_REJECTED).exists()


def test_rejection_can_be_returned_to_origin(case_alpha, analyst, coordinator):
    advance(case_alpha, CaseStatus.IN_ANALYSIS)
    perform_action(case_alpha, "propose_rejection", analyst, data={"comment": "Doute"})
    perform_action(case_alpha, "return_rejection", coordinator, data={"comment": "A analyser"})
    assert case_alpha.status == CaseStatus.IN_ANALYSIS


def test_rejection_not_available_after_analysis(case_alpha, analyst):
    advance(case_alpha, CaseStatus.VALIDATION_PENDING)
    with pytest.raises(TransitionNotAllowed):
        perform_action(case_alpha, "propose_rejection", analyst, data={"comment": "Trop tard"})


def test_dsi_cannot_reject(case_alpha, dsi_alpha):
    advance(case_alpha, CaseStatus.VENDOR_NOTIFIED)
    with pytest.raises(TransitionNotAllowed):
        perform_action(case_alpha, "propose_rejection", dsi_alpha, data={"comment": "Non"})


def test_duplicate_is_confirmed_and_linked(case_alpha, case_beta, triager, coordinator):
    advance(case_beta, CaseStatus.ACKNOWLEDGED)
    mark_duplicate(case_beta, case_alpha, triager, comment="Meme faille")
    case_beta.refresh_from_db()
    assert case_beta.status == CaseStatus.REJECTION_PENDING
    assert case_beta.duplicate_of_id == case_alpha.id

    perform_action(case_beta, "confirm_rejection", coordinator, data={"comment": "Doublon"})
    assert case_beta.status == CaseStatus.DUPLICATE
    assert AuditLog.objects.filter(action=AuditAction.REPORT_DUPLICATED).exists()


def test_duplicate_does_not_expose_original_to_reporter(
    client_for, case_alpha, case_beta, triager, coordinator, researcher_b
):
    advance(case_beta, CaseStatus.ACKNOWLEDGED)
    mark_duplicate(case_beta, case_alpha, triager, comment="Meme faille")
    case_beta.refresh_from_db()
    perform_action(case_beta, "confirm_rejection", coordinator, data={"comment": "Doublon"})

    response = client_for(researcher_b).get(f"/cases/{case_beta.case_id}/")
    content = response.content.decode()

    assert response.status_code == 200
    assert "doublon" in content.lower()
    # L'identifiant du case original ne doit jamais fuiter vers le declarant.
    assert case_alpha.case_id not in content


def test_case_cannot_be_its_own_duplicate(case_alpha, triager):
    advance(case_alpha, CaseStatus.ACKNOWLEDGED)
    with pytest.raises(TransitionNotAllowed) as info:
        mark_duplicate(case_alpha, case_alpha, triager, comment="Lui-meme")
    assert info.value.missing == ["Un dossier ne peut pas être le doublon de lui-même"]


def test_researcher_cannot_mark_duplicate(case_alpha, case_beta, researcher_a):
    with pytest.raises(TransitionNotAllowed):
        mark_duplicate(case_beta, case_alpha, researcher_a)


def test_return_to_author_from_validation(case_alpha, coordinator):
    advance(case_alpha, CaseStatus.VALIDATION_PENDING)
    perform_action(case_alpha, "return_to_author", coordinator, data={"comment": "CWE faux"})
    assert case_alpha.status == CaseStatus.IN_ANALYSIS


def test_return_to_author_from_advisory_review(case_alpha, coordinator):
    advance(case_alpha, CaseStatus.ADVISORY_REVIEW)
    perform_action(case_alpha, "return_to_author", coordinator, data={"comment": "A revoir"})
    assert case_alpha.status == CaseStatus.FIX_VERIFIED


def test_insufficient_fix_returns_to_remediation(case_alpha, analyst):
    advance(case_alpha, CaseStatus.FIX_AVAILABLE)
    perform_action(
        case_alpha, "insufficient_fix", analyst, data={"comment": "Encore exploitable"}
    )
    assert case_alpha.status == CaseStatus.REMEDIATION_IN_PROGRESS
    assert case_alpha.messages.filter(
        confidentiality=Confidentiality.ORGANIZATION, is_system=True
    ).exists()
    remediation = case_alpha.sla_events.get(kind=SLAKind.REMEDIATION)
    assert remediation.state == SLAState.PENDING


def test_escalation_hands_the_case_to_the_coordinator(case_alpha, coordinator):
    """Etapes 6-7 : le Coordinateur ne voit le dossier qu'une fois escalade.

    L'escalade (automatique, sur SLA depasse) ne change pas le statut mais
    fait du Coordinateur le responsable d'une decision : il voit alors le
    dossier, et une seconde escalade est sans objet.
    """
    advance(case_alpha, CaseStatus.VENDOR_NOTIFIED)
    assert not case_alpha.is_visible_to(coordinator)
    with pytest.raises(OutOfScope):
        perform_action(case_alpha, "escalate", coordinator, data={"comment": "Silence DSI"})

    escalate_case(case_alpha, None, "SLA depasse")
    case_alpha.refresh_from_db()
    assert case_alpha.status == CaseStatus.VENDOR_NOTIFIED
    assert case_alpha.escalated_at is not None
    assert case_alpha.is_visible_to(coordinator)
    assert coordinator.pk in current_owner_ids(case_alpha)
    missing = missing_of(
        lambda: perform_action(case_alpha, "escalate", coordinator, data={"comment": "Encore"})
    )
    assert missing == ["Dossier déjà escaladé"]


def test_sla_escalation_makes_the_case_visible_to_the_coordinator(case_alpha, coordinator):
    from apps.coordination.models import Case
    from apps.coordination.tasks import sweep_sla

    advance(case_alpha, CaseStatus.VENDOR_NOTIFIED)
    assert case_alpha not in Case.objects.visible_to(coordinator)
    case_alpha.sla_events.filter(kind=SLAKind.VENDOR_RESPONSE).update(
        due_at=timezone.now() - timedelta(hours=1)
    )
    sweep_sla()
    assert case_alpha in Case.objects.visible_to(coordinator)


def test_escalation_not_available_before_vendor_notification(case_alpha, coordinator):
    advance(case_alpha, CaseStatus.VALIDATED)
    with pytest.raises(TransitionNotAllowed):
        perform_action(case_alpha, "escalate", coordinator, data={"comment": "Trop tot"})


def test_breached_vendor_sla_escalates_automatically(case_alpha):
    from apps.coordination.tasks import sweep_sla

    advance(case_alpha, CaseStatus.VENDOR_NOTIFIED)
    case_alpha.sla_events.filter(kind=SLAKind.VENDOR_RESPONSE).update(
        due_at=timezone.now() - timedelta(hours=1)
    )
    sweep_sla()
    case_alpha.refresh_from_db()
    assert case_alpha.escalated_at is not None
    assert case_alpha.sla_events.get(kind=SLAKind.VENDOR_RESPONSE).state == SLAState.BREACHED


def test_deadline_disclosure_after_90_days(case_alpha, analyst, coordinator):
    advance(case_alpha, CaseStatus.REMEDIATION_IN_PROGRESS)
    draft_advisory(case_alpha, analyst)
    # Sans decision du Coordinateur, pas d'advisory avant le correctif : le
    # dossier n'est d'ailleurs pas dans le perimetre de l'analyste (etape 7).
    with pytest.raises(TransitionNotAllowed):
        perform_action(case_alpha, "submit_advisory", analyst)
    with pytest.raises(OutOfScope):
        perform_action(
            case_alpha, "decide_deadline_disclosure", coordinator, data={"comment": "Trop tot"}
        )

    # Escalade automatique (SLA depasse) : le Coordinateur devient responsable.
    escalate_case(case_alpha, None, "SLA remediation depasse")
    case_alpha.refresh_from_db()
    missing = missing_of(
        lambda: perform_action(
            case_alpha, "decide_deadline_disclosure", coordinator, data={"comment": "Echeance"}
        )
    )
    assert any("90 jours" in item for item in missing)

    type(case_alpha).objects.filter(pk=case_alpha.pk).update(
        vendor_notified_at=timezone.now() - timedelta(days=91)
    )
    case_alpha.refresh_from_db()
    perform_action(
        case_alpha, "decide_deadline_disclosure", coordinator, data={"comment": "Echeance"}
    )
    assert case_alpha.deadline_disclosure_at is not None
    # La decision rend l'etape a l'analyste (advisory) et la retire au
    # Coordinateur.
    assert analyst.pk in current_owner_ids(case_alpha)
    assert coordinator.pk not in current_owner_ids(case_alpha)

    perform_action(case_alpha, "submit_advisory", analyst)
    assert case_alpha.status == CaseStatus.ADVISORY_REVIEW


# -------------------------------------------------------------- branche prime
def test_vdp_case_is_not_eligible_at_validation(case_alpha):
    advance(case_alpha, CaseStatus.VALIDATED)
    assert case_alpha.bounty_stage == BountyStage.NOT_ELIGIBLE


def test_bounty_case_is_eligible_at_validation(submitted_bounty_case):
    assert submitted_bounty_case.bounty_stage == BountyStage.NONE
    advance(submitted_bounty_case, CaseStatus.VALIDATION_PENDING)
    assert submitted_bounty_case.bounty_stage == BountyStage.NONE
    advance(submitted_bounty_case, CaseStatus.VALIDATED)
    assert submitted_bounty_case.bounty_stage == BountyStage.ELIGIBLE


def test_out_of_tier_proposal_requires_justification(bounty_case, analyst):
    data = {"amount": Decimal("10")}
    missing = missing_of(
        lambda: perform_action(bounty_case, "propose_bounty", analyst, data=data)
    )
    assert missing == ["Montant hors palier : justification écrite obligatoire"]

    data["justification"] = "Impact limite, montant symbolique."
    perform_action(bounty_case, "propose_bounty", analyst, data=data)
    assert bounty_case.bounty_stage == BountyStage.PROPOSED


def test_bounty_approval_credits_wallet(bounty_case, analyst, coordinator, bounty_researcher):
    perform_action(bounty_case, "propose_bounty", analyst, data={"amount": Decimal("900000")})
    perform_action(bounty_case, "approve_bounty", coordinator, data={"comment": "Conforme"})
    bounty_case.refresh_from_db()

    assert bounty_case.bounty_stage == BountyStage.CREDITED
    assert bounty_case.bounty.status == "APPROVED"
    assert wallet_balance(bounty_researcher) == {"XOF": Decimal("900000")}


def test_bounty_can_be_returned_to_proposer(bounty_case, analyst, coordinator):
    perform_action(bounty_case, "propose_bounty", analyst)
    perform_action(bounty_case, "return_bounty", coordinator, data={"comment": "Revoir"})
    assert bounty_case.bounty_stage == BountyStage.ELIGIBLE
    perform_action(bounty_case, "propose_bounty", analyst)
    assert bounty_case.bounty_stage == BountyStage.PROPOSED


def test_bounty_stage_is_independent_of_case_status(bounty_case, analyst):
    perform_action(bounty_case, "propose_bounty", analyst)
    assert bounty_case.status == CaseStatus.VALIDATED

    advance(bounty_case, CaseStatus.REMEDIATION_IN_PROGRESS)
    assert bounty_case.bounty_stage == BountyStage.PROPOSED


def test_bounty_cannot_be_proposed_before_validation(submitted_bounty_case, analyst):
    advance(submitted_bounty_case, CaseStatus.IN_ANALYSIS)
    with pytest.raises(TransitionNotAllowed):
        perform_action(submitted_bounty_case, "propose_bounty", analyst)


# ------------------------------------------------------------------------ SLA
def _delay(case, kind, since):
    return case.sla_events.get(kind=kind).due_at - since


def _close_to(delta, expected):
    return abs(delta - expected) < timedelta(minutes=5)


def test_initial_sla_is_acknowledgement_72h(case_alpha):
    kinds = set(case_alpha.sla_events.values_list("kind", flat=True))
    assert kinds == {SLAKind.ACKNOWLEDGEMENT}
    assert _close_to(
        _delay(case_alpha, SLAKind.ACKNOWLEDGEMENT, case_alpha.created_at), timedelta(hours=72)
    )


def test_acknowledgement_satisfies_sla_and_opens_triage(case_alpha):
    advance(case_alpha, CaseStatus.ACKNOWLEDGED)
    assert case_alpha.sla_events.get(kind=SLAKind.ACKNOWLEDGEMENT).state == SLAState.MET
    assert _close_to(_delay(case_alpha, SLAKind.TRIAGE, timezone.now()), timedelta(days=5))


def test_step_sla_delays_follow_v2(case_alpha):
    advance(case_alpha, CaseStatus.VALIDATION_PENDING)
    assert case_alpha.sla_events.get(kind=SLAKind.TRIAGE).state == SLAState.MET
    assert _close_to(_delay(case_alpha, SLAKind.VALIDATION, timezone.now()), timedelta(days=2))

    advance(case_alpha, CaseStatus.VENDOR_NOTIFIED)
    assert _close_to(
        _delay(case_alpha, SLAKind.VENDOR_RESPONSE, timezone.now()), timedelta(days=5)
    )

    advance(case_alpha, CaseStatus.REMEDIATION_IN_PROGRESS)
    remediation = case_alpha.sla_events.get(kind=SLAKind.REMEDIATION)
    assert timezone.localtime(remediation.due_at).date() == (
        case_alpha.remediation_target_date + timedelta(days=1)
    )

    advance(case_alpha, CaseStatus.FIX_AVAILABLE)
    assert case_alpha.sla_events.get(kind=SLAKind.REMEDIATION).state == SLAState.MET
    assert _close_to(
        _delay(case_alpha, SLAKind.VERIFICATION, timezone.now()), timedelta(days=5)
    )


def test_sla_sweep_marks_breach(case_alpha):
    from apps.coordination.tasks import sweep_sla

    event = case_alpha.sla_events.get(kind=SLAKind.ACKNOWLEDGEMENT)
    event.due_at = timezone.now() - timedelta(hours=1)
    event.save(update_fields=["due_at"])

    result = sweep_sla()
    event.refresh_from_db()
    assert event.state == SLAState.BREACHED
    assert result["breached"] >= 1


def test_sla_color_green_orange_red(case_alpha):
    now = timezone.now()
    events = SLAEvent.objects.filter(case=case_alpha, kind=SLAKind.ACKNOWLEDGEMENT)

    events.update(created_at=now - timedelta(hours=1), due_at=now + timedelta(hours=9))
    assert sla_color(case_alpha) == "sla-ok"

    # 80 % du delai consomme : au-dela du seuil de 75 %.
    events.update(created_at=now - timedelta(hours=8), due_at=now + timedelta(hours=2))
    assert sla_color(case_alpha) == "sla-warning"

    events.update(due_at=now - timedelta(minutes=1))
    assert sla_color(case_alpha) == "sla-breached"


# ---------------------------------------------------------------- severite
def test_set_severity_from_cvss_vector(case_alpha, analyst):
    set_severity(
        case_alpha,
        analyst,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    )
    case_alpha.refresh_from_db()
    assert float(case_alpha.cvss_score) == 9.8
    assert case_alpha.severity == Severity.CRITICAL


def test_invalid_cvss_vector_is_rejected(case_alpha, analyst):
    from django.core.exceptions import ValidationError

    with pytest.raises(ValidationError):
        set_severity(case_alpha, analyst, cvss_vector="CVSS:3.1/AV:X/AC:L")


def test_only_analyst_sets_severity(case_alpha, researcher_a, triager, coordinator):
    from django.core.exceptions import PermissionDenied

    for user in (researcher_a, triager, coordinator):
        with pytest.raises(PermissionDenied):
            set_severity(case_alpha, user, severity=Severity.CRITICAL)


def test_qualification_is_frozen_once_submitted(case_alpha, analyst):
    from django.core.exceptions import ValidationError

    advance(case_alpha, CaseStatus.VALIDATION_PENDING)
    with pytest.raises(ValidationError):
        set_severity(case_alpha, analyst, severity=Severity.LOW)


# -------------------------------------------------------------------- vue web
def _action_url(case, key):
    return reverse("coordination:workflow_action", args=[case.case_id, key])


def test_web_action_applies_button(client_for, case_alpha, triager):
    client = client_for(triager)
    client.get(f"/cases/{case_alpha.case_id}/")  # ouverture du dossier
    response = client.post(_action_url(case_alpha, "acknowledge"), {"comment": "Recu"})
    assert response.status_code == 302
    case_alpha.refresh_from_db()
    assert case_alpha.status == CaseStatus.ACKNOWLEDGED


def test_web_action_rejects_get(client_for, case_alpha, triager):
    response = client_for(triager).get(_action_url(case_alpha, "acknowledge"))
    assert response.status_code == 405


def test_web_action_out_of_scope_is_404(client_for, case_alpha, dsi_beta):
    response = client_for(dsi_beta).post(_action_url(case_alpha, "acknowledge"))
    assert response.status_code == 404


def test_web_action_refused_to_auditor(client_for, case_alpha, auditor):
    opened(case_alpha, auditor)
    response = client_for(auditor).post(_action_url(case_alpha, "acknowledge"))
    assert response.status_code == 403
    case_alpha.refresh_from_db()
    assert case_alpha.status == CaseStatus.SUBMITTED


def test_detail_shows_waiting_owner_to_other_roles(client_for, case_alpha, auditor):
    """L'auditeur, seul a voir un dossier hors etape, lit « En attente de »."""
    advance(case_alpha, CaseStatus.IN_ANALYSIS)
    content = client_for(auditor).get(f"/cases/{case_alpha.case_id}/").content.decode()
    assert "En attente de" in content
    assert "Analyste CSIRT" in content


def test_detail_lists_missing_prerequisites_to_owner(client_for, case_alpha, analyst):
    advance(case_alpha, CaseStatus.IN_ANALYSIS)
    content = client_for(analyst).get(f"/cases/{case_alpha.case_id}/").content.decode()
    assert "Soumettre la qualification" in content
    assert "Vecteur CVSS manquant" in content
    assert "CWE manquant" in content


# ------------------------------------------------ perimetre suivant l'etape
def test_triager_loses_the_case_once_his_step_is_done(client_for, case_alpha, triager):
    """Apres la reception, le dossier sort du perimetre de l'agent de triage."""
    from apps.coordination.models import Case

    url = f"/cases/{case_alpha.case_id}/"
    client = client_for(triager)
    assert client.get(url).status_code == 200
    assert case_alpha in Case.objects.visible_to(triager)

    advance(case_alpha, CaseStatus.IN_ANALYSIS)
    assert client.get(url).status_code == 404
    assert case_alpha not in Case.objects.visible_to(triager)
    assert case_alpha.case_id not in client.get("/cases/").content.decode()


def test_analyst_sees_only_the_cases_of_his_steps(analyst, case_alpha):
    from apps.coordination.models import Case

    assert case_alpha not in Case.objects.visible_to(analyst)  # etape 1 : triage
    advance(case_alpha, CaseStatus.IN_ANALYSIS)
    assert case_alpha in Case.objects.visible_to(analyst)
    advance(case_alpha, CaseStatus.VALIDATION_PENDING)
    assert case_alpha not in Case.objects.visible_to(analyst)
    advance(case_alpha, CaseStatus.VALIDATED)
    assert case_alpha in Case.objects.visible_to(analyst)


def test_coordinator_sees_only_his_steps(coordinator, auditor, case_alpha, triager):
    """Le Coordinateur ne voit que ses etapes ; l'auditeur garde la vue nationale."""
    from apps.coordination.models import Case

    def seen(user):
        case_alpha.refresh_from_db()
        return case_alpha in Case.objects.visible_to(user) and case_alpha.is_visible_to(user)

    expected = {
        CaseStatus.SUBMITTED: False,
        CaseStatus.IN_ANALYSIS: False,
        CaseStatus.VALIDATION_PENDING: True,
        CaseStatus.VALIDATED: False,
        CaseStatus.VENDOR_NOTIFIED: False,
        CaseStatus.FIX_VERIFIED: False,
        CaseStatus.ADVISORY_REVIEW: True,
        CaseStatus.CLOSED: False,
    }
    for status, visible in expected.items():
        advance(case_alpha, status)
        assert seen(coordinator) is visible, status
        assert seen(auditor), status


def test_coordinator_sees_a_pending_rejection(coordinator, triager, case_alpha):
    from apps.coordination.models import Case

    assert case_alpha not in Case.objects.visible_to(coordinator)
    perform_action(case_alpha, "propose_rejection", triager, data={"comment": "Hors sujet"})
    assert case_alpha.status == CaseStatus.REJECTION_PENDING
    assert case_alpha in Case.objects.visible_to(coordinator)


def test_coordinator_sees_a_proposed_bounty(bounty_case, analyst, coordinator):
    """Branche prime : B2 revient au Coordinateur, quel que soit le dossier."""
    from apps.coordination.models import Case

    advance(bounty_case, CaseStatus.VENDOR_NOTIFIED)
    assert bounty_case not in Case.objects.visible_to(coordinator)
    perform_action(bounty_case, "propose_bounty", analyst)
    assert bounty_case.bounty_stage == BountyStage.PROPOSED
    assert bounty_case in Case.objects.visible_to(coordinator)
