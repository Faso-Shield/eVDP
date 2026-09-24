"""Tests du workflow v2 (SPEC-eVDP-2026-V2) : un bouton, un role.

Couvre le chemin principal, les six controles de check_transition(), les
sorties d'exception, la branche prime / Wallet, les SLA et la matrice de
visibilite.
"""

from datetime import timedelta
from decimal import Decimal

import pytest
from django.core.exceptions import PermissionDenied, ValidationError
from django.urls import reverse
from django.utils import timezone

from apps.audit.models import AuditAction, AuditLog
from apps.coordination.constants import Confidentiality, SLAKind, SLAState
from apps.coordination.scenarios import open_case
from apps.coordination.services import (
    escalate_case,
    post_message,
    propose_duplicate,
    record_admissibility,
    record_remediation_plan,
    set_severity,
    transition_case,
)
from apps.coordination.workflow import (
    VDP_TRANSITIONS,
    CaseBountyStatus,
    CaseStatus,
    TransitionNotAllowed,
    button_for,
    primary_transition,
)
from apps.vulnerabilities.constants import Severity

from .conftest import make_user

pytestmark = pytest.mark.django_db

S = CaseStatus


# ------------------------------------------------------------ table statique
def test_eleven_main_steps_and_four_exceptions():
    assert len(S.values) == 15
    exceptions = {S.NEEDS_INFORMATION, S.REJECTION_PENDING}
    main = [t for t in VDP_TRANSITIONS if t.primary and t.source not in exceptions]
    assert len(main) == 10  # 10 clics de la soumission a la cloture


@pytest.mark.parametrize("status", S.values)
def test_at_most_one_primary_button_per_status(status):
    assert len([t for t in VDP_TRANSITIONS if t.source == status and t.primary]) <= 1


def test_terminal_states_have_no_button():
    for status in (S.CLOSED, S.REJECTED, S.DUPLICATE):
        assert primary_transition(status) is None


def test_four_eyes_and_comment_on_steps_4_and_10():
    for action in ("validate_qualification", "publish_and_close", "confirm_rejection"):
        transition = next(t for t in VDP_TRANSITIONS if t.action == action)
        assert transition.four_eyes and transition.comment_required


def test_exceptions_are_never_primary():
    for action in (
        "request_information",
        "propose_rejection",
        "propose_duplicate",
        "send_back_qualification",
        "send_back_advisory",
        "reject_fix",
    ):
        assert all(not t.primary for t in VDP_TRANSITIONS if t.action == action)


# ------------------------------------------------------------ chemin nominal
def test_full_path_each_step_by_its_owner(case_alpha, advance, coordinator):
    advance(case_alpha, S.CLOSED)
    assert case_alpha.status == S.CLOSED
    assert case_alpha.is_published is True
    assert case_alpha.closed_at is not None
    # Un seul acteur par etape, trace dans l'historique.
    actions = list(
        case_alpha.status_history.order_by("created_at").values_list("to_status", flat=True)
    )
    assert actions == [
        S.ACKNOWLEDGED,
        S.IN_ANALYSIS,
        S.VALIDATION_PENDING,
        S.VALIDATED,
        S.VENDOR_NOTIFIED,
        S.REMEDIATION_IN_PROGRESS,
        S.FIX_AVAILABLE,
        S.FIX_VERIFIED,
        S.ADVISORY_REVIEW,
        S.CLOSED,
    ]
    advisory = case_alpha.current_advisory()
    assert advisory.is_published and advisory.published_by == coordinator


def test_received_status_no_longer_exists():
    assert "RECEIVED" not in S.values


def test_case_is_created_from_report(case_alpha, researcher_a):
    assert case_alpha.case_id.startswith("EVDP-")
    assert case_alpha.status == S.SUBMITTED
    assert case_alpha.reporter == researcher_a
    assert case_alpha.attachments.count() == 1


# ----------------------------------------------------- 1. transition existe
def test_unknown_action_is_refused(case_alpha, coordinator):
    with pytest.raises(TransitionNotAllowed) as exc:
        transition_case(case_alpha, "publish_and_close", coordinator, comment="x")
    assert exc.value.code == "invalid_transition"


# ------------------------------------------------------------- 2. perimetre
def test_out_of_scope_user_gets_not_found(case_alpha, researcher_b):
    with pytest.raises(TransitionNotAllowed) as exc:
        transition_case(case_alpha, "provide_information", researcher_b, comment="x")
    assert exc.value.code in ("invalid_transition", "not_found")


def test_view_returns_404_out_of_scope(client_for, case_alpha, dsi_beta):
    response = client_for(dsi_beta).post(
        reverse("coordination:workflow_action", args=[case_alpha.case_id]),
        {"action": "acknowledge"},
    )
    assert response.status_code == 404


# ------------------------------------------------------------- 3. capacite
def test_only_triager_acknowledges(case_alpha, coordinator, analyst, triager):
    for user in (coordinator, analyst):
        open_case(case_alpha, user)
        with pytest.raises(TransitionNotAllowed) as exc:
            transition_case(case_alpha, "acknowledge", user)
        assert exc.value.code == "forbidden"
    open_case(case_alpha, triager)
    transition_case(case_alpha, "acknowledge", triager)
    assert case_alpha.status == S.ACKNOWLEDGED


def test_denied_transition_is_audited(case_alpha, researcher_a):
    with pytest.raises(TransitionNotAllowed):
        transition_case(case_alpha, "acknowledge", researcher_a)
    assert AuditLog.objects.filter(
        action=AuditAction.STATUS_CHANGED, result="DENIED", object_id=str(case_alpha.pk)
    ).exists()
    case_alpha.refresh_from_db()
    assert case_alpha.status == S.SUBMITTED


def test_dsi_cannot_reject(case_alpha, advance, dsi_alpha):
    advance(case_alpha, S.VENDOR_NOTIFIED)
    with pytest.raises(TransitionNotAllowed):
        transition_case(case_alpha, "propose_rejection", dsi_alpha, comment="Conteste")


def test_auditor_clicks_nothing(case_alpha, auditor):
    open_case(case_alpha, auditor)
    assert button_for(case_alpha, auditor)["kind"] == "waiting"
    with pytest.raises(TransitionNotAllowed):
        transition_case(case_alpha, "acknowledge", auditor)


# ----------------------------------------------------------- 4. pre-requis
def test_acknowledge_requires_opening_the_case(case_alpha, triager):
    button = button_for(case_alpha, triager)
    assert button["kind"] == "button" and button["enabled"] is False
    assert button["missing"] == ["Ouvrir le dossier"]
    with pytest.raises(TransitionNotAllowed) as exc:
        transition_case(case_alpha, "acknowledge", triager)
    assert exc.value.code == "prerequisites"


def test_opening_the_page_satisfies_the_prerequisite(client_for, case_alpha, triager):
    client = client_for(triager)
    client.get(reverse("coordination:case_detail", args=[case_alpha.case_id]))
    assert button_for(case_alpha, triager)["enabled"] is True


def test_admissibility_checklist_is_required(case_alpha, advance, triager):
    advance(case_alpha, S.ACKNOWLEDGED)
    record_admissibility(case_alpha, triager, True, True, False)
    with pytest.raises(TransitionNotAllowed) as exc:
        transition_case(case_alpha, "declare_admissible", triager)
    assert "Checklist de recevabilité incomplète" in exc.value.missing


def test_qualification_requires_cvss_by_an_analyst(case_alpha, advance, analyst):
    """Le vecteur fourni par le declarant ne vaut pas qualification."""
    advance(case_alpha, S.IN_ANALYSIS)
    case_alpha.cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    case_alpha.save(update_fields=["cvss_vector"])
    missing = button_for(case_alpha, analyst)["missing"]
    assert "Vecteur CVSS manquant (saisi par un analyste)" in missing
    assert "CWE manquante" in missing


def test_qualification_accepts_cvss_v4(case_alpha, advance, analyst, cwe):
    advance(case_alpha, S.IN_ANALYSIS)
    set_severity(
        case_alpha,
        analyst,
        cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    )
    case_alpha.cwe = cwe
    case_alpha.save(update_fields=["cwe"])
    transition_case(case_alpha, "submit_qualification", analyst)
    assert case_alpha.status == S.VALIDATION_PENDING
    assert float(case_alpha.cvss_score) == 9.3
    assert case_alpha.severity == Severity.CRITICAL


def test_triager_cannot_set_cvss(case_alpha, triager):
    with pytest.raises(PermissionDenied):
        set_severity(case_alpha, triager, severity=Severity.CRITICAL)


def test_qualification_is_locked_once_submitted(case_alpha, advance, analyst):
    advance(case_alpha, S.VALIDATION_PENDING)
    with pytest.raises(ValidationError):
        set_severity(case_alpha, analyst, severity=Severity.LOW)


def test_remediation_date_bounded_by_severity(case_alpha, advance, dsi_alpha):
    advance(case_alpha, S.VENDOR_NOTIFIED)  # severite HIGH : 60 jours
    too_late = timezone.localdate() + timedelta(days=61)
    with pytest.raises(ValidationError):
        record_remediation_plan(case_alpha, dsi_alpha, "Plan", too_late)
    record_remediation_plan(
        case_alpha, dsi_alpha, "Plan", timezone.localdate() + timedelta(days=60)
    )


def test_publication_blocked_until_bounty_settled(bounty_case, advance, coordinator):
    advance(bounty_case, S.ADVISORY_REVIEW)
    assert bounty_case.bounty_status == CaseBountyStatus.BOUNTY_ELIGIBLE
    button = button_for(bounty_case, coordinator)
    assert button["enabled"] is False
    assert "Prime ni créditée ni déclarée non éligible" in button["missing"]


def test_unsanitized_advisory_blocks_submission(case_alpha, advance, analyst):
    from apps.disclosures.services import create_advisory_from_case

    advance(case_alpha, S.FIX_VERIFIED)
    create_advisory_from_case(case_alpha, analyst, summary="Cible : https://10.1.2.3/admin")
    with pytest.raises(TransitionNotAllowed) as exc:
        transition_case(case_alpha, "submit_advisory", analyst)
    assert exc.value.code == "prerequisites"


# ------------------------------------------------------------ 5. quatre yeux
def test_validator_must_differ_from_qualifier(case_alpha, advance, analyst):
    """Un analyste senior ne valide jamais sa propre qualification."""
    analyst.is_senior_analyst = True
    analyst.save(update_fields=["is_senior_analyst"])
    advance(case_alpha, S.VALIDATION_PENDING)
    with pytest.raises(TransitionNotAllowed):
        transition_case(case_alpha, "validate_qualification", analyst, comment="OK")


def test_senior_analyst_validates_a_peer(case_alpha, advance):
    senior = make_user("senior@test.bf", "CSIRT_ANALYST", is_senior_analyst=True)
    advance(case_alpha, S.VALIDATION_PENDING)
    transition_case(case_alpha, "validate_qualification", senior, comment="Relu.")
    assert case_alpha.status == S.VALIDATED


def test_senior_flag_has_no_effect_on_other_roles(db):
    triager = make_user("t2@test.bf", "TRIAGER", is_senior_analyst=True)
    assert not triager.has_capability("VALIDATE_SEVERITY")


def test_four_eyes_compares_users_not_roles(case_alpha, advance, coordinator, coordinator_b):
    advance(case_alpha, S.IN_ANALYSIS)
    transition_case(
        case_alpha,
        "propose_rejection",
        make_user("an2@test.bf", "CSIRT_ANALYST"),
        comment="Hors perimetre",
    )
    transition_case(case_alpha, "confirm_rejection", coordinator, comment="Confirme")
    assert case_alpha.status == S.REJECTED


def test_publisher_differs_from_advisory_submitter(case_alpha, advance, analyst):
    advance(case_alpha, S.ADVISORY_REVIEW)
    analyst.role = "NATIONAL_COORDINATOR"
    analyst.save(update_fields=["role"])
    with pytest.raises(TransitionNotAllowed) as exc:
        transition_case(case_alpha, "publish_and_close", analyst, comment="OK")
    assert exc.value.code == "four_eyes"


# ------------------------------------------------------------- 6. commentaire
def test_validation_requires_comment(case_alpha, advance, coordinator):
    advance(case_alpha, S.VALIDATION_PENDING)
    with pytest.raises(TransitionNotAllowed) as exc:
        transition_case(case_alpha, "validate_qualification", coordinator, comment="  ")
    assert exc.value.code == "comment_required"


# ------------------------------------------------------ interface : bouton
def test_waiting_label_for_non_owner(case_alpha, researcher_a, coordinator):
    assert button_for(case_alpha, coordinator) == {
        "kind": "waiting",
        "waiting_for": ["Agent de triage"],
    }


def test_detail_page_shows_single_greyed_button(client_for, case_alpha, analyst, advance):
    advance(case_alpha, S.IN_ANALYSIS)
    page = (
        client_for(analyst)
        .get(reverse("coordination:case_detail", args=[case_alpha.case_id]))
        .content.decode()
    )
    assert "Soumettre la qualification" in page
    assert "Vecteur CVSS manquant" in page
    assert "disabled" in page


# -------------------------------------------------------------- exceptions
def test_information_request_suspends_sla_and_returns(
    case_alpha, advance, analyst, researcher_a
):
    advance(case_alpha, S.IN_ANALYSIS)
    transition_case(case_alpha, "request_information", analyst, comment="Quelle version ?")
    triage = case_alpha.sla_events.get(kind=SLAKind.TRIAGE)
    assert triage.state == SLAState.SUSPENDED
    assert case_alpha.status_before_exception == S.IN_ANALYSIS
    # Le declarant voit son propre bouton, et lui seul.
    assert button_for(case_alpha, researcher_a)["action"] == "provide_information"
    transition_case(case_alpha, "provide_information", researcher_a, comment="v2.3")
    assert case_alpha.status == S.IN_ANALYSIS
    triage.refresh_from_db()
    assert triage.state == SLAState.PENDING


def test_information_timeout_proposes_rejection(case_alpha, advance, analyst):
    from apps.coordination.tasks import sweep_information_requests

    advance(case_alpha, S.IN_ANALYSIS)
    transition_case(case_alpha, "request_information", analyst, comment="Details ?")
    entry = case_alpha.status_history.get(to_status=S.NEEDS_INFORMATION)
    type(entry).objects.filter(pk=entry.pk).update(
        created_at=timezone.now() - timedelta(days=31)
    )
    assert sweep_information_requests() == 1
    case_alpha.refresh_from_db()
    assert case_alpha.status == S.REJECTION_PENDING
    assert case_alpha.status_before_exception == S.IN_ANALYSIS


def test_rejection_is_proposed_then_confirmed(case_alpha, triager, coordinator):
    transition_case(case_alpha, "propose_rejection", triager, comment="Hors perimetre")
    assert case_alpha.status == S.REJECTION_PENDING
    transition_case(case_alpha, "confirm_rejection", coordinator, comment="Confirme")
    assert case_alpha.status == S.REJECTED
    assert AuditLog.objects.filter(action=AuditAction.REPORT_REJECTED).exists()


def test_rejection_can_be_sent_back_to_origin(case_alpha, advance, analyst, coordinator):
    advance(case_alpha, S.IN_ANALYSIS)
    transition_case(case_alpha, "propose_rejection", analyst, comment="Doute")
    transition_case(case_alpha, "cancel_rejection", coordinator, comment="A instruire")
    assert case_alpha.status == S.IN_ANALYSIS
    assert case_alpha.status_before_exception == ""


def test_duplicate_is_proposed_then_confirmed(case_alpha, case_beta, triager, coordinator):
    propose_duplicate(case_beta, case_alpha, triager, comment="Meme faille")
    case_beta.refresh_from_db()
    assert case_beta.status == S.REJECTION_PENDING
    transition_case(case_beta, "confirm_rejection", coordinator, comment="Doublon")
    assert case_beta.status == S.DUPLICATE
    assert case_beta.duplicate_of_id == case_alpha.id


def test_duplicate_does_not_expose_original_to_reporter(
    client_for, case_alpha, case_beta, triager, coordinator, researcher_b
):
    propose_duplicate(case_beta, case_alpha, triager, comment="Meme faille")
    transition_case(case_beta, "confirm_rejection", coordinator, comment="Doublon")
    content = client_for(researcher_b).get(f"/cases/{case_beta.case_id}/").content.decode()
    assert "doublon" in content.lower()
    assert case_alpha.case_id not in content


def test_case_cannot_be_its_own_duplicate(case_alpha, triager):
    with pytest.raises(ValidationError):
        propose_duplicate(case_alpha, case_alpha, triager, comment="x")


def test_send_back_qualification(case_alpha, advance, coordinator):
    advance(case_alpha, S.VALIDATION_PENDING)
    transition_case(case_alpha, "send_back_qualification", coordinator, comment="CWE ?")
    assert case_alpha.status == S.IN_ANALYSIS


def test_insufficient_fix_goes_back_to_remediation(case_alpha, advance, analyst):
    advance(case_alpha, S.FIX_AVAILABLE)
    transition_case(case_alpha, "reject_fix", analyst, comment="Toujours exploitable")
    assert case_alpha.status == S.REMEDIATION_IN_PROGRESS


def test_send_back_advisory_returns_draft(case_alpha, advance, coordinator):
    from apps.disclosures.models import AdvisoryStatus

    advance(case_alpha, S.ADVISORY_REVIEW)
    assert case_alpha.current_advisory().status == AdvisoryStatus.IN_REVIEW
    transition_case(case_alpha, "send_back_advisory", coordinator, comment="Reformuler")
    assert case_alpha.status == S.FIX_VERIFIED
    assert case_alpha.current_advisory().status == AdvisoryStatus.DRAFT


def test_manual_escalation_by_coordinator(case_alpha, advance, coordinator, analyst):
    advance(case_alpha, S.REMEDIATION_IN_PROGRESS)
    with pytest.raises(PermissionDenied):
        escalate_case(case_alpha, analyst, comment="Retard")
    escalate_case(case_alpha, coordinator, comment="Organisation muette")
    assert case_alpha.escalated_at is not None
    assert AuditLog.objects.filter(action=AuditAction.CASE_ESCALATED).exists()


def test_sla_breach_escalates_automatically(case_alpha, coordinator):
    from apps.coordination.tasks import sweep_sla

    event = case_alpha.sla_events.get(kind=SLAKind.ACKNOWLEDGEMENT)
    event.due_at = timezone.now() - timedelta(hours=1)
    event.save(update_fields=["due_at"])
    assert sweep_sla()["breached"] >= 1
    case_alpha.refresh_from_db()
    assert case_alpha.escalated_at is not None
    assert coordinator.notifications.filter(kind="CASE_ESCALATED").exists()


# ------------------------------------------------------------------- SLA
def test_initial_sla_events_are_created(case_alpha):
    kinds = set(case_alpha.sla_events.values_list("kind", flat=True))
    assert {SLAKind.ACKNOWLEDGEMENT, SLAKind.TRIAGE} <= kinds


def test_acknowledgement_satisfies_sla(case_alpha, advance):
    advance(case_alpha, S.ACKNOWLEDGED)
    assert case_alpha.sla_events.get(kind=SLAKind.ACKNOWLEDGEMENT).state == SLAState.MET


def test_step_slas_follow_the_path(case_alpha, advance):
    advance(case_alpha, S.VALIDATION_PENDING)
    assert case_alpha.sla_events.get(kind=SLAKind.VALIDATION).state == SLAState.PENDING
    advance(case_alpha, S.REMEDIATION_IN_PROGRESS)
    remediation = case_alpha.sla_events.get(kind=SLAKind.REMEDIATION)
    assert remediation.due_at.date() == case_alpha.remediation_due_date
    assert case_alpha.sla_events.get(kind=SLAKind.VENDOR_RESPONSE).state == SLAState.MET


def test_kanban_badge_colors(case_alpha, sla_policy):
    event = case_alpha.sla_events.get(kind=SLAKind.ACKNOWLEDGEMENT)
    assert case_alpha.sla_badge() == "green"
    event.created_at = timezone.now() - timedelta(hours=60)
    event.due_at = timezone.now() + timedelta(hours=12)  # 83 % ecoule
    event.save(update_fields=["created_at", "due_at"])
    assert case_alpha.sla_badge() == "orange"
    event.due_at = timezone.now() - timedelta(minutes=1)
    event.save(update_fields=["due_at"])
    assert case_alpha.sla_badge() == "red"


# ------------------------------------------------------- branche prime / Wallet
def test_bounty_branch_opens_at_validation(bounty_case, case_alpha, advance):
    advance(bounty_case, S.VALIDATED)
    advance(case_alpha, S.VALIDATED)
    assert bounty_case.bounty_status == CaseBountyStatus.BOUNTY_ELIGIBLE
    assert case_alpha.bounty_status == CaseBountyStatus.NOT_ELIGIBLE


def test_bounty_then_close(bounty_case, advance, analyst, coordinator, bounty_researcher):
    from apps.bounty.models import WalletEntry
    from apps.bounty.services import approve_bounty, propose_bounty, wallet_balances

    advance(bounty_case, S.VALIDATED)
    bounty = propose_bounty(bounty_case, analyst, amount=Decimal("400000"))
    bounty_case.refresh_from_db()
    assert bounty_case.bounty_status == CaseBountyStatus.BOUNTY_PROPOSED
    approve_bounty(bounty, coordinator, note="Palier respecte")
    bounty_case.refresh_from_db()
    assert bounty_case.bounty_status == CaseBountyStatus.BOUNTY_CREDITED
    assert wallet_balances(bounty_researcher) == {"XOF": Decimal("400000.00")}
    assert WalletEntry.objects.filter(kind="CREDIT").count() == 1

    advance(bounty_case, S.CLOSED)
    assert bounty_case.status == S.CLOSED


def test_bounty_requires_eligibility(bounty_case, analyst):
    from apps.bounty.services import propose_bounty

    with pytest.raises(ValidationError, match="éligible"):
        propose_bounty(bounty_case, analyst, amount=Decimal("100000"))


def test_out_of_tier_bounty_requires_justification(bounty_case, advance, analyst):
    from apps.bounty.services import propose_bounty

    advance(bounty_case, S.VALIDATED)
    with pytest.raises(ValidationError, match="justification"):
        propose_bounty(bounty_case, analyst, amount=Decimal("9"))
    propose_bounty(bounty_case, analyst, amount=Decimal("9"), justification="Geste symbolique")


def test_bounty_send_back(bounty_case, advance, analyst, coordinator):
    from apps.bounty.services import propose_bounty, send_back_bounty

    advance(bounty_case, S.VALIDATED)
    bounty = propose_bounty(bounty_case, analyst, amount=Decimal("400000"))
    with pytest.raises(ValidationError):
        send_back_bounty(bounty, coordinator, comment="")
    send_back_bounty(bounty, coordinator, comment="Revoir le palier")
    bounty_case.refresh_from_db()
    assert bounty_case.bounty_status == CaseBountyStatus.BOUNTY_ELIGIBLE


def test_wallet_is_append_only(bounty_researcher, coordinator):
    from apps.bounty.services import adjust_wallet, wallet_balances

    entry = adjust_wallet(bounty_researcher, "1500", coordinator, note="Correction")
    entry.amount = Decimal("999999")
    with pytest.raises(ValidationError):
        entry.save()
    with pytest.raises(ValidationError):
        entry.delete()
    assert wallet_balances(bounty_researcher) == {"XOF": Decimal("1500.00")}


def test_dsi_never_sees_the_wallet(client_for, bounty_case, advance, analyst, dsi_alpha):
    from apps.bounty.services import propose_bounty

    advance(bounty_case, S.VALIDATED)
    bounty = propose_bounty(bounty_case, analyst, amount=Decimal("400000"))
    advance(bounty_case, S.VENDOR_NOTIFIED)
    client = client_for(dsi_alpha)
    assert client.get(reverse("bounty:detail", args=[bounty.pk])).status_code == 404
    page = client.get(reverse("coordination:case_detail", args=[bounty_case.case_id]))
    assert page.status_code == 200
    assert "400 000" not in page.content.decode()


# -------------------------------------------------------- matrice de visibilite
def test_reporter_sees_simplified_status(client_for, case_alpha, advance, researcher_a):
    advance(case_alpha, S.VALIDATION_PENDING)
    page = (
        client_for(researcher_a)
        .get(reverse("coordination:case_detail", args=[case_alpha.case_id]))
        .content.decode()
    )
    assert "En analyse" in page
    assert "Qualification à valider" not in page
    assert "CVSS" not in page


def test_super_admin_has_no_access_to_cases(client_for, case_alpha):
    admin = make_user("root@test.bf", "SUPER_ADMIN", is_superuser=True, is_staff=True)
    assert not admin.has_capability("VIEW_ALL_CASES")
    assert not admin.has_capability("PUBLISH_ADVISORY")
    response = client_for(admin).get(
        reverse("coordination:case_detail", args=[case_alpha.case_id])
    )
    assert response.status_code == 404


def test_auditor_sees_metadata_only(client_for, case_alpha, auditor):
    page = (
        client_for(auditor)
        .get(reverse("coordination:case_detail", args=[case_alpha.case_id]))
        .content.decode()
    )
    assert case_alpha.case_id in page
    assert case_alpha.report.description not in page


def test_organization_sees_vendor_version_not_the_report(
    client_for, case_alpha, advance, dsi_alpha
):
    advance(case_alpha, S.VENDOR_NOTIFIED)
    page = (
        client_for(dsi_alpha)
        .get(reverse("coordination:case_detail", args=[case_alpha.case_id]))
        .content.decode()
    )
    assert "version organisation" in page.lower()
    assert case_alpha.report.steps_to_reproduce.splitlines()[0] not in page
    assert "chercheur-a@test.bf" not in page


def test_channels_are_sealed(case_alpha, advance, analyst, dsi_alpha, researcher_a):
    from apps.coordination.services import visible_messages

    advance(case_alpha, S.VENDOR_NOTIFIED)
    post_message(case_alpha, analyst, "Au chercheur", Confidentiality.PARTICIPANTS)
    post_message(case_alpha, analyst, "A l'organisation", Confidentiality.ORGANIZATION)
    assert [m.body for m in visible_messages(case_alpha, researcher_a)] == ["Au chercheur"]
    assert [m.body for m in visible_messages(case_alpha, dsi_alpha)] == ["A l'organisation"]
    with pytest.raises(PermissionDenied):
        post_message(case_alpha, dsi_alpha, "Au chercheur", Confidentiality.PARTICIPANTS)


def test_reporter_evidence_is_read_only(case_alpha):
    attachment = case_alpha.attachments.get()
    with pytest.raises(ValidationError):
        attachment.delete()


def test_web_submission_without_attachment_is_refused(client):
    from apps.coordination.models import Case

    client.post(
        reverse("reports:submit"),
        {
            "title": "Faille sans preuve",
            "vulnerability_type": "XSS",
            "reported_severity": "MEDIUM",
            "description": "Une description assez longue pour passer la validation.",
            "accept_policy": "on",
            "contact_email": "x@exemple.bf",
        },
    )
    assert Case.objects.count() == 0


# ------------------------------------------------------------------ reputation
def test_validation_sets_timestamp_and_reputation(case_alpha, advance, researcher_a):
    advance(case_alpha, S.VALIDATED)
    profile = researcher_a.researcher_profile
    profile.refresh_from_db()
    assert case_alpha.validated_at is not None
    assert profile.reputation > 0
    assert profile.reports_validated == 1
