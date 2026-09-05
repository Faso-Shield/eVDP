"""Tests du moteur de workflow CVD et Bug Bounty."""

import pytest
from django.core.exceptions import PermissionDenied, ValidationError

from apps.audit.models import AuditAction, AuditLog
from apps.coordination.constants import SLAKind, SLAState, WorkflowType
from apps.coordination.services import (
    mark_duplicate,
    set_severity,
    transition_case,
)
from apps.coordination.workflow import (
    CaseStatus,
    TransitionNotAllowed,
    allowed_targets,
    check_transition,
)
from apps.vulnerabilities.constants import Severity

pytestmark = pytest.mark.django_db


# --------------------------------------------------------- machine a etats pure
def test_forbidden_transition_is_rejected():
    with pytest.raises(TransitionNotAllowed):
        check_transition(CaseStatus.SUBMITTED, CaseStatus.PUBLISHED, WorkflowType.VDP)


def test_cannot_transition_to_same_state():
    with pytest.raises(TransitionNotAllowed):
        check_transition(CaseStatus.TRIAGE, CaseStatus.TRIAGE, WorkflowType.VDP)


def test_closed_is_terminal():
    assert allowed_targets(CaseStatus.CLOSED, WorkflowType.VDP) == []


def test_vdp_nominal_path_is_allowed():
    path = [
        CaseStatus.SUBMITTED,
        CaseStatus.TRIAGE,
        CaseStatus.VALIDATED,
        CaseStatus.VENDOR_CONTACTED,
        CaseStatus.REMEDIATION,
        CaseStatus.FIX_AVAILABLE,
        CaseStatus.VERIFICATION,
        CaseStatus.FIX_VERIFIED,
        CaseStatus.DISCLOSURE_SCHEDULED,
        CaseStatus.PUBLISHED,
        CaseStatus.CLOSED,
    ]
    for current, target in zip(path, path[1:], strict=False):
        assert check_transition(current, target, WorkflowType.VDP) is True


def test_bounty_nominal_path_is_allowed():
    path = [
        CaseStatus.SUBMITTED,
        CaseStatus.TRIAGE,
        CaseStatus.VALIDATED,
        CaseStatus.SEVERITY_ASSIGNED,
        CaseStatus.BOUNTY_REVIEW,
        CaseStatus.REWARD_APPROVED,
        CaseStatus.REMEDIATION,
        CaseStatus.FIX_AVAILABLE,
        CaseStatus.VERIFICATION,
        CaseStatus.FIX_VERIFIED,
        CaseStatus.DISCLOSURE_SCHEDULED,
        CaseStatus.PUBLISHED,
        CaseStatus.CLOSED,
    ]
    for current, target in zip(path, path[1:], strict=False):
        assert check_transition(current, target, WorkflowType.BUG_BOUNTY) is True


def test_bounty_states_not_available_in_vdp_workflow():
    assert CaseStatus.BOUNTY_REVIEW not in allowed_targets(
        CaseStatus.VALIDATED, WorkflowType.VDP
    )


# --------------------------------------------------------------- cote service
def test_case_is_created_from_report(case_alpha, researcher_a):
    assert case_alpha.case_id.startswith("EVDP-")
    assert case_alpha.status == CaseStatus.SUBMITTED
    assert case_alpha.reporter == researcher_a
    assert case_alpha.timeline.count() == 1


def test_case_id_is_sequential(case_alpha, case_beta):
    assert case_alpha.case_id != case_beta.case_id
    numbers = sorted(int(case.case_id.rsplit("-", 1)[1]) for case in (case_alpha, case_beta))
    assert numbers[1] == numbers[0] + 1


def test_transition_records_history_and_audit(case_alpha, coordinator):
    transition_case(case_alpha, CaseStatus.TRIAGE, coordinator, comment="Debut triage")
    case_alpha.refresh_from_db()

    assert case_alpha.status == CaseStatus.TRIAGE
    assert case_alpha.status_history.filter(to_status=CaseStatus.TRIAGE).exists()
    assert AuditLog.objects.filter(
        action=AuditAction.STATUS_CHANGED, object_id=str(case_alpha.pk)
    ).exists()


def test_transition_denied_for_researcher(case_alpha, researcher_a):
    with pytest.raises(TransitionNotAllowed):
        transition_case(case_alpha, CaseStatus.TRIAGE, researcher_a)
    case_alpha.refresh_from_db()
    assert case_alpha.status == CaseStatus.SUBMITTED


def test_denied_transition_is_audited(case_alpha, researcher_a):
    with pytest.raises(TransitionNotAllowed):
        transition_case(case_alpha, CaseStatus.VALIDATED, researcher_a)
    assert AuditLog.objects.filter(action=AuditAction.STATUS_CHANGED, result="DENIED").exists()


def test_analyst_cannot_publish_without_capability(case_alpha, analyst, coordinator):
    for target in [
        CaseStatus.TRIAGE,
        CaseStatus.VALIDATED,
        CaseStatus.VENDOR_CONTACTED,
        CaseStatus.REMEDIATION,
        CaseStatus.FIX_AVAILABLE,
        CaseStatus.VERIFICATION,
        CaseStatus.FIX_VERIFIED,
        CaseStatus.DISCLOSURE_SCHEDULED,
    ]:
        transition_case(case_alpha, target, coordinator)
    with pytest.raises(TransitionNotAllowed):
        transition_case(case_alpha, CaseStatus.PUBLISHED, analyst)


def test_validation_sets_timestamp_and_reputation(case_alpha, coordinator, researcher_a):
    transition_case(case_alpha, CaseStatus.TRIAGE, coordinator)
    transition_case(case_alpha, CaseStatus.VALIDATED, coordinator)
    case_alpha.refresh_from_db()
    profile = researcher_a.researcher_profile
    profile.refresh_from_db()

    assert case_alpha.validated_at is not None
    assert profile.reputation > 0
    assert profile.reports_validated == 1


def test_reputation_is_not_granted_twice(case_alpha, coordinator, researcher_a):
    from apps.researchers.services import award_reputation

    transition_case(case_alpha, CaseStatus.TRIAGE, coordinator)
    transition_case(case_alpha, CaseStatus.VALIDATED, coordinator)
    profile = researcher_a.researcher_profile
    profile.refresh_from_db()
    first = profile.reputation

    award_reputation(researcher_a, case_alpha, granted_by=coordinator)
    profile.refresh_from_db()
    assert profile.reputation == first


def test_critical_severity_grants_bonus(case_alpha, coordinator, researcher_a):
    set_severity(case_alpha, coordinator, severity=Severity.CRITICAL)
    transition_case(case_alpha, CaseStatus.TRIAGE, coordinator)
    transition_case(case_alpha, CaseStatus.VALIDATED, coordinator)
    profile = researcher_a.researcher_profile
    profile.refresh_from_db()
    # 10 (valide) + 50 (critique)
    assert profile.reputation == 60


# ------------------------------------------------------------------------ SLA
def test_initial_sla_events_are_created(case_alpha):
    kinds = set(case_alpha.sla_events.values_list("kind", flat=True))
    assert SLAKind.ACKNOWLEDGEMENT in kinds
    assert SLAKind.TRIAGE in kinds


def test_acknowledgement_satisfies_sla(case_alpha, coordinator):
    transition_case(case_alpha, CaseStatus.RECEIVED, coordinator)
    event = case_alpha.sla_events.get(kind=SLAKind.ACKNOWLEDGEMENT)
    assert event.state == SLAState.MET


def test_sla_sweep_marks_breach(case_alpha, coordinator):
    from datetime import timedelta

    from django.utils import timezone

    from apps.coordination.tasks import sweep_sla

    event = case_alpha.sla_events.get(kind=SLAKind.ACKNOWLEDGEMENT)
    event.due_at = timezone.now() - timedelta(hours=1)
    event.save(update_fields=["due_at"])

    result = sweep_sla()
    event.refresh_from_db()
    assert event.state == SLAState.BREACHED
    assert result["breached"] >= 1


# ------------------------------------------------------------------- doublons
def test_mark_duplicate_links_original(case_alpha, case_beta, coordinator):
    from apps.coordination.services import transition_case as move

    move(case_beta, CaseStatus.TRIAGE, coordinator)
    mark_duplicate(case_beta, case_alpha, coordinator, comment="Meme faille")
    case_beta.refresh_from_db()

    assert case_beta.status == CaseStatus.DUPLICATE
    assert case_beta.duplicate_of_id == case_alpha.id


def test_duplicate_does_not_expose_original_to_reporter(
    client_for, case_alpha, case_beta, coordinator, researcher_b
):
    transition_case(case_beta, CaseStatus.TRIAGE, coordinator)
    mark_duplicate(case_beta, case_alpha, coordinator)

    client = client_for(researcher_b)
    response = client.get(f"/cases/{case_beta.case_id}/")
    content = response.content.decode()

    assert response.status_code == 200
    assert "doublon" in content.lower()
    # L'identifiant du case original ne doit jamais fuiter vers le declarant.
    assert case_alpha.case_id not in content


def test_case_cannot_be_its_own_duplicate(case_alpha, coordinator):
    transition_case(case_alpha, CaseStatus.TRIAGE, coordinator)
    with pytest.raises(ValidationError):
        mark_duplicate(case_alpha, case_alpha, coordinator)


def test_researcher_cannot_mark_duplicate(case_alpha, case_beta, researcher_a):
    with pytest.raises(PermissionDenied):
        mark_duplicate(case_beta, case_alpha, researcher_a)


# ------------------------------------------------------------------- severite
def test_set_severity_from_cvss_vector(case_alpha, coordinator):
    set_severity(
        case_alpha,
        coordinator,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    )
    case_alpha.refresh_from_db()
    assert float(case_alpha.cvss_score) == 9.8
    assert case_alpha.severity == Severity.CRITICAL


def test_invalid_cvss_vector_is_rejected(case_alpha, coordinator):
    with pytest.raises(ValidationError):
        set_severity(case_alpha, coordinator, cvss_vector="CVSS:3.1/AV:X/AC:L")


def test_researcher_cannot_set_severity(case_alpha, researcher_a):
    with pytest.raises(PermissionDenied):
        set_severity(case_alpha, researcher_a, severity=Severity.CRITICAL)
