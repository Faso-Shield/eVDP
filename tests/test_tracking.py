"""Tests du suivi de dossier sans compte (lien email + code de suivi anonyme)."""

from datetime import timedelta

import pytest
from django.core import mail
from django.urls import reverse
from django.utils import timezone

from apps.coordination.models import CaseTrackingToken
from apps.coordination.services import (
    generate_tracking_token,
    public_status_for,
    resolve_tracking_token,
)
from apps.coordination.workflow import CaseStatus

from .conftest import evidence

pytestmark = pytest.mark.django_db


def form_payload(**overrides):
    payload = {
        "title": "Faille sur le portail de demonstration",
        "product": "Portail demo",
        "affected_organization_name": "Ministere Alpha",
        "vulnerability_type": "XSS",
        "reported_severity": "MEDIUM",
        "description": "Une description assez longue pour passer la validation metier.",
        "steps_to_reproduce": "1. Ouvrir la page\n2. Injecter le payload",
        "impact": "Vol de session utilisateur.",
        "accept_policy": "on",
        "attachments": evidence(),
    }
    payload.update(overrides)
    return payload


# ------------------------------------------------------------------ generation
def test_generate_and_resolve_tracking_token(case_alpha):
    raw = generate_tracking_token(case_alpha)
    assert resolve_tracking_token(raw) == case_alpha


def test_resolve_rejects_unknown_token():
    assert resolve_tracking_token("un-code-invente") is None


def test_resolve_rejects_expired_token(case_alpha):
    raw = generate_tracking_token(case_alpha)
    token = CaseTrackingToken.objects.get(case=case_alpha)
    token.expires_at = timezone.now() - timedelta(days=1)
    token.save(update_fields=["expires_at"])
    assert resolve_tracking_token(raw) is None


def test_token_is_stored_hashed_not_in_clear(case_alpha):
    raw = generate_tracking_token(case_alpha)
    token = CaseTrackingToken.objects.get(case=case_alpha)
    assert token.token_hash != raw
    assert len(token.token_hash) == 64


def test_regenerating_token_invalidates_the_previous_one(case_alpha):
    first = generate_tracking_token(case_alpha)
    second = generate_tracking_token(case_alpha)
    assert first != second
    assert resolve_tracking_token(first) is None
    assert resolve_tracking_token(second) == case_alpha
    assert CaseTrackingToken.objects.filter(case=case_alpha).count() == 1


# --------------------------------------------------------------- statut public
def test_public_status_hides_internal_detail(case_alpha):
    case_alpha.status = CaseStatus.VALIDATION_PENDING
    case_alpha.save(update_fields=["status"])
    status = public_status_for(case_alpha)
    assert status["key"] == "ANALYSIS"
    assert status["case_id"] == case_alpha.case_id


def test_public_status_resolved_bucket(case_alpha):
    case_alpha.status = CaseStatus.CLOSED
    case_alpha.save(update_fields=["status"])
    assert public_status_for(case_alpha)["is_resolved"] is True


def test_public_status_dismissed_bucket(case_alpha):
    case_alpha.status = CaseStatus.REJECTED
    case_alpha.save(update_fields=["status"])
    status = public_status_for(case_alpha)
    assert status["is_dismissed"] is True
    assert status["is_resolved"] is False


# --------------------------------------------------------------- bout-en-bout
def test_fully_anonymous_submission_shows_tracking_code_once(client):
    response = client.post(
        reverse("reports:submit"), form_payload(is_anonymous="on"), follow=True
    )
    assert response.status_code == 200
    assert response.context["tracking_code"] is not None
    assert len(mail.outbox) == 0  # aucun email : aucune adresse fournie

    code = response.context["tracking_code"]
    status_response = client.get(reverse("reports:track_status", args=[code]))
    assert status_response.status_code == 200
    assert status_response.context["found"] is True


def test_no_account_with_email_receives_link_not_onscreen_code(client):
    response = client.post(
        reverse("reports:submit"),
        form_payload(contact_email="declarant@exemple.bf"),
        follow=True,
    )
    assert response.status_code == 200
    assert response.context["tracking_code"] is None
    assert response.context["emailed_link"] is True
    assert len(mail.outbox) == 1
    assert "/suivi/" in mail.outbox[0].body


def test_authenticated_submission_gets_no_tracking_token(client_for, researcher_a):
    client = client_for(researcher_a)
    payload = form_payload()
    payload.pop("accept_policy", None)
    payload["accept_policy"] = "on"
    client.post(reverse("reports:submit"), payload, follow=True)
    from apps.coordination.models import Case

    case = Case.objects.get(reporter=researcher_a)
    assert not CaseTrackingToken.objects.filter(case=case).exists()


def test_track_lookup_form_redirects_to_status(client, case_alpha):
    raw = generate_tracking_token(case_alpha)
    response = client.post(reverse("reports:track_lookup"), {"code": raw})
    assert response.status_code == 302
    assert response.url == reverse("reports:track_status", args=[raw])


def test_track_lookup_accepts_pasted_full_link(client, case_alpha):
    raw = generate_tracking_token(case_alpha)
    response = client.post(
        reverse("reports:track_lookup"), {"code": f"https://evdp.bf/suivi/{raw}/"}
    )
    assert response.status_code == 302
    assert response.url == reverse("reports:track_status", args=[raw])


def test_wrong_code_gives_generic_not_found_response(client):
    response = client.get(reverse("reports:track_status", args=["code-invente"]))
    assert response.status_code == 200
    assert response.context["found"] is False


def test_status_page_never_exposes_internal_case_id_format_details(client, case_alpha):
    """La page ne doit jamais reveler de detail interne (messages, cessionnaire...),
    seulement le statut simplifie et la reference deja connue du declarant."""
    raw = generate_tracking_token(case_alpha)
    response = client.get(reverse("reports:track_status", args=[raw]))
    content = response.content.decode()
    assert case_alpha.title not in content


def test_track_status_is_rate_limited(client, case_alpha):
    raw = generate_tracking_token(case_alpha)
    statuses = [
        client.get(reverse("reports:track_status", args=[raw])).status_code for _ in range(25)
    ]
    assert 429 in statuses


# ------------------------------------------------ code lisible et reponse
def test_tracking_code_is_human_friendly(case_alpha):
    import re

    raw = generate_tracking_token(case_alpha)
    assert re.fullmatch(r"([A-HJKMNP-Z2-9]{4}-){4}[A-HJKMNP-Z2-9]{4}", raw)


def test_tracking_code_tolerates_case_spaces_and_missing_dashes(case_alpha):
    raw = generate_tracking_token(case_alpha)
    sloppy = " " + raw.replace("-", " ").lower() + " "
    assert resolve_tracking_token(sloppy) == case_alpha
    assert resolve_tracking_token(raw.replace("-", "")) == case_alpha


def test_legacy_tracking_tokens_still_resolve(case_alpha):
    """Les codes emis avant le nouveau format restent valables."""
    from django.utils import timezone

    from apps.coordination.models import CaseTrackingToken
    from apps.core.utils import hash_text

    legacy = "Xk3_9fQ-legacy-token_ABCdef123"
    CaseTrackingToken.objects.update_or_create(
        case=case_alpha,
        defaults={
            "token_hash": hash_text(legacy),
            "expires_at": timezone.now().replace(year=2099),
        },
    )
    assert resolve_tracking_token(legacy) == case_alpha


def test_status_page_shows_progress_steps(client, case_alpha, advance):
    advance(case_alpha, CaseStatus.VALIDATED)
    raw = generate_tracking_token(case_alpha)
    page = client.get(reverse("reports:track_status", args=[raw])).content.decode()
    assert "En analyse" in page and "is-current" in page
    status = public_status_for(case_alpha)
    assert [s["done"] for s in status["steps"]] == [True, True, False, False, False]
    assert status["steps"][2]["current"] is True


def _anonymous_case_needing_information(client, advance, analyst):
    from apps.coordination.models import Case
    from apps.coordination.services import transition_case

    response = client.post(
        reverse("reports:submit"), form_payload(is_anonymous="on"), follow=True
    )
    code = response.context["tracking_code"]
    case = Case.objects.get()
    advance(case, CaseStatus.IN_ANALYSIS)
    transition_case(
        case, "request_information", analyst, comment="Quelle version du portail ?"
    )
    return case, code


def test_anonymous_reporter_sees_the_question_and_answers(client, advance, analyst):
    case, code = _anonymous_case_needing_information(client, advance, analyst)
    page = client.get(reverse("reports:track_status", args=[code])).content.decode()
    assert "Quelle version du portail ?" in page
    assert "Envoyer les compléments" in page

    response = client.post(
        reverse("reports:track_status", args=[code]),
        {"body": "Version 2.3.1, navigateur Firefox.", "attachments": evidence("capture.txt")},
    )
    assert response.status_code == 302
    case.refresh_from_db()
    assert case.status == CaseStatus.IN_ANALYSIS
    assert case.messages.filter(body__contains="Version 2.3.1").exists()
    assert case.attachments.filter(original_filename="capture.txt").exists()


def test_answer_is_refused_when_nothing_is_requested(client, case_alpha):
    from apps.coordination.models import CaseTrackingToken

    case_alpha.reporter = None
    case_alpha.save(update_fields=["reporter"])
    raw = generate_tracking_token(case_alpha)
    assert CaseTrackingToken.objects.count() == 1
    client.post(reverse("reports:track_status", args=[raw]), {"body": "Hors propos"})
    assert case_alpha.messages.count() == 0


def test_answer_with_unknown_code_changes_nothing(client, advance, analyst):
    case, _code = _anonymous_case_needing_information(client, advance, analyst)
    client.post(
        reverse("reports:track_status", args=["AAAA-BBBB-CCCC-DDDD-EEEE"]), {"body": "Intrus"}
    )
    case.refresh_from_db()
    assert case.status == CaseStatus.NEEDS_INFORMATION
    assert not case.messages.filter(body__contains="Intrus").exists()
