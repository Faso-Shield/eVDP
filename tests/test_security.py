"""Tests de securite applicative (OWASP Top 10 / ASVS)."""

import pytest
from django.urls import reverse

from apps.audit.models import AuditAction, AuditLog, AuditResult
from apps.coordination.constants import Confidentiality
from apps.coordination.services import post_message, visible_messages
from apps.core.markdown_utils import render_markdown
from apps.core.pgp import PGPError, validate_public_key

pytestmark = pytest.mark.django_db


# --------------------------------------------------------------- en-tetes HTTP
def test_security_headers_present(client):
    response = client.get("/")
    assert "Content-Security-Policy" in response
    assert "frame-ancestors 'none'" in response["Content-Security-Policy"]
    assert response["X-Content-Type-Options"] == "nosniff"
    assert response["X-Frame-Options"] == "DENY"
    assert "Permissions-Policy" in response
    assert response["Referrer-Policy"] == "strict-origin-when-cross-origin"


def test_sensitive_pages_are_not_cacheable(client_for, researcher_a, case_alpha):
    client = client_for(researcher_a)
    response = client.get(f"/cases/{case_alpha.case_id}/")
    assert "no-store" in response["Cache-Control"]


def test_security_txt_is_served(client):
    response = client.get("/.well-known/security.txt")
    assert response.status_code == 200
    assert b"Contact:" in response.content
    assert b"Policy:" in response.content


# ------------------------------------------------------------------------ XSS
def test_markdown_strips_script_tags():
    html = render_markdown("Bonjour <script>alert('xss')</script> monde")
    assert "<script>" not in html
    assert "alert" not in html or "&lt;script&gt;" not in html


def test_markdown_strips_event_handlers():
    html = render_markdown('<img src=x onerror="alert(1)">')
    assert "onerror" not in html


def test_markdown_strips_javascript_urls():
    html = render_markdown("[cliquez](javascript:alert(1))")
    assert "javascript:" not in html


def test_markdown_strips_iframe():
    html = render_markdown('<iframe src="https://evil.example"></iframe>')
    assert "<iframe" not in html


def test_stored_xss_in_report_is_neutralised(client_for, case_alpha, researcher_a):
    case_alpha.report.description = "<script>alert('pwned')</script>Description reelle"
    case_alpha.report.save(update_fields=["description"])

    client = client_for(researcher_a)
    content = client.get(f"/cases/{case_alpha.case_id}/").content.decode()
    assert "<script>alert('pwned')</script>" not in content
    assert "Description reelle" in content


def test_stored_xss_in_message_is_neutralised(
    client_for, case_alpha, coordinator, researcher_a
):
    post_message(
        case_alpha,
        coordinator,
        "<script>alert(1)</script>Message legitime",
        confidentiality=Confidentiality.RESEARCHER,
    )
    client = client_for(researcher_a)
    content = client.get(f"/cases/{case_alpha.case_id}/").content.decode()
    assert "<script>alert(1)</script>" not in content


# ----------------------------------------------------------------------- CSRF
def test_post_without_csrf_token_is_rejected(client_for, researcher_a, case_alpha):
    from django.test import Client

    client = Client(enforce_csrf_checks=True)
    client.force_login(researcher_a)
    response = client.post(
        reverse("coordination:post_message", args=[case_alpha.case_id]),
        {"body": "Message sans jeton", "confidentiality": "RESEARCHER"},
    )
    assert response.status_code == 403
    assert case_alpha.messages.count() == 0


# ----------------------------------------------------------------------- IDOR
def test_case_ids_are_uuid_internally(case_alpha):
    import uuid

    assert isinstance(case_alpha.pk, uuid.UUID)


def test_case_access_denied_is_audited(client_for, researcher_a, case_beta):
    client = client_for(researcher_a)
    client.get(f"/cases/{case_beta.case_id}/")
    assert AuditLog.objects.filter(
        action=AuditAction.CASE_VIEWED, result=AuditResult.DENIED
    ).exists()


def test_enumeration_returns_404_not_403(client_for, researcher_a, case_beta):
    """Un 403 confirmerait l'existence du dossier : on renvoie 404."""
    client = client_for(researcher_a)
    assert client.get(f"/cases/{case_beta.case_id}/").status_code == 404


def test_nonexistent_case_returns_same_404(client_for, researcher_a):
    client = client_for(researcher_a)
    assert client.get("/cases/EVDP-2026-999999/").status_code == 404


# --------------------------------------------------- confidentialite messages
def test_internal_message_hidden_from_reporter(case_alpha, analyst, researcher_a):
    post_message(
        case_alpha, analyst, "Analyse interne", confidentiality=Confidentiality.INTERNAL
    )
    bodies = [m.body for m in visible_messages(case_alpha, researcher_a)]
    assert "Analyse interne" not in bodies


def test_internal_message_hidden_from_organization(case_alpha, analyst, dsi_alpha):
    from apps.coordination.workflow import CaseStatus

    from .conftest import advance

    advance(case_alpha, CaseStatus.VENDOR_NOTIFIED)
    post_message(
        case_alpha, analyst, "Analyse interne", confidentiality=Confidentiality.INTERNAL
    )
    bodies = [m.body for m in visible_messages(case_alpha, dsi_alpha)]
    assert "Analyse interne" not in bodies


def test_coordinator_cannot_write_internal_notes(case_alpha, coordinator):
    """Notes de triage et d'analyse : le coordinateur les lit sans les ecrire."""
    from django.core.exceptions import PermissionDenied

    with pytest.raises(PermissionDenied):
        post_message(case_alpha, coordinator, "Note", confidentiality=Confidentiality.INTERNAL)


def test_researcher_cannot_post_internal_message(case_alpha, researcher_a):
    from django.core.exceptions import PermissionDenied

    with pytest.raises(PermissionDenied):
        post_message(
            case_alpha, researcher_a, "Tentative", confidentiality=Confidentiality.INTERNAL
        )


def test_message_integrity_hash(case_alpha, coordinator):
    message = post_message(
        case_alpha, coordinator, "Contenu original", confidentiality=Confidentiality.RESEARCHER
    )
    assert message.integrity_ok() is True
    message.body = "Contenu altere"
    assert message.integrity_ok() is False


# ------------------------------------------------------------------------ PGP
def test_private_key_block_is_refused():
    with pytest.raises(PGPError, match="privee"):
        validate_public_key(
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\nx\n-----END PGP PRIVATE KEY BLOCK-----"
        )


def test_ssh_private_key_is_refused():
    with pytest.raises(PGPError):
        validate_public_key("-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END-----")


def test_malformed_public_key_is_refused():
    with pytest.raises(PGPError, match="invalide"):
        validate_public_key("pas une cle")


def test_valid_public_key_shape_is_accepted():
    blob = (
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\nmQINBGX...\n-----END PGP PUBLIC KEY BLOCK-----"
    )
    assert validate_public_key(blob) == blob


# ------------------------------------------------------------- audit immuable
def test_audit_entry_cannot_be_modified(researcher_a):
    from apps.audit.services import log_action

    entry = log_action(AuditAction.LOGIN, actor=researcher_a, obj=researcher_a)
    entry.action = AuditAction.BOUNTY_APPROVED
    with pytest.raises(NotImplementedError):
        entry.save()


def test_audit_entry_cannot_be_deleted(researcher_a):
    from apps.audit.services import log_action

    entry = log_action(AuditAction.LOGIN, actor=researcher_a, obj=researcher_a)
    with pytest.raises(NotImplementedError):
        entry.delete()


def test_audit_queryset_cannot_be_bulk_deleted(researcher_a):
    from apps.audit.services import log_action

    log_action(AuditAction.LOGIN, actor=researcher_a, obj=researcher_a)
    with pytest.raises(NotImplementedError):
        AuditLog.objects.all().delete()


def test_audit_metadata_redacts_secrets(researcher_a):
    from apps.audit.services import log_action

    entry = log_action(
        AuditAction.LOGIN,
        actor=researcher_a,
        obj=researcher_a,
        password="motdepasse",
        api_token="secret",
        note="ok",
    )
    assert entry.metadata["password"] == "[redacted]"
    assert entry.metadata["api_token"] == "[redacted]"
    assert entry.metadata["note"] == "ok"


# ------------------------------------------------------------- rate limiting
def test_login_rate_limit_blocks_brute_force(client, researcher_a, settings):
    settings.EVDP = {
        **settings.EVDP,
        "RATE_LIMITS": {**settings.EVDP["RATE_LIMITS"], "login": "3/5m"},
    }
    url = reverse("accounts:login")
    for _ in range(3):
        client.post(url, {"username": researcher_a.email, "password": "faux"})
    response = client.post(url, {"username": researcher_a.email, "password": "faux"})
    assert response.status_code == 429
    assert "Retry-After" in response


def test_report_submission_is_rate_limited(client, settings, organization):
    settings.EVDP = {
        **settings.EVDP,
        "RATE_LIMITS": {**settings.EVDP["RATE_LIMITS"], "report": "2/1h"},
    }
    url = reverse("reports:submit")
    payload = {"title": "x", "description": "y", "vulnerability_type": "OTHER"}
    for _ in range(2):
        client.post(url, payload)
    assert client.post(url, payload).status_code == 429
