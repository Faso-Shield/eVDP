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


def test_stored_xss_in_message_is_neutralised(client_for, case_alpha, triager, researcher_a):
    from .conftest import claim

    claim(case_alpha, triager)
    post_message(
        case_alpha,
        triager,
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
def test_internal_message_hidden_from_reporter(case_alpha, triager, researcher_a):
    # Etape 1 : l'agent de triage, responsable de l'etape, redige la note.
    from .conftest import claim

    claim(case_alpha, triager)
    post_message(
        case_alpha, triager, "Analyse interne", confidentiality=Confidentiality.INTERNAL
    )
    bodies = [m.body for m in visible_messages(case_alpha, researcher_a)]
    assert "Analyse interne" not in bodies


def test_internal_message_hidden_from_organization(case_alpha, analyst, dsi_alpha):
    from apps.coordination.workflow import CaseStatus

    from .conftest import advance

    post_message(
        case_alpha,
        None,
        "Analyse interne",
        confidentiality=Confidentiality.INTERNAL,
        is_system=True,
    )
    advance(case_alpha, CaseStatus.VENDOR_NOTIFIED)
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


def test_message_integrity_hash(case_alpha, triager):
    from .conftest import claim

    claim(case_alpha, triager)
    message = post_message(
        case_alpha, triager, "Contenu original", confidentiality=Confidentiality.RESEARCHER
    )
    assert message.integrity_ok() is True
    message.body = "Contenu altere"
    assert message.integrity_ok() is False


# ------------------------------------------------------------------------ PGP
def test_private_key_block_is_refused():
    with pytest.raises(PGPError, match="privée"):
        validate_public_key(
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\nx\n-----END PGP PRIVATE KEY BLOCK-----"
        )


def test_ssh_private_key_is_refused():
    with pytest.raises(PGPError):
        validate_public_key("-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END-----")


def test_malformed_public_key_is_refused():
    with pytest.raises(PGPError, match="invalide"):
        validate_public_key("pas une cle")


def test_valid_public_key_is_accepted():
    """La forme ne suffit plus : la cle est lue (voir tests/test_pgp_keys.py)."""
    from .pgp_fixtures import VALID_KEY

    assert validate_public_key(VALID_KEY) == VALID_KEY.strip()


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


def test_login_is_rate_limited_per_account_across_ip_addresses(client, researcher_a, settings):
    """Changer d'IP a chaque essai ne contourne plus la limite."""
    settings.EVDP = {
        **settings.EVDP,
        "RATE_LIMITS": {**settings.EVDP["RATE_LIMITS"], "login_account": "3/15m"},
    }
    url = reverse("accounts:login")
    for i in range(3):
        client.post(
            url,
            {"username": researcher_a.email.upper(), "password": "faux"},
            REMOTE_ADDR=f"203.0.113.{i + 1}",
        )
    response = client.post(
        url, {"username": researcher_a.email, "password": "faux"}, REMOTE_ADDR="203.0.113.99"
    )
    assert response.status_code == 429


def test_successful_login_resets_the_counter(client, settings):
    """reset() visait une fenetre inexistante pour une regle en minutes."""
    from apps.core.ratelimit import hit, reset

    settings.EVDP = {
        **settings.EVDP,
        "RATE_LIMITS": {**settings.EVDP["RATE_LIMITS"], "login": "2/5m"},
    }
    assert hit("login", "198.51.100.7", "2/5m")[0]
    assert hit("login", "198.51.100.7", "2/5m")[0]
    reset("login", "198.51.100.7")
    assert hit("login", "198.51.100.7", "2/5m")[0]


# ------------------------------------------------------ durcissements divers
def test_export_links_follow_the_export_capability(client_for, triager, analyst):
    """Le lien s'affichait a tout role national, menant a un 403 pour qui n'a
    pas EXPORT_DATA."""
    url = reverse("coordination:case_list")
    assert "Export CSV" not in client_for(triager).get(url).content.decode()
    assert "Export CSV" in client_for(analyst).get(url).content.decode()


def test_api_search_and_bounties_are_throttled(client_for, analyst, monkeypatch):
    """Sans throttle_scope, ScopedRateThrottle ne limitait pas ces vues."""
    from django.core.cache import cache

    from apps.api.throttling import ResilientScopedRateThrottle

    cache.clear()
    # DRF fige les debits a l'import de la classe : on les fixe sur elle.
    monkeypatch.setattr(
        ResilientScopedRateThrottle, "THROTTLE_RATES", {"authenticated": "2/day"}
    )
    client = client_for(analyst)
    statuses = [client.get("/api/v1/search/", {"q": "x"}).status_code for _ in range(3)]
    assert statuses == [200, 200, 429]
    assert client.get("/api/v1/bounties/").status_code == 429


def test_anonymous_report_never_asks_for_public_credit(organization):
    from .conftest import build_report, submit

    report = build_report(None, organization, is_anonymous=True, wants_credit=True)
    report.reporter_email = "contact@exemple.bf"
    case = submit(report)
    case.report.refresh_from_db()
    assert case.report.wants_credit is False


def test_admin_cannot_delete_advisories_nor_edit_payout_details(rf, db):
    from django.contrib.admin.sites import site

    from apps.disclosures.models import Advisory
    from apps.researchers.models import PayoutMethod, PayoutProfile

    request = rf.get("/")
    request.user = make_superuser()
    assert not site._registry[Advisory].has_delete_permission(request)
    for model, field in [(PayoutProfile, "legal_full_name"), (PayoutMethod, "account_number")]:
        assert field in site._registry[model].get_readonly_fields(request)


def make_superuser():
    from .conftest import make_user

    return make_user("root@test.bf", is_superuser=True, is_staff=True)
