"""Double authentification TOTP : perimetre, parcours et contournements.

Le perimetre est le coeur du sujet : le second facteur protege les comptes
qui voient les dossiers d'autrui, et laisse tranquille celui qui vient
signaler une faille.
"""

from html import unescape
from urllib.parse import unquote

import pyotp
import pytest
import segno
from django.core.exceptions import ValidationError
from django.core.management import CommandError, call_command
from django.utils import timezone

from apps.accounts import mfa
from apps.accounts.mfa import INTERVAL, consume_code, is_required
from apps.accounts.middleware import SESSION_KEY as MFA_SESSION_KEY
from apps.accounts.models import User
from apps.accounts.roles import RESEARCHER_ROLES, Role
from apps.audit.models import AuditAction, AuditLog

from .conftest import PASSWORD, make_user

pytestmark = pytest.mark.django_db


def code_pour(secret, instant=None):
    totp = pyotp.TOTP(secret, interval=INTERVAL, digits=6)
    return totp.at(instant) if instant is not None else totp.now()


@pytest.fixture
def admin_staff(db):
    return User.objects.create_superuser("admin-mfa@test.bf", "MotDePasse!Long12")


# ------------------------------------------------------------------ perimetre
@pytest.mark.parametrize("role", list(Role.values))
def test_the_rule_follows_the_role_and_nothing_else(role):
    """Tout role est classe explicitement : un role ajoute force le choix."""
    utilisateur = make_user(f"{role.lower()}@test.bf", role=role)
    assert is_required(utilisateur) is (role not in RESEARCHER_ROLES)


def test_a_reporter_account_is_never_subject_to_it(researcher_a, bounty_researcher):
    """La promesse du dispositif : signaler reste sans friction ajoutee."""
    for signaleur in (researcher_a, bounty_researcher):
        assert not signaleur.mfa_required
        assert not signaleur.mfa_pending_enrollment


def test_a_reporter_account_cannot_even_enable_it(researcher_a):
    researcher_a.mfa_enabled = True
    with pytest.raises(ValidationError, match="compte signaleur"):
        researcher_a.full_clean()


def test_demoting_an_account_purges_its_authenticator(analyst):
    """Une retrogradation ne doit pas laisser un secret orphelin en base."""
    analyst.mfa_secret = pyotp.random_base32()
    analyst.mfa_enabled = True
    analyst.mfa_confirmed_at = timezone.now()
    analyst.save()

    analyst.role = Role.SECURITY_RESEARCHER
    analyst.save(update_fields=["role"])
    analyst.refresh_from_db()

    assert not analyst.mfa_enabled
    assert analyst.mfa_secret == ""
    assert analyst.mfa_confirmed_at is None


# ----------------------------------------------------------------- circulation
def test_a_reporter_browses_without_ever_being_challenged(client_for, researcher_a):
    client = client_for(researcher_a, mfa=False)
    assert client.get("/dashboard/", follow=True).status_code == 200


def test_an_unenrolled_business_account_is_sent_to_enrollment(client_for, analyst):
    reponse = client_for(analyst, mfa=False).get("/dashboard/")
    assert reponse.status_code == 302
    assert reponse["Location"] == "/mfa/enrolement/"


def test_the_django_admin_is_not_a_way_around_it(client_for, admin_staff):
    """L'administration a sa propre page de connexion : pas de dispense."""
    reponse = client_for(admin_staff, mfa=False).get("/admin/")
    assert reponse.status_code == 302
    assert reponse["Location"] == "/mfa/enrolement/"


def test_a_session_authenticated_api_call_is_refused_not_redirected(client_for, analyst):
    """Rediriger un client machine vers une page HTML n'aurait aucun sens."""
    reponse = client_for(analyst, mfa=False).get("/api/v1/reports/")
    assert reponse.status_code == 403
    assert "Double authentification" in reponse.json()["detail"]


def test_logout_stays_reachable_without_the_second_factor(client_for, analyst):
    """Un compte en cours d'enrolement doit pouvoir renoncer."""
    assert client_for(analyst, mfa=False).post("/logout/").status_code == 302


# ------------------------------------------------------------------ enrolement
def test_enrollment_activates_the_account_and_opens_access(client_for, analyst):
    client = client_for(analyst, mfa=False)
    client.get("/mfa/enrolement/")
    secret = client.session["mfa_setup_candidate"]

    assert client.post("/mfa/enrolement/", {"code": code_pour(secret)}).status_code == 302

    analyst.refresh_from_db()
    assert analyst.mfa_enabled
    assert analyst.mfa_secret == secret
    assert analyst.mfa_confirmed_at is not None
    assert client.session[MFA_SESSION_KEY] is True
    assert client.get("/dashboard/", follow=True).status_code == 200
    assert AuditLog.objects.filter(action=AuditAction.MFA_ENROLLED).exists()


def test_a_wrong_code_enrolls_nothing(client_for, analyst):
    client = client_for(analyst, mfa=False)
    client.get("/mfa/enrolement/")

    assert client.post("/mfa/enrolement/", {"code": "000000"}).status_code == 200

    analyst.refresh_from_db()
    assert not analyst.mfa_enabled
    assert analyst.mfa_secret == ""
    assert AuditLog.objects.filter(action=AuditAction.MFA_FAILED).exists()


def test_changing_authenticator_requires_proving_the_current_one(client_for, analyst):
    """Sinon le mot de passe seul suffirait a remplacer le second facteur."""
    analyst.mfa_secret = pyotp.random_base32()
    analyst.mfa_enabled = True
    analyst.save()

    reponse = client_for(analyst, mfa=False).get("/mfa/enrolement/")
    assert reponse.status_code == 302
    assert reponse["Location"] == "/mfa/"


# ---------------------------------------------------------------- verification
@pytest.fixture
def analyste_enrole(analyst):
    analyst.mfa_secret = pyotp.random_base32()
    analyst.mfa_enabled = True
    analyst.mfa_confirmed_at = timezone.now()
    analyst.save()
    return analyst


def test_a_valid_code_elevates_the_session(client_for, analyste_enrole):
    client = client_for(analyste_enrole, mfa=False)
    assert client.get("/dashboard/")["Location"] == "/mfa/"

    code = code_pour(analyste_enrole.mfa_secret)
    assert client.post("/mfa/", {"code": code}).status_code == 302
    assert client.get("/dashboard/", follow=True).status_code == 200
    assert AuditLog.objects.filter(action=AuditAction.MFA_VERIFIED).exists()


def test_a_wrong_code_leaves_the_session_closed(client_for, analyste_enrole):
    client = client_for(analyste_enrole, mfa=False)
    assert client.post("/mfa/", {"code": "000000"}).status_code == 200
    assert client.get("/dashboard/")["Location"] == "/mfa/"


def test_spaces_copied_from_the_authenticator_are_tolerated(analyste_enrole):
    brut = code_pour(analyste_enrole.mfa_secret)
    assert consume_code(analyste_enrole, f"{brut[:3]} {brut[3:]}")


def test_a_code_cannot_be_replayed(analyste_enrole):
    """Un code intercepte resterait sinon utilisable toute sa fenetre."""
    code = code_pour(analyste_enrole.mfa_secret)
    assert consume_code(analyste_enrole, code)
    assert not consume_code(analyste_enrole, code)


def test_an_older_code_is_refused_once_a_newer_one_is_spent(analyste_enrole):
    """La tolerance de derive ne doit pas rouvrir le pas precedent."""
    instant = int(timezone.now().timestamp())
    precedent = code_pour(analyste_enrole.mfa_secret, instant - INTERVAL)
    courant = code_pour(analyste_enrole.mfa_secret, instant)

    assert consume_code(analyste_enrole, courant, now=instant)
    assert not consume_code(analyste_enrole, precedent, now=instant)


def test_another_accounts_code_is_refused(analyste_enrole, coordinator):
    coordinator.mfa_secret = pyotp.random_base32()
    coordinator.mfa_enabled = True
    coordinator.save()
    assert not consume_code(analyste_enrole, code_pour(coordinator.mfa_secret))


# ---------------------------------------------------------------- code QR
def test_the_enrollment_page_serves_a_scannable_qr_code(client_for, analyst):
    """Le QR doit porter l'URI d'enrolement, et la cle rester saisissable."""
    client = client_for(analyst, mfa=False)
    page = client.get("/mfa/enrolement/").content.decode()
    secret = client.session["mfa_setup_candidate"]

    assert "data:image/svg+xml" in page, "code QR absent"
    assert mfa.readable_secret(secret) in page, "saisie manuelle toujours possible"
    assert mfa.provisioning_uri(analyst, secret) in unescape(page)


def test_the_qr_is_derived_from_the_secret(analyst):
    """Un symbole constant se scannerait aussi : il doit suivre le secret."""
    premier = pyotp.random_base32()
    second = pyotp.random_base32()

    assert mfa.qr_data_uri(analyst, premier) == mfa.qr_data_uri(analyst, premier)
    assert mfa.qr_data_uri(analyst, premier) != mfa.qr_data_uri(analyst, second)


def test_the_qr_is_a_svg_large_enough_for_its_payload(analyst):
    """Le symbole doit avoir la version qu'exige l'URI, pas une plus petite."""
    secret = pyotp.random_base32()
    svg = unquote(mfa.qr_data_uri(analyst, secret).split(",", 1)[1])
    cote, _ = segno.make(mfa.provisioning_uri(analyst, secret), error="m").symbol_size(
        scale=5, border=2
    )

    assert svg.startswith("<svg")
    assert f"width='{cote}'" in svg


def test_the_qr_needs_no_csp_exception(settings):
    """Une URI `data:` dans un <img> : deja couverte par la CSP en vigueur."""
    assert "data:" in settings.CSP_DIRECTIVES["img-src"]


# ------------------------------------------------------------- reinitialisation
def test_reset_sends_the_account_back_to_enrollment(client_for, analyste_enrole):
    analyste_enrole.reset_mfa()
    analyste_enrole.refresh_from_db()

    assert analyste_enrole.mfa_pending_enrollment
    assert analyste_enrole.mfa_required, "la dispense n'est jamais accordee"
    reponse = client_for(analyste_enrole, mfa=False).get("/dashboard/")
    assert reponse["Location"] == "/mfa/enrolement/"


def test_the_offline_command_recovers_a_locked_out_administrator(analyste_enrole):
    """Recours quand plus personne ne peut se connecter a l'administration."""
    call_command("reset_mfa", analyste_enrole.email)
    analyste_enrole.refresh_from_db()

    assert analyste_enrole.mfa_pending_enrollment
    assert AuditLog.objects.filter(action=AuditAction.MFA_RESET).exists()


def test_the_offline_command_refuses_a_reporter_account(researcher_a):
    with pytest.raises(CommandError, match="n'est pas soumis"):
        call_command("reset_mfa", researcher_a.email)


# ------------------------------------------------------- parcours de connexion
def test_a_business_account_logging_in_lands_on_enrollment(client, analyst):
    """Bout en bout depuis le mot de passe, et non depuis force_login."""
    reponse = client.post(
        "/login/", {"username": analyst.email, "password": PASSWORD}, follow=True
    )
    assert reponse.status_code == 200
    assert reponse.redirect_chain[-1][0] == "/mfa/enrolement/"
    assert b"authentificateur" in reponse.content


def test_a_reporter_logging_in_goes_straight_to_the_dashboard(client, researcher_a):
    reponse = client.post(
        "/login/", {"username": researcher_a.email, "password": PASSWORD}, follow=True
    )
    assert reponse.status_code == 200
    assert "/mfa/" not in reponse.redirect_chain[-1][0]
