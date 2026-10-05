"""Cles PGP : analyse cote serveur, cle nationale geree dans l'application,
chiffrement et dechiffrement proposes dans le navigateur."""

from datetime import datetime

import pytest
from django.urls import reverse

from apps.audit.models import AuditAction, AuditLog
from apps.core import pgp
from apps.core.models import NationalPGPKey

from . import pgp_fixtures as keys

pytestmark = pytest.mark.django_db


# ------------------------------------------------------------- analyse
@pytest.mark.parametrize(
    ("blob", "fingerprint", "version"),
    [
        (keys.VALID_KEY, keys.VALID_FINGERPRINT, 4),
        (keys.EXPIRING_KEY, keys.EXPIRING_FINGERPRINT, 4),
        (keys.V6_KEY, keys.V6_FINGERPRINT, 6),
    ],
)
def test_fingerprint_matches_openpgpjs(blob, fingerprint, version):
    info = pgp.inspect_public_key(blob)
    assert info.fingerprint == fingerprint
    assert info.version == version


def test_expiration_is_read_from_the_self_signature():
    expected = datetime.fromisoformat(keys.EXPIRING_AT.replace("Z", "+00:00"))
    info = pgp.inspect_public_key(keys.EXPIRING_KEY)
    assert info.expires_at == expected
    assert not info.is_expired
    assert pgp.inspect_public_key(keys.VALID_KEY).expires_at is None


def test_expired_key_is_refused():
    assert pgp.inspect_public_key(keys.EXPIRED_KEY).is_expired
    with pytest.raises(pgp.PGPError, match="expiré"):
        pgp.validate_public_key(keys.EXPIRED_KEY)


@pytest.mark.parametrize(
    "blob",
    [
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\nmQINBGX...\n-----END PGP PUBLIC KEY BLOCK-----",
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nAAAA\n-----END PGP PUBLIC KEY BLOCK-----",
    ],
)
def test_a_block_that_only_looks_like_a_key_is_refused(blob):
    with pytest.raises(pgp.PGPError):
        pgp.validate_public_key(blob)


# ------------------------------------------------------- cle nationale
def test_published_key_replaces_the_previous_and_is_served(client, coordinator):
    first = pgp.publish_national_key(keys.VALID_KEY, coordinator)
    second = pgp.publish_national_key(keys.V6_KEY, coordinator)
    first.refresh_from_db()
    assert not first.is_active and second.is_active
    assert NationalPGPKey.objects.filter(is_active=True).count() == 1

    response = client.get(reverse("core:pgp_key"))
    assert response.content.decode().strip() == keys.V6_KEY.strip()
    assert pgp.national_fingerprint().replace(" ", "") == keys.V6_FINGERPRINT


def test_only_key_managers_publish_the_national_key(client_for, coordinator, analyst):
    url = reverse("core:pgp_key_manage")
    assert client_for(analyst).get(url).status_code == 403
    response = client_for(coordinator).post(url, {"public_key": keys.VALID_KEY})
    assert response.status_code == 302
    assert pgp.active_national_key().fingerprint == keys.VALID_FINGERPRINT
    assert AuditLog.objects.filter(action=AuditAction.PGP_KEY_PUBLISHED).exists()

    client_for(coordinator).post(url, {"public_key": keys.EXPIRED_KEY})
    assert pgp.active_national_key().fingerprint == keys.VALID_FINGERPRINT


def test_expiring_key_alerts_its_managers(coordinator):
    from apps.accounts.tasks import warn_national_pgp_key_expiry
    from apps.notifications.models import Notification

    pgp.publish_national_key(keys.VALID_KEY, coordinator)
    assert warn_national_pgp_key_expiry() == 0
    pgp.publish_national_key(keys.EXPIRING_KEY, coordinator)
    assert warn_national_pgp_key_expiry() == 1
    assert Notification.objects.filter(recipient=coordinator, title__contains="PGP").exists()


# --------------------------------------------- chiffrement dans le navigateur
def test_report_form_offers_browser_encryption_once_a_key_is_published(client, coordinator):
    url = reverse("reports:submit")
    assert 'id="pgp-encrypt"' not in client.get(url).content.decode()
    pgp.publish_national_key(keys.VALID_KEY, coordinator)
    html = client.get(url).content.decode()
    assert 'id="pgp-encrypt"' in html
    assert "js/vendor/openpgp.min.js" in html
    # Le texte en clair n'a pas de name : il ne part jamais au serveur.
    textarea = html.split('id="pgp-plaintext"')[0].rsplit("<textarea", 1)[1]
    assert "name=" not in textarea


def test_browser_encrypted_block_is_accepted(organization):
    from apps.reports.forms import VulnerabilityReportForm

    form = VulnerabilityReportForm(
        data={
            "title": "Signalement chiffre",
            "affected_organization": organization.pk,
            "description": "Description suffisamment longue pour la validation.",
            "contact_email": "contact@exemple.bf",
            "pgp_payload": keys.MESSAGE_FOR_VALID_KEY,
            "accept_policy": "on",
        }
    )
    assert form.is_valid(), form.errors


def test_case_page_offers_decryption_to_the_owner_not_the_auditor(
    client_for, case_alpha, triager, auditor
):
    from .conftest import claim

    case_alpha.report.pgp_payload = keys.MESSAGE_FOR_VALID_KEY
    case_alpha.report.save(update_fields=["pgp_payload"])
    claim(case_alpha, triager)
    url = reverse("coordination:case_detail", args=[case_alpha.case_id])
    html = client_for(triager).get(url).content.decode()
    assert 'id="pgp-decrypt"' in html and 'id="pgp-armored"' in html
    assert 'id="pgp-decrypt"' not in client_for(auditor).get(url).content.decode()
