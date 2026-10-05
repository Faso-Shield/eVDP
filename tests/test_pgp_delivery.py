"""Remise de la cle privee nationale : chiffree dans le navigateur par un code
que eVDP ignore, recuperee une fois par son destinataire, puis effacee."""

from datetime import timedelta

import pytest
from django.urls import reverse
from django.utils import timezone

from apps.audit.models import AuditAction, AuditLog
from apps.core import pgp
from apps.core.models import PGPKeyDelivery

from . import pgp_fixtures as keys

pytestmark = pytest.mark.django_db


@pytest.fixture
def national_key(coordinator):
    return pgp.publish_national_key(keys.VALID_KEY, coordinator)


@pytest.fixture
def delivery(national_key, coordinator, analyst):
    return pgp.create_key_delivery(keys.DELIVERY_PAYLOAD, analyst, coordinator)


# ------------------------------------------------------------- forme
def test_a_password_encrypted_message_is_accepted():
    assert pgp.validate_key_delivery(keys.DELIVERY_PAYLOAD) == keys.DELIVERY_PAYLOAD.strip()


@pytest.mark.parametrize(
    "blob",
    [
        "",
        keys.LITERAL_MESSAGE,  # message en clair
        keys.MESSAGE_FOR_VALID_KEY,  # chiffre pour une cle publique, pas par code
        "-----BEGIN PGP PRIVATE KEY BLOCK-----\nxx\n-----END PGP PRIVATE KEY BLOCK-----",
        "-----BEGIN PGP MESSAGE-----\n\nAAAA\n-----END PGP MESSAGE-----",
    ],
)
def test_anything_but_a_password_encrypted_message_is_refused(blob):
    with pytest.raises(pgp.PGPError):
        pgp.validate_key_delivery(blob)


# ------------------------------------------------------ preparation
def test_manager_prepares_a_delivery_for_a_national_team_member(
    client_for, coordinator, analyst, national_key
):
    from apps.notifications.models import Notification

    response = client_for(coordinator).post(
        reverse("core:pgp_delivery_create"),
        {"recipient": analyst.pk, "payload": keys.DELIVERY_PAYLOAD},
    )
    assert response.status_code == 200
    delivery = PGPKeyDelivery.objects.get()
    assert delivery.recipient == analyst and delivery.is_open
    assert delivery.fingerprint == keys.VALID_FINGERPRINT
    assert AuditLog.objects.filter(action=AuditAction.PGP_KEY_DELIVERY_CREATED).exists()
    notification = Notification.objects.get(recipient=analyst)
    assert notification.url == reverse("core:pgp_delivery_retrieve", args=[delivery.pk])
    # Le code de remise n'est jamais envoye au serveur.
    assert keys.DELIVERY_CODE not in str(response.content)


@pytest.mark.parametrize("payload", [keys.LITERAL_MESSAGE, keys.VALID_KEY])
def test_a_clear_payload_is_refused(client_for, coordinator, analyst, national_key, payload):
    response = client_for(coordinator).post(
        reverse("core:pgp_delivery_create"), {"recipient": analyst.pk, "payload": payload}
    )
    assert response.status_code == 400
    assert not PGPKeyDelivery.objects.exists()


def test_only_the_national_team_can_receive_the_key(
    client_for, coordinator, auditor, dsi_alpha, national_key
):
    url = reverse("core:pgp_delivery_create")
    for user in (auditor, dsi_alpha):
        response = client_for(coordinator).post(
            url, {"recipient": user.pk, "payload": keys.DELIVERY_PAYLOAD}
        )
        assert response.status_code == 400
    response = client_for(coordinator).post(
        url, {"recipient": "pas-un-uuid", "payload": keys.DELIVERY_PAYLOAD}
    )
    assert response.status_code == 400
    assert not PGPKeyDelivery.objects.exists()


def test_no_delivery_without_a_published_key(coordinator, analyst):
    with pytest.raises(pgp.PGPError):
        pgp.create_key_delivery(keys.DELIVERY_PAYLOAD, analyst, coordinator)


def test_only_key_managers_prepare_a_delivery(client_for, analyst, triager, national_key):
    response = client_for(analyst).post(
        reverse("core:pgp_delivery_create"),
        {"recipient": triager.pk, "payload": keys.DELIVERY_PAYLOAD},
    )
    assert response.status_code == 403


def test_manage_page_offers_generation_and_delivery(
    client_for, coordinator, analyst, national_key
):
    html = client_for(coordinator).get(reverse("core:pgp_key_manage")).content.decode()
    assert 'id="pgp-generate"' in html and 'id="pgp-deliver"' in html
    assert "js/vendor/openpgp.min.js" in html
    assert str(analyst.pk) in html
    # La cle privee chargee pour la remise n'a pas de name : elle ne part pas.
    file_input = html.split('id="pgp-deliver-file"')[0].rsplit("<input", 1)[1]
    assert "name=" not in file_input


# ------------------------------------------------------ recuperation
def test_recipient_fetches_then_confirms_and_the_block_is_wiped(client_for, analyst, delivery):
    client = client_for(analyst)
    assert (
        client.get(reverse("core:pgp_delivery_retrieve", args=[delivery.pk])).status_code
        == 200
    )

    response = client.post(reverse("core:pgp_delivery_fetch", args=[delivery.pk]))
    assert response.status_code == 200
    assert response.json()["payload"] == keys.DELIVERY_PAYLOAD.strip()

    response = client.post(reverse("core:pgp_delivery_confirm", args=[delivery.pk]))
    assert response.status_code == 200
    delivery.refresh_from_db()
    assert delivery.payload == "" and delivery.retrieved_at is not None
    assert AuditLog.objects.filter(action=AuditAction.PGP_KEY_DELIVERY_RETRIEVED).exists()
    assert (
        client.post(reverse("core:pgp_delivery_fetch", args=[delivery.pk])).status_code == 410
    )


def test_nobody_else_sees_the_delivery(client_for, triager, coordinator, delivery):
    for user in (triager, coordinator):
        client = client_for(user)
        assert (
            client.get(reverse("core:pgp_delivery_retrieve", args=[delivery.pk])).status_code
            == 404
        )
        assert (
            client.post(reverse("core:pgp_delivery_fetch", args=[delivery.pk])).status_code
            == 404
        )


def test_too_many_attempts_wipe_the_delivery(client_for, analyst, delivery):
    client = client_for(analyst)
    url = reverse("core:pgp_delivery_fetch", args=[delivery.pk])
    for _ in range(pgp.DELIVERY_MAX_FETCHES):
        assert client.post(url).status_code == 200
    assert client.post(url).status_code == 410
    delivery.refresh_from_db()
    assert delivery.payload == "" and delivery.retrieved_at is None


def test_expired_delivery_is_unavailable_and_purged(client_for, analyst, delivery):
    from apps.accounts.tasks import purge_pgp_key_deliveries

    delivery.expires_at = timezone.now() - timedelta(minutes=1)
    delivery.save(update_fields=["expires_at"])
    assert (
        client_for(analyst)
        .post(reverse("core:pgp_delivery_fetch", args=[delivery.pk]))
        .status_code
        == 410
    )
    assert purge_pgp_key_deliveries() == 1
    delivery.refresh_from_db()
    assert delivery.payload == ""


def test_a_recipient_who_left_the_national_team_loses_the_delivery(
    client_for, analyst, delivery
):
    from apps.accounts.roles import Role

    analyst.role = Role.DSI_ADMIN
    analyst.save(update_fields=["role"])
    response = client_for(analyst).post(reverse("core:pgp_delivery_fetch", args=[delivery.pk]))
    assert response.status_code == 404


def test_manager_revokes_a_pending_delivery(client_for, coordinator, analyst, delivery):
    response = client_for(coordinator).post(
        reverse("core:pgp_delivery_revoke", args=[delivery.pk])
    )
    assert response.status_code == 302
    delivery.refresh_from_db()
    assert delivery.payload == "" and delivery.revoked_at is not None
    assert AuditLog.objects.filter(action=AuditAction.PGP_KEY_DELIVERY_REVOKED).exists()
    assert (
        client_for(analyst)
        .post(reverse("core:pgp_delivery_fetch", args=[delivery.pk]))
        .status_code
        == 410
    )
