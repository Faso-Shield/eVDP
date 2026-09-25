"""Coordonnees de paiement du chercheur : etat, relance, affichage.

Sans coordonnees de paiement, une prime approuvee ne peut pas etre versee.
Le coordinateur doit pouvoir relancer le chercheur (notification et email),
qui est aussi relance d'office a l'approbation et averti sur son espace.
"""

from datetime import timedelta
from decimal import Decimal

import pytest
from django.core import mail
from django.core.exceptions import PermissionDenied, ValidationError
from django.urls import reverse
from django.utils import timezone

from apps.audit.models import AuditAction, AuditLog
from apps.bounty.services import (
    approve_bounty,
    payout_readiness,
    propose_bounty,
    request_payout_details,
)
from apps.notifications.models import Notification, NotificationKind

pytestmark = pytest.mark.django_db


@pytest.fixture
def proposed(bounty_case, analyst):
    from apps.coordination.models import Case
    from apps.vulnerabilities.constants import Severity

    Case.objects.filter(pk=bounty_case.pk).update(severity=Severity.MEDIUM)
    bounty_case.refresh_from_db()
    return propose_bounty(bounty_case, analyst, amount=Decimal("200000"))


def _complete_wallet(user):
    from django.core.files.uploadedfile import SimpleUploadedFile

    from apps.researchers.models import PayoutMethod, PayoutMethodType
    from apps.researchers.services import (
        add_payout_method,
        attach_id_document,
        get_or_create_payout_profile,
    )

    profile = get_or_create_payout_profile(user)
    profile.legal_full_name = "Awa Traore"
    profile.contact_phone = "+22670000000"
    profile.accepted_terms = True
    profile.save()
    attach_id_document(
        profile,
        user,
        SimpleUploadedFile("cnib.pdf", b"%PDF-1.4 x", content_type="application/pdf"),
    )
    add_payout_method(
        profile,
        user,
        PayoutMethod(
            method_type=PayoutMethodType.BANK_TRANSFER,
            bank_name="Coris Bank",
            account_holder_name="Awa Traore",
            account_number="BF1234567890123456",
        ),
    )


def _requests(user):
    return Notification.objects.filter(
        recipient=user, kind=NotificationKind.PAYOUT_DETAILS_REQUESTED
    )


# ------------------------------------------------------------------- etat
def test_empty_wallet_lists_everything_missing(bounty_researcher):
    readiness = payout_readiness(bounty_researcher)
    assert readiness["ready"] is False
    assert "Moyen de paiement principal" in readiness["missing"]
    assert "Pièce d'identité" in readiness["missing"]


def test_complete_wallet_is_ready(bounty_researcher):
    _complete_wallet(bounty_researcher)
    assert payout_readiness(bounty_researcher) == {
        "ready": True,
        "missing": [],
        "method": payout_readiness(bounty_researcher)["method"],
    }


# ------------------------------------------------------------------ relance
def test_coordinator_requests_payout_details(proposed, coordinator, bounty_researcher):
    mail.outbox.clear()
    request_payout_details(proposed, coordinator)

    notification = _requests(bounty_researcher).get()
    assert notification.url == reverse("wallet:home")
    assert "Moyen de paiement principal" in notification.body
    assert bounty_researcher.email in [m.to[0] for m in mail.outbox]
    assert AuditLog.objects.filter(
        action=AuditAction.PAYOUT_DETAILS_REQUESTED, actor=coordinator
    ).exists()


def test_request_is_limited_to_once_a_day(proposed, coordinator, bounty_researcher):
    request_payout_details(proposed, coordinator)
    with pytest.raises(ValidationError, match="déjà été relancé"):
        request_payout_details(proposed, coordinator)
    _requests(bounty_researcher).update(created_at=timezone.now() - timedelta(days=2))
    request_payout_details(proposed, coordinator)
    assert _requests(bounty_researcher).count() == 2


def test_no_request_when_the_wallet_is_complete(proposed, coordinator, bounty_researcher):
    _complete_wallet(bounty_researcher)
    with pytest.raises(ValidationError, match="déjà complet"):
        request_payout_details(proposed, coordinator)


def test_analyst_cannot_request(proposed, analyst):
    with pytest.raises(PermissionDenied):
        request_payout_details(proposed, analyst)


def test_approval_requests_the_details_automatically(proposed, coordinator, bounty_researcher):
    approve_bounty(proposed, coordinator)
    assert _requests(bounty_researcher).count() == 1


def test_approval_with_complete_wallet_sends_no_request(
    proposed, coordinator, bounty_researcher
):
    _complete_wallet(bounty_researcher)
    approve_bounty(proposed, coordinator)
    assert not _requests(bounty_researcher).exists()


# --------------------------------------------------------------- interface
def test_bounty_page_offers_the_request_button(client_for, proposed, coordinator):
    client = client_for(coordinator)
    url = reverse("bounty:detail", args=[proposed.pk])
    content = client.get(url).content.decode()
    assert "Portefeuille du chercheur" in content
    assert "Demander au chercheur de compléter" in content

    response = client.post(reverse("bounty:request_payout", args=[proposed.pk]))
    assert response.status_code == 302
    assert "Dernière relance" in client.get(url).content.decode()


def test_request_via_get_is_rejected(client_for, proposed, coordinator):
    response = client_for(coordinator).get(
        reverse("bounty:request_payout", args=[proposed.pk])
    )
    assert response.status_code == 405


def test_researcher_is_told_what_is_missing(client_for, proposed, bounty_researcher):
    client = client_for(bounty_researcher)
    detail = client.get(reverse("bounty:detail", args=[proposed.pk])).content.decode()
    assert "Complétez votre portefeuille" in detail
    dashboard = client.get(reverse("dashboard:researcher")).content.decode()
    assert "Une récompense vous attend" in dashboard


def test_bounty_page_shows_the_tier_and_the_track(client_for, proposed, coordinator):
    content = (
        client_for(coordinator)
        .get(reverse("bounty:detail", args=[proposed.pk]))
        .content.decode()
    )
    assert "Palier" in content
    assert "Approuvée et créditée" in content


# ------------------------------------------------ fenetres B1 / B2 du dossier
def test_propose_dialog_shows_the_tier_and_prefills_the_amount(
    client_for, bounty_case, analyst
):
    from .conftest import claim

    claim(bounty_case, analyst)
    content = client_for(analyst).get(bounty_case.get_absolute_url()).content.decode()
    assert "Palier du programme" in content
    assert "Montant suggéré" in content


def test_approve_dialog_shows_the_proposal(client_for, proposed, coordinator):
    from .conftest import claim

    case = proposed.case
    claim(case, coordinator)
    content = client_for(coordinator).get(case.get_absolute_url()).content.decode()
    assert "Montant proposé" in content
    assert "Portefeuille du chercheur" in content


# ------------------------------------------------------------- pages 403
def test_business_report_page_uses_the_error_layout(client_for, analyst):
    content = client_for(analyst).get(reverse("reports:submit")).content.decode()
    assert "error-card" in content
    assert "Signalement réservé aux chercheurs" in content


def test_csrf_failure_uses_the_error_layout(researcher_a):
    from django.test import Client

    client = Client(enforce_csrf_checks=True)
    client.force_login(researcher_a)
    response = client.post(reverse("accounts:profile"), {"full_name": "x"})
    assert response.status_code == 403
    content = response.content.decode()
    assert "error-card" in content
    assert "Ce formulaire a expiré" in content
