"""Tests du grand livre du Wallet (workflow v2, branche Bug Bounty).

Le Wallet est un grand livre d'ecritures (credit, ajustement, versement) ;
le solde est calcule, jamais stocke ni modifiable. Aucun flux financier reel
n'est declenche : le versement effectif reste hors plateforme (MVP).
"""

from decimal import Decimal

import pytest
from django.core.exceptions import PermissionDenied, ValidationError

from apps.bounty.models import WalletEntry, WalletEntryKind
from apps.bounty.services import (
    adjust_wallet,
    approve_bounty,
    propose_bounty,
    record_payment,
    wallet_balance,
)
from apps.coordination.models import Case
from apps.coordination.workflow import CaseStatus
from apps.vulnerabilities.constants import Severity

from .conftest import advance

pytestmark = pytest.mark.django_db


@pytest.fixture
def credited_bounty(submitted_bounty_case, analyst, coordinator):
    """Prime de 200 000 XOF approuvee : une ecriture de credit au Wallet."""
    case = advance(submitted_bounty_case, CaseStatus.VALIDATED)
    Case.objects.filter(pk=case.pk).update(severity=Severity.MEDIUM)
    case.refresh_from_db()
    bounty = propose_bounty(case, analyst, amount=Decimal("200000"))
    approve_bounty(bounty, coordinator)
    return bounty


def test_balance_is_computed_from_entries(credited_bounty, coordinator):
    """Solde = credit - versement + ajustement."""
    researcher = credited_bounty.researcher
    assert wallet_balance(researcher) == {"XOF": Decimal("200000")}

    record_payment(credited_bounty, coordinator, amount=Decimal("150000"))
    assert wallet_balance(researcher) == {"XOF": Decimal("50000")}

    adjust_wallet(
        researcher, coordinator, Decimal("-10000"), "Frais bancaires rembourses a tort"
    )
    assert wallet_balance(researcher) == {"XOF": Decimal("40000")}

    kinds = sorted(
        WalletEntry.objects.filter(researcher=researcher).values_list("kind", flat=True)
    )
    assert kinds == sorted(
        [WalletEntryKind.CREDIT, WalletEntryKind.PAYOUT, WalletEntryKind.ADJUSTMENT]
    )


def test_balance_is_empty_without_entries(researcher_a):
    assert wallet_balance(researcher_a) == {}


def test_entry_cannot_be_modified(credited_bounty):
    entry = WalletEntry.objects.get(bounty=credited_bounty)
    entry.amount = Decimal("999999")
    with pytest.raises(ValidationError):
        entry.save()
    entry.refresh_from_db()
    assert entry.amount == Decimal("200000")


def test_entry_cannot_be_deleted(credited_bounty):
    entry = WalletEntry.objects.get(bounty=credited_bounty)
    with pytest.raises(ValidationError):
        entry.delete()
    assert WalletEntry.objects.filter(pk=entry.pk).exists()


def test_adjustment_requires_approve_capability(credited_bounty, analyst):
    with pytest.raises(PermissionDenied):
        adjust_wallet(credited_bounty.researcher, analyst, Decimal("5000"), "Correction")


def test_adjustment_requires_a_reason(credited_bounty, coordinator):
    with pytest.raises(ValidationError):
        adjust_wallet(credited_bounty.researcher, coordinator, Decimal("5000"), "  ")


def test_adjustment_refuses_a_zero_amount(credited_bounty, coordinator):
    with pytest.raises(ValidationError):
        adjust_wallet(credited_bounty.researcher, coordinator, Decimal("0"), "Rien")


def test_wallet_page_shows_balance_and_entries(client_for, credited_bounty):
    client = client_for(credited_bounty.researcher)
    response = client.get("/wallet/")
    assert response.status_code == 200
    page = response.content.decode()

    assert response.context["wallet_balance"] == {"XOF": Decimal("200000")}
    assert "200 000" in page
    assert f"Prime {credited_bounty.case.case_id}" in page
    assert "Crédit (prime approuvée)" in page


def test_wallet_page_lists_only_own_entries(client_for, credited_bounty, researcher_a):
    """Chaque chercheur ne voit que son propre grand livre."""
    response = client_for(researcher_a).get("/wallet/")
    assert response.status_code == 200
    assert response.context["wallet_balance"] == {}
    assert credited_bounty.case.case_id not in response.content.decode()
