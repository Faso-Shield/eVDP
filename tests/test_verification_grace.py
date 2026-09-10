"""Delai de grace et relance de l'exigence d'adresse email verifiee.

Exiger une adresse verifiee prive du jour au lendemain les comptes deja en
base. Ces tests fixent la portee du sursis : il vaut pour les comptes
anterieurs a la bascule, pas pour ceux crees ensuite.
"""

from datetime import date, timedelta

import pytest
from django.core.exceptions import ValidationError
from django.utils import timezone

from apps.accounts.models import TokenPurpose, UserToken
from apps.accounts.tasks import remind_unverified_accounts
from apps.accounts.verification import grace_deadline, is_within_grace
from apps.notifications.models import Notification
from apps.reports.services import submit_report

from .conftest import build_report

pytestmark = pytest.mark.django_db

BASCULE = date(2026, 1, 1)


@pytest.fixture
def regle_active(settings):
    """Bascule au 1er janvier 2026, 30 jours de sursis, relances a J-14/7/1."""
    settings.EVDP = {
        **settings.EVDP,
        "VERIFICATION_ENFORCED_FROM": BASCULE.isoformat(),
        "VERIFICATION_GRACE_DAYS": 30,
        "VERIFICATION_REMINDER_DAYS": ["14", "7", "1"],
    }
    return settings


def _cree_le(user, quand):
    """Force la date de creation, `created_at` etant auto_now_add."""
    type(user).objects.filter(pk=user.pk).update(created_at=quand)
    user.refresh_from_db()
    return user


# ------------------------------------------------------------------- perimetre
def test_account_predating_the_rule_gets_a_deadline(regle_active, bounty_researcher):
    bounty_researcher.email_verified = False
    bounty_researcher.save(update_fields=["email_verified"])
    _cree_le(bounty_researcher, timezone.make_aware(timezone.datetime(2025, 6, 1)))

    assert grace_deadline(bounty_researcher) == BASCULE + timedelta(days=30)


def test_account_created_after_the_rule_gets_none(regle_active, bounty_researcher):
    """Un sursis pour les nouveaux comptes viderait la regle de son sens."""
    bounty_researcher.email_verified = False
    bounty_researcher.save(update_fields=["email_verified"])
    _cree_le(bounty_researcher, timezone.make_aware(timezone.datetime(2026, 3, 1)))

    assert grace_deadline(bounty_researcher) is None


def test_verified_account_has_no_deadline(regle_active, bounty_researcher):
    assert grace_deadline(bounty_researcher) is None


def test_no_grace_without_a_switch_date(settings, bounty_researcher):
    """Sans date de bascule, la regle s'applique sans sursis."""
    settings.EVDP = {**settings.EVDP, "VERIFICATION_ENFORCED_FROM": ""}
    bounty_researcher.email_verified = False
    bounty_researcher.save(update_fields=["email_verified"])
    assert grace_deadline(bounty_researcher) is None


def test_malformed_switch_date_falls_back_to_strict(settings, bounty_researcher):
    """Une date illisible ne doit pas ouvrir un sursis indefini."""
    settings.EVDP = {**settings.EVDP, "VERIFICATION_ENFORCED_FROM": "pas-une-date"}
    bounty_researcher.email_verified = False
    bounty_researcher.save(update_fields=["email_verified"])
    assert grace_deadline(bounty_researcher) is None


# --------------------------------------------------------------------- effets
def test_unverified_account_still_admitted_during_grace(
    regle_active, bounty_program, bounty_researcher, organization, monkeypatch
):
    bounty_researcher.email_verified = False
    bounty_researcher.save(update_fields=["email_verified"])
    _cree_le(bounty_researcher, timezone.make_aware(timezone.datetime(2025, 6, 1)))
    monkeypatch.setattr(timezone, "localdate", lambda: BASCULE + timedelta(days=10))

    case = submit_report(
        build_report(bounty_researcher, organization, bounty_program),
        reporter=bounty_researcher,
    )
    assert case.program_id == bounty_program.id


def test_refused_once_the_grace_has_expired(
    regle_active, bounty_program, bounty_researcher, organization, monkeypatch
):
    bounty_researcher.email_verified = False
    bounty_researcher.save(update_fields=["email_verified"])
    _cree_le(bounty_researcher, timezone.make_aware(timezone.datetime(2025, 6, 1)))
    monkeypatch.setattr(timezone, "localdate", lambda: BASCULE + timedelta(days=31))

    with pytest.raises(ValidationError, match="adresse email verifiee"):
        submit_report(
            build_report(bounty_researcher, organization, bounty_program),
            reporter=bounty_researcher,
        )


def test_grace_is_inclusive_of_its_last_day(regle_active, bounty_researcher):
    bounty_researcher.email_verified = False
    bounty_researcher.save(update_fields=["email_verified"])
    _cree_le(bounty_researcher, timezone.make_aware(timezone.datetime(2025, 6, 1)))
    echeance = BASCULE + timedelta(days=30)

    assert is_within_grace(bounty_researcher, today=echeance)
    assert not is_within_grace(bounty_researcher, today=echeance + timedelta(days=1))


# -------------------------------------------------------------------- relance
def test_reminder_sent_on_a_milestone(
    regle_active, bounty_researcher, monkeypatch
):
    bounty_researcher.email_verified = False
    bounty_researcher.save(update_fields=["email_verified"])
    _cree_le(bounty_researcher, timezone.make_aware(timezone.datetime(2025, 6, 1)))
    # J-7 de l'echeance, qui tombe a BASCULE + 30 jours.
    monkeypatch.setattr(timezone, "localdate", lambda: BASCULE + timedelta(days=23))

    assert remind_unverified_accounts() == 1
    bounty_researcher.refresh_from_db()
    assert bounty_researcher.verification_reminded_on == BASCULE + timedelta(days=23)
    assert Notification.objects.filter(recipient=bounty_researcher).exists()
    assert UserToken.objects.filter(
        user=bounty_researcher, purpose=TokenPurpose.EMAIL_VERIFICATION
    ).exists()


def test_reminder_is_not_sent_twice_the_same_day(
    regle_active, bounty_researcher, monkeypatch
):
    """La tache doit pouvoir etre rejouee sans spammer le chercheur."""
    bounty_researcher.email_verified = False
    bounty_researcher.save(update_fields=["email_verified"])
    _cree_le(bounty_researcher, timezone.make_aware(timezone.datetime(2025, 6, 1)))
    monkeypatch.setattr(timezone, "localdate", lambda: BASCULE + timedelta(days=23))

    assert remind_unverified_accounts() == 1
    assert remind_unverified_accounts() == 0


def test_no_reminder_outside_the_milestones(
    regle_active, bounty_researcher, monkeypatch
):
    bounty_researcher.email_verified = False
    bounty_researcher.save(update_fields=["email_verified"])
    _cree_le(bounty_researcher, timezone.make_aware(timezone.datetime(2025, 6, 1)))
    # J-20 : aucun jalon.
    monkeypatch.setattr(timezone, "localdate", lambda: BASCULE + timedelta(days=10))

    assert remind_unverified_accounts() == 0


def test_verified_accounts_are_never_reminded(
    regle_active, bounty_researcher, monkeypatch
):
    _cree_le(bounty_researcher, timezone.make_aware(timezone.datetime(2025, 6, 1)))
    monkeypatch.setattr(timezone, "localdate", lambda: BASCULE + timedelta(days=23))

    assert remind_unverified_accounts() == 0
