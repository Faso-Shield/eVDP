"""Tests du portefeuille de versement (informations personnelles et moyens
de paiement declares par un chercheur pour recevoir une recompense).

Principe applique partout : les donnees sont strictement en libre-service
(seul le titulaire peut les consulter ou les modifier), chaque ecriture est
auditee, et un identifiant hors perimetre renvoie 404, jamais 403.
"""

import pytest
from django.core.exceptions import PermissionDenied, ValidationError
from django.urls import reverse

from apps.audit.models import AuditAction, AuditLog
from apps.researchers.forms import PayoutMethodForm
from apps.researchers.models import PayoutMethod, PayoutMethodType, PayoutProfile
from apps.researchers.services import (
    add_payout_method,
    get_or_create_payout_profile,
    remove_payout_method,
    set_primary_payout_method,
    update_payout_method,
    update_payout_profile,
)

pytestmark = pytest.mark.django_db


def _profile(user, **overrides):
    profile = get_or_create_payout_profile(user)
    defaults = {
        "legal_full_name": "Awa Traore",
        "contact_phone": "+22670000000",
        "accepted_terms": True,
    }
    defaults.update(overrides)
    for key, value in defaults.items():
        setattr(profile, key, value)
    profile.save()
    return profile


def _bank_method(**overrides):
    defaults = {
        "method_type": PayoutMethodType.BANK_TRANSFER,
        "bank_name": "Coris Bank",
        "account_holder_name": "Awa Traore",
        "account_number": "BF1234567890123456",
    }
    defaults.update(overrides)
    return PayoutMethod(**defaults)


def _mobile_method(**overrides):
    defaults = {
        "method_type": PayoutMethodType.MOBILE_MONEY,
        "mobile_operator": "ORANGE_MONEY",
        "mobile_number": "70000000",
        "mobile_holder_name": "Awa Traore",
    }
    defaults.update(overrides)
    return PayoutMethod(**defaults)


# --------------------------------------------------------------------- profil
def test_get_or_create_is_idempotent(researcher_a):
    first = get_or_create_payout_profile(researcher_a)
    second = get_or_create_payout_profile(researcher_a)
    assert first.pk == second.pk


def test_profile_incomplete_until_terms_accepted(researcher_a):
    profile = get_or_create_payout_profile(researcher_a)
    assert profile.is_complete is False
    profile = _profile(researcher_a)
    assert profile.is_complete is True


def test_update_profile_is_audited(researcher_a):
    profile = _profile(researcher_a)
    update_payout_profile(profile, researcher_a)
    assert AuditLog.objects.filter(action=AuditAction.PAYOUT_PROFILE_UPDATED).exists()


def test_cannot_update_someone_elses_profile(researcher_a, researcher_b):
    profile = _profile(researcher_a)
    with pytest.raises(PermissionDenied):
        update_payout_profile(profile, researcher_b)


# ------------------------------------------------------------------- methodes
def test_add_bank_method(researcher_a):
    profile = _profile(researcher_a)
    method = add_payout_method(profile, researcher_a, _bank_method())
    assert method.pk is not None
    assert method.is_primary is True  # premier moyen : principal par defaut
    assert AuditLog.objects.filter(action=AuditAction.PAYOUT_METHOD_ADDED).exists()


def test_second_method_is_not_primary_by_default(researcher_a):
    profile = _profile(researcher_a)
    add_payout_method(profile, researcher_a, _bank_method())
    second = add_payout_method(profile, researcher_a, _mobile_method())
    assert second.is_primary is False


def test_only_one_primary_at_a_time(researcher_a):
    profile = _profile(researcher_a)
    first = add_payout_method(profile, researcher_a, _bank_method())
    second = add_payout_method(profile, researcher_a, _mobile_method())
    set_primary_payout_method(second, researcher_a)

    first.refresh_from_db()
    second.refresh_from_db()
    assert first.is_primary is False
    assert second.is_primary is True


def test_cannot_set_inactive_method_as_primary(researcher_a):
    profile = _profile(researcher_a)
    method = add_payout_method(profile, researcher_a, _bank_method())
    remove_payout_method(method, researcher_a)
    with pytest.raises(ValidationError):
        set_primary_payout_method(method, researcher_a)


def test_remove_is_a_soft_deactivation(researcher_a):
    profile = _profile(researcher_a)
    method = add_payout_method(profile, researcher_a, _bank_method())
    remove_payout_method(method, researcher_a)

    assert PayoutMethod.objects.filter(pk=method.pk).exists()  # jamais supprime
    method.refresh_from_db()
    assert method.is_active is False
    assert method.is_primary is False
    assert AuditLog.objects.filter(action=AuditAction.PAYOUT_METHOD_REMOVED).exists()


def test_max_methods_is_enforced(researcher_a, settings):
    settings.EVDP = {**settings.EVDP, "MAX_PAYOUT_METHODS": 1}
    profile = _profile(researcher_a)
    add_payout_method(profile, researcher_a, _bank_method())
    with pytest.raises(ValidationError):
        add_payout_method(profile, researcher_a, _mobile_method())


def test_cannot_add_method_to_someone_elses_profile(researcher_a, researcher_b):
    profile = _profile(researcher_a)
    with pytest.raises(PermissionDenied):
        add_payout_method(profile, researcher_b, _bank_method())


def test_update_method_is_audited(researcher_a):
    profile = _profile(researcher_a)
    method = add_payout_method(profile, researcher_a, _bank_method())
    method.bank_name = "Ecobank"
    update_payout_method(method, researcher_a)
    assert AuditLog.objects.filter(action=AuditAction.PAYOUT_METHOD_UPDATED).exists()


# --------------------------------------------------------------------- masquage
def test_bank_account_is_masked_in_summary(researcher_a):
    profile = _profile(researcher_a)
    method = add_payout_method(profile, researcher_a, _bank_method())
    assert "BF1234567890123456" not in method.summary
    assert method.summary.endswith("3456")


def test_mobile_number_is_masked_in_summary(researcher_a):
    profile = _profile(researcher_a)
    method = add_payout_method(profile, researcher_a, _mobile_method())
    assert "70000000" not in method.summary
    assert method.summary.endswith("0000")


# --------------------------------------------------------------------- formulaire
def test_bank_transfer_requires_bank_fields():
    form = PayoutMethodForm(data={"method_type": PayoutMethodType.BANK_TRANSFER})
    assert not form.is_valid()
    assert "bank_name" in form.errors
    assert "account_holder_name" in form.errors
    assert "account_number" in form.errors


def test_mobile_money_requires_mobile_fields():
    form = PayoutMethodForm(data={"method_type": PayoutMethodType.MOBILE_MONEY})
    assert not form.is_valid()
    assert "mobile_operator" in form.errors
    assert "mobile_number" in form.errors


def test_valid_bank_transfer_form_passes():
    form = PayoutMethodForm(
        data={
            "method_type": PayoutMethodType.BANK_TRANSFER,
            "bank_name": "Coris Bank",
            "account_holder_name": "Awa Traore",
            "account_number": "BF1234567890123456",
        }
    )
    assert form.is_valid(), form.errors


# ------------------------------------------------------------------------- vues
def test_wallet_requires_login(client):
    response = client.get(reverse("wallet:home"))
    assert response.status_code == 302
    assert "/login/" in response.url


def test_wallet_accessible_to_researcher(client_for, researcher_a):
    client = client_for(researcher_a)
    response = client.get(reverse("wallet:home"))
    assert response.status_code == 200


def test_wallet_forbidden_to_non_researcher_role(client_for, dsi_alpha):
    client = client_for(dsi_alpha)
    response = client.get(reverse("wallet:home"))
    assert response.status_code == 403


def test_wallet_forbidden_to_auditor(client_for, auditor):
    """AUDITOR est un role national : ni chercheur, ni chasseur de bounty."""
    client = client_for(auditor)
    response = client.get(reverse("wallet:home"))
    assert response.status_code == 403


def test_update_profile_via_view(client_for, researcher_a):
    client = client_for(researcher_a)
    response = client.post(
        reverse("wallet:home"),
        {
            "form": "profile",
            "legal_full_name": "Awa Traore",
            "contact_phone": "+22670000000",
            "country": "Burkina Faso",
            "accepted_terms": "on",
        },
    )
    assert response.status_code == 302
    profile = PayoutProfile.objects.get(user=researcher_a)
    assert profile.is_complete is True


def test_add_method_via_view(client_for, researcher_a):
    client = client_for(researcher_a)
    _profile(researcher_a)
    response = client.post(
        reverse("wallet:method_add"),
        {
            "method_type": PayoutMethodType.MOBILE_MONEY,
            "mobile_operator": "ORANGE_MONEY",
            "mobile_number": "70000000",
            "mobile_holder_name": "Awa Traore",
        },
    )
    assert response.status_code == 302
    assert PayoutMethod.objects.filter(profile__user=researcher_a).count() == 1


def test_cannot_edit_another_researchers_method_returns_404(
    client_for, researcher_a, researcher_b
):
    profile = _profile(researcher_a)
    method = add_payout_method(profile, researcher_a, _bank_method())

    client = client_for(researcher_b)
    response = client.get(reverse("wallet:method_edit", args=[method.id]))
    assert response.status_code == 404


def test_cannot_remove_another_researchers_method(client_for, researcher_a, researcher_b):
    profile = _profile(researcher_a)
    method = add_payout_method(profile, researcher_a, _bank_method())

    client = client_for(researcher_b)
    response = client.post(reverse("wallet:method_remove", args=[method.id]))
    assert response.status_code == 404
    method.refresh_from_db()
    assert method.is_active is True  # inchange


def test_remove_via_get_is_rejected(client_for, researcher_a):
    """Une mutation ne doit jamais s'executer sur une simple requete GET
    (protection CSRF de fait, les methodes surs n'exigent pas de jeton)."""
    profile = _profile(researcher_a)
    method = add_payout_method(profile, researcher_a, _bank_method())

    client = client_for(researcher_a)
    response = client.get(reverse("wallet:method_remove", args=[method.id]))
    assert response.status_code == 405
    method.refresh_from_db()
    assert method.is_active is True


def test_wallet_page_shows_masked_values_only(client_for, researcher_a):
    profile = _profile(researcher_a)
    add_payout_method(profile, researcher_a, _bank_method())

    client = client_for(researcher_a)
    content = client.get(reverse("wallet:home")).content.decode()
    assert "BF1234567890123456" not in content
    assert "3456" in content


def test_sidebar_link_visible_only_to_researchers(client_for, researcher_a, dsi_alpha):
    # dashboard:home redirige vers l'espace correspondant au role de l'appelant.
    researcher_content = (
        client_for(researcher_a).get(reverse("dashboard:home"), follow=True).content.decode()
    )
    assert reverse("wallet:home") in researcher_content

    dsi_content = (
        client_for(dsi_alpha).get(reverse("dashboard:home"), follow=True).content.decode()
    )
    assert reverse("wallet:home") not in dsi_content
