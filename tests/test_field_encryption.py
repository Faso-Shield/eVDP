"""Chiffrement au repos des donnees de versement (apps.core.fields).

Ce qui compte : la base ne contient jamais la valeur en clair, le code la
lit en clair, et une cle absente ou erronee se signale au lieu de faire
passer du chiffre pour une donnee.
"""

from io import StringIO

import pytest
from cryptography.fernet import Fernet
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.core.management import call_command
from django.db import connection

from apps.core.fields import FERNET_PREFIX
from apps.researchers.models import PayoutMethod, PayoutMethodType, PayoutProfile

pytestmark = pytest.mark.django_db

IBAN = "BF42BF0840101300463574000390"


def raw(model, pk, column):
    """Valeur telle qu'elle est stockee, sans passer par le champ."""
    with connection.cursor() as cursor:
        cursor.execute(
            f"SELECT {column} FROM {model._meta.db_table} WHERE id = %s",  # noqa: S608
            [model._meta.pk.get_db_prep_value(pk, connection)],
        )
        return cursor.fetchone()[0]


def write_raw(model, pk, column, value):
    with connection.cursor() as cursor:
        cursor.execute(
            f"UPDATE {model._meta.db_table} SET {column} = %s WHERE id = %s",  # noqa: S608
            [value, model._meta.pk.get_db_prep_value(pk, connection)],
        )


@pytest.fixture
def profile(researcher_a):
    return PayoutProfile.objects.create(
        user=researcher_a,
        legal_full_name="Awa Ouedraogo",
        id_document_number="B1234567",
        contact_phone="+22670000000",
        address="Secteur 15, Ouagadougou",
    )


@pytest.fixture
def bank_method(profile):
    return PayoutMethod.objects.create(
        profile=profile,
        method_type=PayoutMethodType.BANK_TRANSFER,
        account_holder_name="Awa Ouedraogo",
        account_number=IBAN,
    )


def test_payout_data_is_stored_encrypted_and_read_in_clear(profile, bank_method):
    for model, obj, column, clear in [
        (PayoutProfile, profile, "legal_full_name", "Awa Ouedraogo"),
        (PayoutProfile, profile, "id_document_number", "B1234567"),
        (PayoutProfile, profile, "contact_phone", "+22670000000"),
        (PayoutProfile, profile, "address", "Secteur 15, Ouagadougou"),
        (PayoutMethod, bank_method, "account_number", IBAN),
        (PayoutMethod, bank_method, "account_holder_name", "Awa Ouedraogo"),
    ]:
        stored = raw(model, obj.pk, column)
        assert stored.startswith(FERNET_PREFIX)
        assert clear not in stored
        assert getattr(model.objects.get(pk=obj.pk), column) == clear


def test_empty_values_stay_empty(profile):
    assert raw(PayoutProfile, profile.pk, "id_document_original_filename") == ""


def test_legacy_clear_values_stay_readable_then_get_encrypted(profile):
    """Une donnee anterieure au chiffrement se lit, et la commande la chiffre."""
    write_raw(PayoutProfile, profile.pk, "contact_phone", "+22671111111")
    assert PayoutProfile.objects.get(pk=profile.pk).contact_phone == "+22671111111"

    call_command("rechiffrer_champs", stdout=StringIO())

    assert raw(PayoutProfile, profile.pk, "contact_phone").startswith(FERNET_PREFIX)
    assert PayoutProfile.objects.get(pk=profile.pk).contact_phone == "+22671111111"


def test_key_rotation(settings, profile):
    ancienne = settings.FIELD_ENCRYPTION_KEYS[0]
    nouvelle = Fernet.generate_key().decode()

    # La nouvelle cle en tete : l'ancienne dechiffre encore l'existant.
    settings.FIELD_ENCRYPTION_KEYS = [nouvelle, ancienne]
    assert PayoutProfile.objects.get(pk=profile.pk).legal_full_name == "Awa Ouedraogo"
    call_command("rechiffrer_champs", stdout=StringIO())

    # Apres rechiffrement, l'ancienne cle peut etre retiree.
    settings.FIELD_ENCRYPTION_KEYS = [nouvelle]
    assert PayoutProfile.objects.get(pk=profile.pk).legal_full_name == "Awa Ouedraogo"


def test_wrong_key_is_an_error_not_ciphertext_shown_as_data(settings, profile):
    settings.FIELD_ENCRYPTION_KEYS = [Fernet.generate_key().decode()]
    with pytest.raises(ImproperlyConfigured):
        PayoutProfile.objects.get(pk=profile.pk)


def test_max_length_is_still_validated(profile):
    profile.id_document_number = "X" * 61
    with pytest.raises(ValidationError) as exc:
        profile.full_clean()
    assert "id_document_number" in exc.value.message_dict


def test_encrypted_email_is_validated(profile):
    method = PayoutMethod(
        profile=profile, method_type=PayoutMethodType.PAYPAL, paypal_email="pas-un-email"
    )
    with pytest.raises(ValidationError) as exc:
        method.full_clean()
    assert "paypal_email" in exc.value.message_dict
