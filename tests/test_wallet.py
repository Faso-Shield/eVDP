"""Tests du portefeuille de versement (informations personnelles et moyens
de paiement declares par un chercheur pour recevoir une recompense).

Principe applique partout : les donnees sont strictement en libre-service
(seul le titulaire peut les consulter ou les modifier), chaque ecriture est
auditee, et un identifiant hors perimetre renvoie 404, jamais 403.
"""

import pytest
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse

from apps.audit.models import AuditAction, AuditLog
from apps.researchers.forms import PayoutMethodForm, PayoutProfileForm
from apps.researchers.models import PayoutMethod, PayoutMethodType, PayoutProfile
from apps.researchers.services import (
    add_payout_method,
    attach_id_document,
    get_or_create_payout_profile,
    remove_payout_method,
    set_primary_payout_method,
    update_payout_method,
    update_payout_profile,
    validate_id_document,
)

pytestmark = pytest.mark.django_db


def _upload(
    name="cnib.pdf", content=b"%PDF-1.4 contenu de test", content_type="application/pdf"
):
    return SimpleUploadedFile(name, content, content_type=content_type)


def _profile(user, with_document=True, **overrides):
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
    if with_document:
        attach_id_document(profile, user, _upload())
        profile.refresh_from_db()
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


def _crypto_method(**overrides):
    defaults = {
        "method_type": PayoutMethodType.CRYPTO,
        "crypto_currency": "USDT",
        "crypto_network": "Tron (TRC-20)",
        "crypto_wallet_address": "TXaBcDeFgHiJkLmNoPqRsTuVwXyZ12345",
    }
    defaults.update(overrides)
    return PayoutMethod(**defaults)


def _paypal_method(**overrides):
    defaults = {
        "method_type": PayoutMethodType.PAYPAL,
        "paypal_email": "awa.traore@example.com",
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
    profile = _profile(researcher_a, with_document=False)
    assert profile.is_complete is False  # aucun justificatif encore joint
    attach_id_document(profile, researcher_a, _upload())
    profile.refresh_from_db()
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


def test_telecel_money_is_a_valid_operator(researcher_a):
    profile = _profile(researcher_a)
    method = add_payout_method(
        profile, researcher_a, _mobile_method(mobile_operator="TELECEL_MONEY")
    )
    assert "Telecel Money" in method.summary


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
    assert profile.legal_full_name == "Awa Traore"
    assert profile.accepted_terms is True
    # Sans justificatif joint, le portefeuille reste incomplet : voir
    # test_upload_document_via_view pour le parcours menant a is_complete.
    assert profile.is_complete is False


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


# ---------------------------------------------------------------- justificatif
def test_valid_document_is_accepted():
    extension, content_type = validate_id_document(_upload("cnib.pdf"))
    assert extension == "pdf"
    assert content_type == "application/pdf"


def test_unlisted_extension_is_rejected():
    with pytest.raises(ValidationError, match="Format non accepte"):
        validate_id_document(_upload("cnib.docx", content_type="application/msword"))


def test_executable_disguised_as_document_is_rejected():
    """Le contenu prime sur l'extension declaree."""
    with pytest.raises(ValidationError):
        validate_id_document(_upload("cnib.pdf", content=b"MZ\x90\x00faux document"))


def test_oversized_document_is_rejected(settings):
    settings.EVDP = {**settings.EVDP, "MAX_ID_DOCUMENT_SIZE": 10}
    with pytest.raises(ValidationError, match="volumineux"):
        validate_id_document(_upload(content=b"contenu plus grand que 10 octets"))


def test_empty_document_is_rejected():
    with pytest.raises(ValidationError, match="vide"):
        validate_id_document(_upload(content=b""))


def test_attach_document_stores_metadata_and_audits(researcher_a):
    profile = get_or_create_payout_profile(researcher_a)
    attach_id_document(profile, researcher_a, _upload("cnib.pdf"))
    profile.refresh_from_db()

    assert profile.id_document_file.name
    assert profile.id_document_original_filename == "cnib.pdf"
    assert profile.id_document_content_type == "application/pdf"
    assert profile.id_document_sha256
    assert profile.id_document_uploaded_at is not None
    assert AuditLog.objects.filter(action=AuditAction.PAYOUT_DOCUMENT_UPLOADED).exists()


def test_storage_name_is_opaque_and_not_the_original_filename(researcher_a):
    profile = get_or_create_payout_profile(researcher_a)
    attach_id_document(profile, researcher_a, _upload("piece_identite_awa.pdf"))
    profile.refresh_from_db()
    assert "piece_identite_awa" not in profile.id_document_file.name


def test_replacing_a_document_deletes_the_old_file(researcher_a):
    profile = get_or_create_payout_profile(researcher_a)
    attach_id_document(profile, researcher_a, _upload("premier.pdf"))
    profile.refresh_from_db()
    # Nom capture comme chaine : `profile.id_document_file` est un FieldFile
    # mutable en place (delete() met son .name a None) - le lire APRES le
    # second televersement testerait un objet deja mute, pas la ligne DB.
    old_name = profile.id_document_file.name
    storage = profile.id_document_file.storage
    assert storage.exists(old_name)

    attach_id_document(profile, researcher_a, _upload("second.pdf"))
    profile.refresh_from_db()

    assert not storage.exists(old_name)
    assert profile.id_document_file.name != old_name


def test_cannot_attach_document_to_someone_elses_profile(researcher_a, researcher_b):
    profile = get_or_create_payout_profile(researcher_a)
    with pytest.raises(PermissionDenied):
        attach_id_document(profile, researcher_b, _upload())


def test_profile_form_rejects_invalid_document_extension():
    form = PayoutProfileForm(
        data={
            "legal_full_name": "Awa Traore",
            "contact_phone": "+22670000000",
            "country": "Burkina Faso",
            "accepted_terms": "on",
        },
        files={"id_document": _upload("cnib.exe", content_type="application/octet-stream")},
    )
    assert not form.is_valid()
    assert "id_document" in form.errors


def test_profile_form_accepts_no_document():
    """Le justificatif est facultatif a chaque soumission : ne pas en
    fournir de nouveau conserve celui deja enregistre."""
    form = PayoutProfileForm(
        data={
            "legal_full_name": "Awa Traore",
            "contact_phone": "+22670000000",
            "country": "Burkina Faso",
            "accepted_terms": "on",
        }
    )
    assert form.is_valid(), form.errors


# --------------------------------------------------------------------- vues
def test_upload_document_via_view(client_for, researcher_a):
    client = client_for(researcher_a)
    response = client.post(
        reverse("wallet:home"),
        {
            "form": "profile",
            "legal_full_name": "Awa Traore",
            "contact_phone": "+22670000000",
            "country": "Burkina Faso",
            "accepted_terms": "on",
            "id_document": _upload("cnib.pdf"),
        },
    )
    assert response.status_code == 302
    profile = PayoutProfile.objects.get(user=researcher_a)
    assert profile.id_document_original_filename == "cnib.pdf"
    assert profile.is_complete is True


def test_document_owner_can_download(client_for, researcher_a):
    profile = get_or_create_payout_profile(researcher_a)
    attach_id_document(profile, researcher_a, _upload("cnib.pdf"))

    client = client_for(researcher_a)
    response = client.get(reverse("wallet:id_document_download"))
    assert response.status_code == 200
    assert AuditLog.objects.filter(action=AuditAction.PAYOUT_DOCUMENT_DOWNLOADED).exists()


def test_download_without_document_is_404(client_for, researcher_a):
    client = client_for(researcher_a)
    response = client.get(reverse("wallet:id_document_download"))
    assert response.status_code == 404


def test_another_researcher_cannot_reach_the_first_ones_document(
    client_for, researcher_a, researcher_b
):
    """Chaque compte n'a acces qu'a SON PROPRE document : la vue est
    volontairement liee a request.user, jamais a un identifiant d'URL."""
    profile = get_or_create_payout_profile(researcher_a)
    attach_id_document(profile, researcher_a, _upload("cnib.pdf"))

    client = client_for(researcher_b)
    response = client.get(reverse("wallet:id_document_download"))
    assert response.status_code == 404


def test_wallet_form_has_multipart_enctype(client_for, researcher_a):
    """Regression : sans enctype='multipart/form-data', le navigateur
    n'envoie jamais le contenu d'un fichier joint, seulement son nom."""
    client = client_for(researcher_a)
    content = client.get(reverse("wallet:home")).content.decode()
    assert 'enctype="multipart/form-data"' in content


def test_wallet_page_shows_current_document_status(client_for, researcher_a):
    profile = get_or_create_payout_profile(researcher_a)
    attach_id_document(profile, researcher_a, _upload("cnib.pdf"))

    client = client_for(researcher_a)
    content = client.get(reverse("wallet:home")).content.decode()
    assert "cnib.pdf" in content
    assert reverse("wallet:id_document_download") in content


def test_wallet_page_leaks_no_django_comment_markers(client_for, researcher_a):
    """Regression : les commentaires Django multi-lignes en syntaxe {# #}
    ne sont pas supportes et s'affichent comme texte brut (voir aussi
    tests/test_programs.py, meme piege deja rencontre sur un autre gabarit)."""
    client = client_for(researcher_a)
    content = client.get(reverse("wallet:home")).content.decode()
    assert "{#" not in content
    assert "#}" not in content


# ------------------------------------------------------- cryptomonnaie
def test_add_crypto_method(researcher_a):
    profile = _profile(researcher_a)
    method = add_payout_method(profile, researcher_a, _crypto_method())
    assert method.pk is not None
    assert method.method_type == PayoutMethodType.CRYPTO


def test_crypto_wallet_address_is_masked_in_summary(researcher_a):
    profile = _profile(researcher_a)
    method = add_payout_method(profile, researcher_a, _crypto_method())
    assert "TXaBcDeFgHiJkLmNoPqRsTuVwXyZ12345" not in method.summary
    assert method.summary.endswith("2345")
    assert "USDT" in method.summary
    assert "Tron (TRC-20)" in method.summary


def test_crypto_requires_its_fields():
    form = PayoutMethodForm(data={"method_type": PayoutMethodType.CRYPTO})
    assert not form.is_valid()
    assert "crypto_currency" in form.errors
    assert "crypto_network" in form.errors
    assert "crypto_wallet_address" in form.errors


def test_valid_crypto_form_passes():
    form = PayoutMethodForm(
        data={
            "method_type": PayoutMethodType.CRYPTO,
            "crypto_currency": "BTC",
            "crypto_network": "Bitcoin",
            "crypto_wallet_address": "bc1qxyz0000000000000000000000000000000000",
        }
    )
    assert form.is_valid(), form.errors


def test_add_crypto_method_via_view(client_for, researcher_a):
    client = client_for(researcher_a)
    response = client.post(
        reverse("wallet:method_add"),
        {
            "method_type": PayoutMethodType.CRYPTO,
            "crypto_currency": "ETH",
            "crypto_network": "Ethereum (ERC-20)",
            "crypto_wallet_address": "0x0000000000000000000000000000000000dEaD",
        },
    )
    assert response.status_code == 302
    method = PayoutMethod.objects.get(profile__user=researcher_a)
    assert method.method_type == PayoutMethodType.CRYPTO
    assert method.crypto_currency == "ETH"


# --------------------------------------- un formulaire par type, pas un seul
def test_switching_type_never_persists_the_other_types_fields():
    """Coeur de la demande : remplir plusieurs blocs puis choisir un type ne
    doit conserver QUE les champs de ce type, jamais les autres."""
    form = PayoutMethodForm(
        data={
            "method_type": PayoutMethodType.CRYPTO,
            "crypto_currency": "BTC",
            "crypto_network": "Bitcoin",
            "crypto_wallet_address": "bc1qxyz0000000000000000000000000000000000",
            # Champs d'un AUTRE type, remplis avant de finalement choisir crypto :
            "bank_name": "Coris Bank",
            "account_holder_name": "Awa Traore",
            "account_number": "BF1234567890123456",
            "mobile_operator": "ORANGE_MONEY",
            "mobile_number": "70000000",
            "mobile_holder_name": "Awa Traore",
        }
    )
    assert form.is_valid(), form.errors
    method = form.save(commit=False)
    assert method.bank_name == ""
    assert method.account_number == ""
    assert method.mobile_number == ""
    assert method.crypto_wallet_address == "bc1qxyz0000000000000000000000000000000000"


def test_method_form_renders_one_group_per_type(client_for, researcher_a):
    client = client_for(researcher_a)
    content = client.get(reverse("wallet:home")).content.decode()
    for group in ("BANK_TRANSFER", "MOBILE_MONEY", "CRYPTO", "OTHER"):
        assert f'data-method-group="{group}"' in content


def test_add_form_shows_no_group_before_a_type_is_chosen(client_for, researcher_a):
    """Le type n'a pas de valeur par defaut (champ obligatoire, liste
    deroulante sur "---------") : aucun groupe ne doit presupposer un type
    tant que l'utilisateur n'a rien choisi."""
    client = client_for(researcher_a)
    content = client.get(reverse("wallet:home")).content.decode()
    add_form_html = content.split("Ajouter un moyen de paiement")[1]
    for group in ("BANK_TRANSFER", "MOBILE_MONEY", "CRYPTO", "OTHER"):
        block = add_form_html.split(f'data-method-group="{group}"')[1][:40]
        assert "hidden" in block


def test_edit_form_shows_the_methods_own_group_by_default(client_for, researcher_a):
    profile = _profile(researcher_a)
    method = add_payout_method(profile, researcher_a, _crypto_method())

    client = client_for(researcher_a)
    content = client.get(reverse("wallet:method_edit", args=[method.id])).content.decode()
    crypto_block = content.split('data-method-group="CRYPTO"')[1][:40]
    bank_block = content.split('data-method-group="BANK_TRANSFER"')[1][:40]
    assert "hidden" not in crypto_block
    assert "hidden" in bank_block


def test_wallet_page_loads_the_dynamic_form_script(client_for, researcher_a):
    client = client_for(researcher_a)
    content = client.get(reverse("wallet:home")).content.decode()
    assert "js/wallet.js" in content


# ------------------------------------------------------------------- paypal
def test_add_paypal_method(researcher_a):
    profile = _profile(researcher_a)
    method = add_payout_method(profile, researcher_a, _paypal_method())
    assert method.pk is not None
    assert method.method_type == PayoutMethodType.PAYPAL


def test_paypal_email_is_masked_in_summary(researcher_a):
    profile = _profile(researcher_a)
    method = add_payout_method(profile, researcher_a, _paypal_method())
    assert "awa.traore@example.com" not in method.summary
    assert method.summary.startswith("PayPal — ")
    assert method.summary.endswith(".com")


def test_paypal_requires_its_email():
    form = PayoutMethodForm(data={"method_type": PayoutMethodType.PAYPAL})
    assert not form.is_valid()
    assert "paypal_email" in form.errors


def test_paypal_rejects_an_invalid_email():
    form = PayoutMethodForm(
        data={"method_type": PayoutMethodType.PAYPAL, "paypal_email": "pas-un-email"}
    )
    assert not form.is_valid()
    assert "paypal_email" in form.errors


def test_valid_paypal_form_passes():
    form = PayoutMethodForm(
        data={"method_type": PayoutMethodType.PAYPAL, "paypal_email": "awa@example.com"}
    )
    assert form.is_valid(), form.errors


def test_add_paypal_method_via_view(client_for, researcher_a):
    client = client_for(researcher_a)
    response = client.post(
        reverse("wallet:method_add"),
        {"method_type": PayoutMethodType.PAYPAL, "paypal_email": "awa@example.com"},
    )
    assert response.status_code == 302
    method = PayoutMethod.objects.get(profile__user=researcher_a)
    assert method.method_type == PayoutMethodType.PAYPAL
    assert method.paypal_email == "awa@example.com"


def test_switching_to_paypal_never_persists_other_types_fields():
    form = PayoutMethodForm(
        data={
            "method_type": PayoutMethodType.PAYPAL,
            "paypal_email": "awa@example.com",
            "bank_name": "Coris Bank",
            "account_holder_name": "Awa Traore",
            "account_number": "BF1234567890123456",
        }
    )
    assert form.is_valid(), form.errors
    method = form.save(commit=False)
    assert method.bank_name == ""
    assert method.account_number == ""
    assert method.paypal_email == "awa@example.com"


def test_method_form_renders_a_paypal_group(client_for, researcher_a):
    client = client_for(researcher_a)
    content = client.get(reverse("wallet:home")).content.decode()
    assert 'data-method-group="PAYPAL"' in content
    assert "Adresse email PayPal" in content
