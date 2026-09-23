"""Formulaires du portefeuille de versement.

Informations personnelles et moyens de paiement necessaires pour qu'un
chercheur puisse recevoir une recompense Bug Bounty. Distinct du profil
public (voir ResearcherProfileForm dans apps.accounts.forms) : ces donnees
ne sont jamais publiees.
"""

from django import forms

from .models import PayoutMethod, PayoutMethodType, PayoutProfile
from .services import ID_DOCUMENT_ALLOWED_EXTENSIONS, validate_id_document


class PayoutProfileForm(forms.ModelForm):
    """Informations personnelles + justificatif d'identite.

    `id_document` n'est pas un champ du modele : c'est un fichier a
    televerser, valide ici puis enregistre par
    apps.researchers.services.attach_id_document (nom opaque, stockage
    controle). Optionnel a chaque soumission : ne pas en fournir un nouveau
    conserve le document deja enregistre.
    """

    id_document = forms.FileField(
        label="Justificatif d'identite (CNIB, passeport…)",
        required=False,
        widget=forms.FileInput(
            attrs={
                "class": "upload-input",
                # Filtre la boite de dialogue du navigateur ; ne remplace pas
                # la validation serveur (voir validate_id_document), seule
                # autorite en la matiere.
                "accept": ".pdf,.jpg,.jpeg,.png,.webp,application/pdf,image/*",
            }
        ),
        help_text=(
            "Formats acceptes : "
            + ", ".join(sorted(ID_DOCUMENT_ALLOWED_EXTENSIONS))
            + ". Televerser un nouveau fichier remplace le document existant."
        ),
    )

    class Meta:
        model = PayoutProfile
        fields = [
            "legal_full_name",
            "id_document_type",
            "id_document_number",
            "contact_phone",
            "address",
            "country",
            "accepted_terms",
        ]
        labels = {
            "legal_full_name": "Nom complet (piece d'identite)",
            "id_document_type": "Type de piece d'identite",
            "id_document_number": "Numero de piece",
            "contact_phone": "Telephone de contact",
            "address": "Adresse",
            "country": "Pays",
            "accepted_terms": "J'atteste l'exactitude des informations fournies",
        }
        widgets = {"address": forms.Textarea(attrs={"rows": 2})}

    def clean_accepted_terms(self):
        accepted = self.cleaned_data.get("accepted_terms")
        if not accepted:
            raise forms.ValidationError(
                "Vous devez attester l'exactitude de vos informations."
            )
        return accepted

    def clean_id_document(self):
        uploaded = self.cleaned_data.get("id_document")
        if uploaded:
            validate_id_document(uploaded)
        return uploaded


class PayoutMethodForm(forms.ModelForm):
    """Un formulaire distinct par type de moyen : cote serveur, seuls les
    champs du type choisi sont exiges (clean()) et persistes (les autres
    sont vides quoi que l'utilisateur y ait saisi avant de changer de type).
    Cote client, le gabarit n'affiche que le groupe correspondant - voir
    static/js/wallet.js - mais le controle serveur reste la seule autorite,
    un client sans JavaScript soumettant tous les champs a la fois.
    """

    #: Champs propres a chaque type. Les cles correspondent aux valeurs de
    #: PayoutMethodType et aux attributs `data-method-group` du gabarit.
    FIELD_GROUPS = {
        PayoutMethodType.BANK_TRANSFER: ["bank_name", "account_holder_name", "account_number"],
        PayoutMethodType.MOBILE_MONEY: [
            "mobile_operator",
            "mobile_number",
            "mobile_holder_name",
        ],
        PayoutMethodType.CRYPTO: [
            "crypto_currency",
            "crypto_network",
            "crypto_wallet_address",
        ],
        PayoutMethodType.PAYPAL: ["paypal_email"],
        PayoutMethodType.OTHER: ["other_label", "other_reference"],
    }

    class Meta:
        model = PayoutMethod
        fields = [
            "method_type",
            "label",
            "bank_name",
            "account_holder_name",
            "account_number",
            "mobile_operator",
            "mobile_number",
            "mobile_holder_name",
            "crypto_currency",
            "crypto_network",
            "crypto_wallet_address",
            "paypal_email",
            "other_label",
            "other_reference",
        ]
        labels = {
            "method_type": "Type de moyen de paiement",
            "label": "Nom (facultatif, pour vous y retrouver)",
            "bank_name": "Nom de la banque",
            "account_holder_name": "Titulaire du compte",
            "account_number": "IBAN / numero de compte",
            "mobile_operator": "Operateur",
            "mobile_number": "Numero mobile money",
            "mobile_holder_name": "Titulaire du compte mobile money",
            "crypto_currency": "Cryptomonnaie",
            "crypto_network": "Reseau",
            "crypto_wallet_address": "Adresse du portefeuille",
            "paypal_email": "Adresse email PayPal",
            "other_label": "Intitule",
            "other_reference": "Reference",
        }
        widgets = {
            "crypto_currency": forms.TextInput(
                attrs={"list": "crypto-currency-suggestions", "placeholder": "BTC, ETH, USDT…"}
            ),
            "crypto_network": forms.TextInput(
                attrs={"placeholder": "Bitcoin, Ethereum (ERC-20), Tron (TRC-20)…"}
            ),
            "paypal_email": forms.EmailInput(attrs={"placeholder": "vous@exemple.com"}),
        }

    def clean(self):
        cleaned = super().clean()
        method_type = cleaned.get("method_type")

        def require(*fields):
            for field in fields:
                if not (cleaned.get(field) or "").strip():
                    self.add_error(field, "Ce champ est obligatoire pour ce type de moyen.")

        if method_type in self.FIELD_GROUPS:
            require(*self.FIELD_GROUPS[method_type])

        # Un formulaire par type : les champs des AUTRES types ne sont
        # jamais persistes, meme si l'utilisateur les avait remplis avant
        # de changer de type de moyen.
        for group_type, fields in self.FIELD_GROUPS.items():
            if group_type != method_type:
                for field in fields:
                    cleaned[field] = ""
        return cleaned
