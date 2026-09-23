"""Formulaires du portefeuille de versement.

Informations personnelles et moyens de paiement necessaires pour qu'un
chercheur puisse recevoir une recompense Bug Bounty. Distinct du profil
public (voir ResearcherProfileForm dans apps.accounts.forms) : ces donnees
ne sont jamais publiees.
"""

from django import forms

from .models import PayoutMethod, PayoutMethodType, PayoutProfile


class PayoutProfileForm(forms.ModelForm):
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


class PayoutMethodForm(forms.ModelForm):
    """Un seul formulaire pour les trois types : seuls les champs pertinents
    au type choisi sont exiges, valide cote serveur dans clean()."""

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
            "other_label": "Intitule",
            "other_reference": "Reference",
        }

    def clean(self):
        cleaned = super().clean()
        method_type = cleaned.get("method_type")

        def require(*fields):
            for field in fields:
                if not (cleaned.get(field) or "").strip():
                    self.add_error(field, "Ce champ est obligatoire pour ce type de moyen.")

        if method_type == PayoutMethodType.BANK_TRANSFER:
            require("bank_name", "account_holder_name", "account_number")
        elif method_type == PayoutMethodType.MOBILE_MONEY:
            require("mobile_operator", "mobile_number", "mobile_holder_name")
        elif method_type == PayoutMethodType.OTHER:
            require("other_label", "other_reference")
        return cleaned
