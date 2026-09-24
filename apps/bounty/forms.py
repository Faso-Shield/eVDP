"""Formulaires de gestion des recompenses."""

from django import forms

from .models import PaymentMethod, ReviewDecision


class BountyProposalForm(forms.Form):
    amount = forms.DecimalField(
        label="Montant proposé", max_digits=12, decimal_places=2, min_value=0
    )
    justification = forms.CharField(
        label="Justification",
        widget=forms.Textarea(attrs={"rows": 3}),
        required=False,
    )


class BountyDecisionForm(forms.Form):
    amount = forms.DecimalField(
        label="Montant approuvé",
        max_digits=12,
        decimal_places=2,
        min_value=0,
        required=False,
    )
    note = forms.CharField(
        label="Note de décision", widget=forms.Textarea(attrs={"rows": 3}), required=False
    )


class BountyReviewForm(forms.Form):
    decision = forms.ChoiceField(label="Avis", choices=ReviewDecision.choices)
    suggested_amount = forms.DecimalField(
        label="Montant suggéré",
        max_digits=12,
        decimal_places=2,
        required=False,
        min_value=0,
    )
    comment = forms.CharField(
        label="Commentaire", widget=forms.Textarea(attrs={"rows": 3}), required=False
    )


class PaymentForm(forms.Form):
    amount = forms.DecimalField(
        label="Montant versé",
        max_digits=12,
        decimal_places=2,
        min_value=0,
        required=False,
    )
    method = forms.ChoiceField(label="Moyen", choices=PaymentMethod.choices)
    reference = forms.CharField(label="Référence comptable", max_length=120, required=False)


class SettlementForm(forms.Form):
    """Confirmation qu'un versement enregistré a réellement été réglé.

    La preuve est obligatoire : on ne marque jamais un versement "Réglé"
    sur une simple déclaration (voir apps.bounty.services.confirm_settlement).
    """

    proof_file = forms.FileField(
        label="Preuve de paiement (reçu, confirmation bancaire...)",
        widget=forms.FileInput(attrs={"class": "upload-input"}),
    )
    note = forms.CharField(
        label="Note (facultatif)", widget=forms.Textarea(attrs={"rows": 2}), required=False
    )


class PaymentFailureForm(forms.Form):
    reason = forms.CharField(
        label="Motif de l'échec",
        widget=forms.Textarea(attrs={"rows": 2}),
    )
