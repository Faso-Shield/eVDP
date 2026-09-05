"""Formulaires de gestion des recompenses."""

from django import forms

from .models import PaymentMethod, ReviewDecision


class BountyProposalForm(forms.Form):
    amount = forms.DecimalField(
        label="Montant propose", max_digits=12, decimal_places=2, min_value=0
    )
    justification = forms.CharField(
        label="Justification",
        widget=forms.Textarea(attrs={"rows": 3}),
        required=False,
    )


class BountyDecisionForm(forms.Form):
    amount = forms.DecimalField(
        label="Montant approuve",
        max_digits=12,
        decimal_places=2,
        min_value=0,
        required=False,
    )
    note = forms.CharField(
        label="Note de decision", widget=forms.Textarea(attrs={"rows": 3}), required=False
    )


class BountyReviewForm(forms.Form):
    decision = forms.ChoiceField(label="Avis", choices=ReviewDecision.choices)
    suggested_amount = forms.DecimalField(
        label="Montant suggere",
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
        label="Montant verse",
        max_digits=12,
        decimal_places=2,
        min_value=0,
        required=False,
    )
    method = forms.ChoiceField(label="Moyen", choices=PaymentMethod.choices)
    reference = forms.CharField(label="Reference comptable", max_length=120, required=False)
