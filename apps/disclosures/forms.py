"""Formulaires de redaction des advisories."""

from django import forms
from django.forms import inlineformset_factory

from .models import Advisory, AdvisoryReference, AdvisoryTimelineEntry


class AdvisoryForm(forms.ModelForm):
    class Meta:
        model = Advisory
        fields = [
            "title",
            "summary",
            "organization",
            "product",
            "affected_versions",
            "fixed_versions",
            "description",
            "impact",
            "solution",
            "workaround",
            "severity",
            "cvss_score",
            "cvss_vector",
            "cwe",
            "cve",
            "credit",
            "scheduled_for",
        ]
        labels = {
            "title": "Titre",
            "summary": "Résumé public",
            "organization": "Organisation",
            "product": "Produit",
            "affected_versions": "Versions affectées",
            "fixed_versions": "Versions corrigées",
            "description": "Description",
            "impact": "Impact",
            "solution": "Solution",
            "workaround": "Contournement",
            "severity": "Sévérité",
            "cvss_score": "Score CVSS",
            "cvss_vector": "Vecteur CVSS",
            "cwe": "CWE",
            "cve": "CVE",
            "credit": "Crédit chercheur",
            "scheduled_for": "Publication planifiée",
        }
        widgets = {
            "summary": forms.Textarea(attrs={"rows": 3}),
            "description": forms.Textarea(attrs={"rows": 6}),
            "impact": forms.Textarea(attrs={"rows": 4}),
            "solution": forms.Textarea(attrs={"rows": 4}),
            "workaround": forms.Textarea(attrs={"rows": 3}),
            "scheduled_for": forms.DateTimeInput(
                attrs={"type": "datetime-local"}, format="%Y-%m-%dT%H:%M"
            ),
        }


AdvisoryTimelineFormSet = inlineformset_factory(
    Advisory,
    AdvisoryTimelineEntry,
    fields=["happened_on", "label", "position"],
    widgets={
        "happened_on": forms.DateInput(attrs={"type": "date"}, format="%Y-%m-%d"),
    },
    extra=1,
    can_delete=True,
)

AdvisoryReferenceFormSet = inlineformset_factory(
    Advisory, AdvisoryReference, fields=["title", "url"], extra=1, can_delete=True
)
