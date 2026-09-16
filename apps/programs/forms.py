"""Formulaires de gestion des programmes."""

from django import forms
from django.forms import inlineformset_factory

from apps.organizations.models import Organization, OrganizationStatus

from .models import Program, ProgramScope, RewardPolicy, RewardTier


class ProgramForm(forms.ModelForm):
    class Meta:
        model = Program
        fields = [
            "name",
            "program_type",
            "organization",
            "status",
            "confidentiality",
            "summary",
            "description",
            "rules",
            "out_of_scope_notes",
            "safe_harbor",
            "disclosure_policy",
            "eligibility",
            "starts_on",
            "ends_on",
            "contact_email",
            "pgp_public_key",
            "sla_policy",
            "disclosure_delay_days",
            "requires_verified_email",
            "allows_anonymous_reports",
        ]
        labels = {
            "name": "Nom du programme",
            "program_type": "Type de programme",
            "organization": "Organisation",
            "status": "Statut",
            "confidentiality": "Niveau de confidentialité",
            "summary": "Résumé",
            "description": "Description",
            "rules": "Règles de test",
            "out_of_scope_notes": "Hors périmètre (note)",
            "safe_harbor": "Safe Harbor",
            "disclosure_policy": "Politique de divulgation",
            "eligibility": "Conditions d'éligibilité",
            "starts_on": "Date de début",
            "ends_on": "Date de fin",
            "contact_email": "Email de contact",
            "pgp_public_key": "Clé publique PGP (contact direct, hors eVDP)",
            "sla_policy": "Politique SLA",
            "disclosure_delay_days": "Délai de divulgation (jours)",
            "requires_verified_email": "Exiger un email vérifié",
            "allows_anonymous_reports": "Accepter les signalements anonymes",
        }
        widgets = {
            "starts_on": forms.DateInput(attrs={"type": "date"}, format="%Y-%m-%d"),
            "ends_on": forms.DateInput(attrs={"type": "date"}, format="%Y-%m-%d"),
            "description": forms.Textarea(attrs={"rows": 6}),
            "rules": forms.Textarea(attrs={"rows": 5}),
            "out_of_scope_notes": forms.Textarea(attrs={"rows": 4}),
            "safe_harbor": forms.Textarea(attrs={"rows": 5}),
            "disclosure_policy": forms.Textarea(attrs={"rows": 4}),
            "eligibility": forms.Textarea(attrs={"rows": 4}),
            "pgp_public_key": forms.Textarea(attrs={"rows": 4}),
        }

    def __init__(self, *args, user=None, **kwargs):
        super().__init__(*args, **kwargs)
        queryset = Organization.objects.filter(status=OrganizationStatus.ACTIVE)
        # Une DSI ne peut creer un programme que pour ses propres organisations.
        if user is not None and not user.is_national:
            queryset = queryset.filter(id__in=user.organization_ids())
        self.fields["organization"].queryset = queryset
        self.fields["organization"].widget.attrs.update(
            {"class": "ts-select", "data-placeholder": "Rechercher une organisation…"}
        )


class ProgramScopeForm(forms.ModelForm):
    class Meta:
        model = ProgramScope
        fields = [
            "in_scope",
            "target_type",
            "identifier",
            "application",
            "platform",
            "environment",
            "priority",
            "description",
            "is_active",
        ]
        labels = {
            "in_scope": "Dans le périmètre",
            "target_type": "Type de cible",
            "identifier": "Identifiant",
            "application": "Application",
            "platform": "Plateforme",
            "environment": "Environnement",
            "priority": "Priorité",
            "description": "Description",
            "is_active": "Actif",
        }
        widgets = {"description": forms.Textarea(attrs={"rows": 2})}


class RewardPolicyForm(forms.ModelForm):
    class Meta:
        model = RewardPolicy
        fields = ["currency", "is_active", "total_budget", "notes"]
        labels = {
            "currency": "Devise",
            "is_active": "Politique active",
            "total_budget": "Budget total",
            "notes": "Notes",
        }


RewardTierFormSet = inlineformset_factory(
    RewardPolicy,
    RewardTier,
    fields=["severity", "min_amount", "max_amount", "description"],
    extra=1,
    can_delete=True,
)
