"""Formulaires des organisations."""

from django import forms

from .models import Organization, SecurityContact


class OrganizationForm(forms.ModelForm):
    class Meta:
        model = Organization
        fields = [
            "name",
            "acronym",
            "organization_type",
            "sector",
            "domain",
            "official_email",
            "phone",
            "website",
            "address",
            "region",
            "status",
            "dsi_name",
            "dsi_email",
            "manager_name",
            "manager_email",
            "pgp_public_key",
            "description",
            "accepts_vdp",
        ]
        labels = {
            "name": "Nom",
            "acronym": "Sigle",
            "organization_type": "Type",
            "sector": "Secteur",
            "domain": "Domaine principal",
            "official_email": "Email officiel",
            "phone": "Téléphone",
            "website": "Site web",
            "address": "Adresse",
            "region": "Région",
            "status": "Statut",
            "dsi_name": "Responsable DSI",
            "dsi_email": "Email DSI",
            "manager_name": "Responsable",
            "manager_email": "Email responsable",
            "pgp_public_key": "Clé publique PGP",
            "description": "Description",
            "accepts_vdp": "Accepte les signalements via eVDP",
        }
        widgets = {
            "description": forms.Textarea(attrs={"rows": 4}),
            "pgp_public_key": forms.Textarea(attrs={"rows": 4}),
        }


class SecurityContactForm(forms.ModelForm):
    class Meta:
        model = SecurityContact
        fields = ["name", "role", "email", "phone", "pgp_public_key", "is_primary"]
        widgets = {"pgp_public_key": forms.Textarea(attrs={"rows": 3})}
