"""Formulaires des organisations."""

from decimal import Decimal

from django import forms

from . import geo
from .models import MembershipRole, Organization, SecurityContact


class OrganizationForm(forms.ModelForm):
    # Une seule case pour la position : ce qu'on copie depuis Google Maps
    # (« 12.377635, -1.487849 ») se colle tel quel. Le modele garde deux
    # colonnes, que clean_coordinates renseigne.
    coordinates = forms.CharField(
        label="Coordonnées GPS",
        required=False,
        max_length=500,
        widget=forms.TextInput(
            attrs={"placeholder": "12.377635, -1.487849", "autocomplete": "off"}
        ),
        help_text="Collez les coordonnées copiées depuis Google Maps (clic droit sur le "
        "lieu), ou un lien Google Maps. Vide : chef-lieu de la région.",
    )

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
            "coordinates",
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

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance.latitude is not None and self.instance.longitude is not None:
            self.initial["coordinates"] = geo.format_coordinates(
                self.instance.latitude, self.instance.longitude
            )

    def clean_coordinates(self):
        text = (self.cleaned_data.get("coordinates") or "").strip()
        if not text:
            self.instance.latitude = self.instance.longitude = None
            return ""
        try:
            lat, lon = geo.parse_coordinates(text)
        except geo.CoordinatesError as exc:
            raise forms.ValidationError(str(exc)) from exc
        self.instance.latitude = Decimal(f"{lat:.6f}")
        self.instance.longitude = Decimal(f"{lon:.6f}")
        return geo.format_coordinates(lat, lon)


class SecurityContactForm(forms.ModelForm):
    class Meta:
        model = SecurityContact
        fields = ["name", "role", "email", "phone", "pgp_public_key", "is_primary"]
        widgets = {"pgp_public_key": forms.Textarea(attrs={"rows": 3})}


class OrganizationMemberForm(forms.Form):
    """Rattache un compte eVDP a une organisation.

    Si l'email correspond deja a un compte actif, il est simplement rattache.
    Sinon, une invitation est envoyee : un compte est cree (sans mot de passe
    utilisable) et la personne recoit un lien pour choisir le sien, exactement
    comme pour la reinitialisation de mot de passe standard. Le nom complet
    n'est donc obligatoire que dans ce second cas.
    """

    email = forms.EmailField(label="Email du compte eVDP")
    full_name = forms.CharField(
        label="Nom complet",
        required=False,
        max_length=150,
        help_text="Uniquement si la personne n'a pas encore de compte eVDP : "
        "necessaire pour l'invitation.",
    )
    membership_role = forms.ChoiceField(choices=MembershipRole.choices, label="Role")
    is_primary = forms.BooleanField(required=False, label="Contact principal")

    #: renseigne apres nettoyage : l'utilisateur existant, ou None si une
    #: invitation doit etre envoyee.
    user = None

    def clean(self):
        cleaned = super().clean()
        from apps.accounts.models import User

        email = (cleaned.get("email") or "").strip().lower()
        if not email:
            return cleaned
        cleaned["email"] = email
        self.user = User.objects.filter(email=email, is_active=True).first()
        if self.user is None and not (cleaned.get("full_name") or "").strip():
            self.add_error(
                "full_name",
                "Aucun compte eVDP actif avec cette adresse email : indiquez "
                "le nom complet pour envoyer une invitation.",
            )
        return cleaned
