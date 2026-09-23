"""Formulaires d'authentification et de compte."""

from django import forms
from django.contrib.auth.forms import AuthenticationForm, PasswordChangeForm
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

from apps.researchers.models import IdentityMode

from .models import User
from .roles import SELF_SERVICE_ROLES, Role


class EmailAuthenticationForm(AuthenticationForm):
    username = forms.EmailField(
        label="Adresse email",
        widget=forms.EmailInput(attrs={"autocomplete": "email", "autofocus": True}),
    )

    error_messages = {
        **AuthenticationForm.error_messages,
        "invalid_login": "Adresse email ou mot de passe incorrect.",
        "inactive": "Ce compte est désactivé.",
    }


class TotpCodeForm(forms.Form):
    """Saisie du code a six chiffres de l'authentificateur."""

    code = forms.CharField(
        label="Code de votre authentificateur",
        max_length=16,
        widget=forms.TextInput(
            attrs={
                "autocomplete": "one-time-code",
                "inputmode": "numeric",
                "autofocus": True,
                "placeholder": "123456",
            }
        ),
        help_text="Six chiffres, renouvelés toutes les 30 secondes.",
    )

    def clean_code(self):
        # Les authentificateurs affichent le code en deux groupes de trois :
        # l'espace recopie ne doit pas faire echouer une saisie correcte.
        return (self.cleaned_data["code"] or "").replace(" ", "").strip()


class RegistrationForm(forms.ModelForm):
    """Inscription publique : uniquement des roles chercheur."""

    password1 = forms.CharField(
        label="Mot de passe",
        widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}),
        help_text="12 caractères minimum, non trivial.",
    )
    password2 = forms.CharField(
        label="Confirmation du mot de passe",
        widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}),
    )
    pseudonym = forms.CharField(
        label="Pseudonyme",
        max_length=60,
        required=False,
        help_text="Nom affiché si vous choisissez de rester pseudonyme.",
    )
    identity_mode = forms.ChoiceField(
        label="Visibilité de votre identité",
        choices=IdentityMode.choices,
        initial=IdentityMode.PSEUDONYM,
    )
    accept_policy = forms.BooleanField(
        label="J'accepte la politique de divulgation et les règles de test.",
        required=True,
    )

    class Meta:
        model = User
        fields = ["email", "full_name", "role"]
        labels = {
            "email": "Adresse email",
            "full_name": "Nom complet",
            "role": "Type de compte",
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Le role soumis n'est jamais accepte tel quel : la liste est bornee.
        self.fields["role"].choices = [
            (value, label) for value, label in Role.choices if value in SELF_SERVICE_ROLES
        ]
        self.fields["role"].initial = Role.SECURITY_RESEARCHER

    def clean_email(self):
        email = self.cleaned_data["email"].lower().strip()
        if User.objects.filter(email=email).exists():
            # Message neutre : ne pas confirmer l'existence d'un compte.
            raise ValidationError(
                "Impossible de créer ce compte. Si vous possédez déjà un compte, "
                "utilisez la procédure de réinitialisation du mot de passe."
            )
        return email

    def clean_role(self):
        role = self.cleaned_data.get("role")
        if role not in SELF_SERVICE_ROLES:
            raise ValidationError("Type de compte non autorisé à l'inscription.")
        return role

    def clean(self):
        cleaned = super().clean()
        p1, p2 = cleaned.get("password1"), cleaned.get("password2")
        if p1 and p2 and p1 != p2:
            self.add_error("password2", "Les deux mots de passe different.")
        if p1:
            validate_password(p1)
        return cleaned

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password1"])
        user.email_verified = False
        user.is_staff = False
        user.is_superuser = False
        if commit:
            user.save()
        return user


class ProfileForm(forms.ModelForm):
    """Edition du profil. Le role et les drapeaux de securite sont exclus."""

    class Meta:
        model = User
        fields = ["full_name", "display_name", "phone"]
        labels = {
            "full_name": "Nom complet",
            "display_name": "Nom affiché",
            "phone": "Téléphone",
        }


class ResearcherProfileForm(forms.ModelForm):
    class Meta:
        from apps.researchers.models import ResearcherProfile

        model = ResearcherProfile
        fields = [
            "pseudonym",
            "country",
            "affiliation",
            "website",
            "biography",
            "identity_mode",
            "is_public_profile",
        ]
        labels = {
            "pseudonym": "Pseudonyme",
            "country": "Pays",
            "affiliation": "Rattachement",
            "website": "Site web",
            "biography": "Biographie",
            "identity_mode": "Visibilité de l'identité",
            "is_public_profile": "Apparaître dans l'annuaire public",
        }
        widgets = {"biography": forms.Textarea(attrs={"rows": 5})}


class StrongPasswordChangeForm(PasswordChangeForm):
    pass
