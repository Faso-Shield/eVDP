"""Formulaire public de signalement d'une vulnerabilite."""

from django import forms
from django.core.exceptions import ValidationError

from apps.core.pgp import is_encrypted_blob
from apps.organizations.models import Organization, OrganizationStatus
from apps.programs.models import Program

from .models import VulnerabilityReport

MAX_TEXT = 20000


class VulnerabilityReportForm(forms.ModelForm):
    """Saisie d'un signalement. Le contenu est du Markdown assaini a l'affichage.

    La qualification technique (type, CWE, severite, vecteur CVSS, versions,
    environnement) n'est pas demandee au declarant : elle releve de l'analyste
    CSIRT a l'etape 3 (spec v2). Le rapport garde les valeurs par defaut du
    modele (type « Autre », severite « Moyenne ») jusqu'a la qualification.
    """

    accept_policy = forms.BooleanField(
        label="Je confirme avoir lu la politique de divulgation et m'engage à "
        "respecter les règles de test.",
        required=True,
    )
    contact_email = forms.EmailField(
        label="Adresse de contact",
        required=False,
        help_text="Obligatoire si vous signalez sans compte, pour recevoir le suivi.",
    )

    class Meta:
        model = VulnerabilityReport
        fields = [
            "title",
            "program",
            "affected_organization",
            "affected_organization_name",
            "product",
            "target_url",
            "description",
            "steps_to_reproduce",
            "impact",
            "proof_of_concept",
            "recommendations",
            "requests_cve",
            "wants_credit",
            "is_anonymous",
            "pgp_payload",
        ]
        labels = {
            "title": "Titre du signalement",
            "program": "Programme concerné",
            "affected_organization": "Organisation affectée",
            "affected_organization_name": "Organisation (si absente de la liste)",
            "product": "Produit / service",
            "target_url": "URL ou endpoint concerné",
            "vulnerability_type": "Type de vulnérabilité",
            "cwe": "CWE",
            "cvss_vector": "Vecteur CVSS (v3.1 ou v4.0)",
            "reported_severity": "Sévérité estimée",
            "description": "Description",
            "steps_to_reproduce": "Étapes de reproduction",
            "impact": "Impact",
            "proof_of_concept": "Preuve de concept",
            "recommendations": "Recommandations",
            "affected_version": "Version affectée",
            "fixed_version": "Version corrigée (si connue)",
            "environment": "Environnement",
            "external_reference": "Référence externe",
            "requests_cve": "Je demande l'attribution d'un CVE",
            "wants_credit": "Je souhaite être crédité publiquement (incompatible avec l'anonymat)",
            "is_anonymous": "Signaler de manière anonyme",
            "pgp_payload": "Rapport chiffré PGP (optionnel)",
        }
        help_texts = {
            "description": "Markdown autorisé. Décrivez la vulnérabilité factuellement.",
            "steps_to_reproduce": "Markdown autorisé. Une étape par ligne.",
            "cvss_vector": "Exemple : CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "pgp_payload": "Collez ici un bloc PGP MESSAGE chiffré avec la clé "
            "publique nationale si le contenu est trop sensible.",
        }
        widgets = {
            "description": forms.Textarea(attrs={"rows": 8}),
            "steps_to_reproduce": forms.Textarea(attrs={"rows": 6}),
            "impact": forms.Textarea(attrs={"rows": 4}),
            "proof_of_concept": forms.Textarea(attrs={"rows": 6}),
            "recommendations": forms.Textarea(attrs={"rows": 4}),
            "pgp_payload": forms.Textarea(attrs={"rows": 6}),
            "target_url": forms.TextInput(attrs={"placeholder": "https://exemple.gov.bf/…"}),
        }

    def __init__(self, *args, user=None, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)
        self.fields["program"].queryset = Program.objects.public()
        self.fields["program"].required = False
        self.fields["affected_organization"].queryset = Organization.objects.filter(
            status=OrganizationStatus.ACTIVE, accepts_vdp=True
        )
        self.fields["affected_organization"].required = False
        if user is not None and user.is_authenticated:
            self.fields.pop("contact_email", None)

    def clean_pgp_payload(self):
        payload = (self.cleaned_data.get("pgp_payload") or "").strip()
        if payload and not is_encrypted_blob(payload):
            raise ValidationError(
                "Le bloc doit être un message PGP chiffré " "(-----BEGIN PGP MESSAGE-----)."
            )
        return payload

    def clean_description(self):
        description = (self.cleaned_data.get("description") or "").strip()
        if len(description) < 30:
            raise ValidationError(
                "La description doit comporter au moins 30 caractères pour "
                "permettre une qualification."
            )
        if len(description) > MAX_TEXT:
            raise ValidationError("Description trop longue (20 000 caractères maximum).")
        return description

    def clean(self):
        cleaned = super().clean()
        anonymous = cleaned.get("is_anonymous")
        contact = (cleaned.get("contact_email") or "").strip()
        if anonymous and cleaned.get("wants_credit"):
            self.add_error(
                "wants_credit",
                "Un signalement anonyme ne peut pas être crédité publiquement : "
                "décochez l'une des deux options.",
            )

        # Le declarant doit etre porte par l'instance AVANT la validation du
        # modele (_post_clean), sinon VulnerabilityReport.clean() rejette un
        # rapport pourtant valide.
        if self.user is not None and self.user.is_authenticated:
            self.instance.reporter = self.user
        elif contact:
            self.instance.reporter_email = contact
        elif not anonymous:
            self.add_error(
                "contact_email",
                "Indiquez une adresse de contact ou cochez le signalement anonyme.",
            )

        organization = cleaned.get("affected_organization")
        org_name = (cleaned.get("affected_organization_name") or "").strip()
        program = cleaned.get("program")
        if not organization and not org_name and not program:
            self.add_error(
                "affected_organization",
                "Précisez l'organisation affectée ou sélectionnez un programme.",
            )

        if program is not None and not program.is_open:
            self.add_error("program", "Ce programme n'accepte plus de soumissions.")
        if program is not None:
            motif = program.reporter_rejection(self.user, is_anonymous=bool(anonymous))
            if motif:
                self.add_error("program", motif)
        return cleaned

    def save(self, commit=True):
        report = super().save(commit=False)
        contact = (self.cleaned_data.get("contact_email") or "").strip()
        if contact:
            report.reporter_email = contact
        report.accepted_policy = self.cleaned_data.get("accept_policy", False)
        if commit:
            report.save()
        return report


class TrackingCodeForm(forms.Form):
    code = forms.CharField(
        label="Code ou lien de suivi",
        max_length=120,
        widget=forms.TextInput(
            attrs={
                "placeholder": "ABCD-EFGH-JKMN-PQRS-TUVW",
                "autocomplete": "off",
                "autocapitalize": "characters",
                "spellcheck": "false",
            }
        ),
        help_text="Majuscules, minuscules, espaces ou tirets : peu importe.",
    )

    def clean_code(self):
        value = (self.cleaned_data.get("code") or "").strip()
        # Tolerance : accepte aussi bien le code seul que le lien complet
        # colle par erreur (ex. https://.../suivi/<code>/).
        if "/" in value:
            value = value.rstrip("/").rsplit("/", 1)[-1]
        if not value:
            raise ValidationError("Saisissez votre code de suivi.")
        return value


class TrackingComplementForm(forms.Form):
    """Reponse d'un declarant anonyme a une demande de complements."""

    body = forms.CharField(
        label="Votre réponse",
        max_length=MAX_TEXT,
        widget=forms.Textarea(attrs={"rows": 6}),
    )


class AttachmentUploadForm(forms.Form):
    file = forms.FileField(label="Fichier")
    description = forms.CharField(
        label="Description",
        max_length=255,
        required=False,
        widget=forms.TextInput(attrs={"placeholder": "Capture, trace, PoC…"}),
    )
