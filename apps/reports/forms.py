"""Formulaire public de signalement d'une vulnerabilite."""

from django import forms
from django.core.exceptions import ValidationError

from apps.core.pgp import is_encrypted_blob
from apps.organizations.models import Organization, OrganizationStatus
from apps.programs.models import Program
from apps.vulnerabilities.constants import Severity, VulnerabilityType
from apps.vulnerabilities.cvss import CVSSError, base_score
from apps.vulnerabilities.models import CWE

from .models import VulnerabilityReport

MAX_TEXT = 20000


class VulnerabilityReportForm(forms.ModelForm):
    """Saisie d'un signalement. Le contenu est du Markdown assaini a l'affichage."""

    accept_policy = forms.BooleanField(
        label="Je confirme avoir lu la politique de divulgation et m'engage a "
        "respecter les regles de test.",
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
            "vulnerability_type",
            "cwe",
            "cvss_vector",
            "reported_severity",
            "description",
            "steps_to_reproduce",
            "impact",
            "proof_of_concept",
            "recommendations",
            "affected_version",
            "fixed_version",
            "environment",
            "external_reference",
            "requests_cve",
            "wants_credit",
            "is_anonymous",
            "pgp_payload",
        ]
        labels = {
            "title": "Titre du signalement",
            "program": "Programme concerne",
            "affected_organization": "Organisation affectee",
            "affected_organization_name": "Organisation (si absente de la liste)",
            "product": "Produit / service",
            "target_url": "URL ou endpoint concerne",
            "vulnerability_type": "Type de vulnerabilite",
            "cwe": "CWE",
            "cvss_vector": "Vecteur CVSS v3.1",
            "reported_severity": "Severite estimee",
            "description": "Description",
            "steps_to_reproduce": "Etapes de reproduction",
            "impact": "Impact",
            "proof_of_concept": "Preuve de concept",
            "recommendations": "Recommandations",
            "affected_version": "Version affectee",
            "fixed_version": "Version corrigee (si connue)",
            "environment": "Environnement",
            "external_reference": "Reference externe",
            "requests_cve": "Je demande l'attribution d'un CVE",
            "wants_credit": "Je souhaite etre credite publiquement",
            "is_anonymous": "Signaler de maniere anonyme",
            "pgp_payload": "Rapport chiffre PGP (optionnel)",
        }
        help_texts = {
            "description": "Markdown autorise. Decrivez la vulnerabilite factuellement.",
            "steps_to_reproduce": "Markdown autorise. Une etape par ligne.",
            "cvss_vector": "Exemple : CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "pgp_payload": "Collez ici un bloc PGP MESSAGE chiffre avec la cle "
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
        self.fields["cwe"].queryset = CWE.objects.all()
        self.fields["cwe"].required = False
        self.fields["vulnerability_type"].choices = VulnerabilityType.choices
        self.fields["reported_severity"].choices = Severity.choices
        if user is not None and user.is_authenticated:
            self.fields.pop("contact_email", None)

    def clean_cvss_vector(self):
        vector = (self.cleaned_data.get("cvss_vector") or "").strip()
        if not vector:
            return ""
        try:
            base_score(vector)
        except CVSSError as exc:
            raise ValidationError(str(exc)) from exc
        return vector

    def clean_pgp_payload(self):
        payload = (self.cleaned_data.get("pgp_payload") or "").strip()
        if payload and not is_encrypted_blob(payload):
            raise ValidationError(
                "Le bloc doit etre un message PGP chiffre " "(-----BEGIN PGP MESSAGE-----)."
            )
        return payload

    def clean_description(self):
        description = (self.cleaned_data.get("description") or "").strip()
        if len(description) < 30:
            raise ValidationError(
                "La description doit comporter au moins 30 caracteres pour "
                "permettre une qualification."
            )
        if len(description) > MAX_TEXT:
            raise ValidationError("Description trop longue (20 000 caracteres maximum).")
        return description

    def clean(self):
        cleaned = super().clean()
        anonymous = cleaned.get("is_anonymous")
        contact = (cleaned.get("contact_email") or "").strip()

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
                "Precisez l'organisation affectee ou selectionnez un programme.",
            )

        if program is not None and not program.is_open:
            self.add_error("program", "Ce programme n'accepte plus de soumissions.")
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


class AttachmentUploadForm(forms.Form):
    file = forms.FileField(label="Fichier")
    description = forms.CharField(
        label="Description",
        max_length=255,
        required=False,
        widget=forms.TextInput(attrs={"placeholder": "Capture, trace, PoC…"}),
    )
