"""Formulaire public de signalement d'une vulnerabilite."""

from django import forms
from django.core.exceptions import ValidationError

from apps.core.pgp import is_encrypted_blob
from apps.organizations.models import Organization, OrganizationStatus
from apps.programs.models import Program, ProgramType
from apps.vulnerabilities.constants import Severity, VulnerabilityType
from apps.vulnerabilities.cvss import CVSSError, base_score
from apps.vulnerabilities.models import CWE

from .models import VulnerabilityReport

MAX_TEXT = 20000


class VulnerabilityReportForm(forms.ModelForm):
    """Saisie d'un signalement. Le contenu est du Markdown assaini a l'affichage."""

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
            "program": "Programme concerné",
            "affected_organization": "Organisation affectée",
            "affected_organization_name": "Organisation (si absente de la liste)",
            "product": "Produit / service",
            "target_url": "URL ou endpoint concerné",
            "vulnerability_type": "Type de vulnérabilité",
            "cwe": "CWE",
            "cvss_vector": "Vecteur CVSS v3.1",
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
            "wants_credit": "Je souhaite être crédité publiquement",
            "is_anonymous": "Signaler de manière anonyme",
            "pgp_payload": "Rapport chiffré PGP (optionnel)",
        }
        help_texts = {
            "description": "Markdown autorisé. Décrivez la vulnérabilité factuellement.",
            "steps_to_reproduce": "Markdown autorisé. Une étape par ligne.",
            "cvss_vector": "Exemple : CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "pgp_payload": "Optionnel. Réservé au détail qui rendrait la faille "
            "immédiatement exploitable en cas de fuite — voir « Signalement "
            "chiffré » ci-contre.",
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

        # Champs de reference potentiellement longs : recherche au fil de la
        # frappe (Tom Select, voir static/js/select-enhance.js) plutot qu'un
        # <select> natif a parcourir.
        self.fields["program"].widget.attrs.update(
            {"class": "ts-select", "data-placeholder": "Rechercher un programme…"}
        )
        self.fields["affected_organization"].widget.attrs.update(
            {"class": "ts-select", "data-placeholder": "Rechercher une organisation…"}
        )
        self.fields["cwe"].widget.attrs.update(
            {"class": "ts-select", "data-placeholder": "Rechercher un CWE…"}
        )
        self.fields["vulnerability_type"].widget.attrs.update(
            {"class": "ts-select", "data-placeholder": "Rechercher un type…"}
        )
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

        authenticated = self.user is not None and self.user.is_authenticated
        if program is not None and program.program_type == ProgramType.BUG_BOUNTY:
            # Un Bug Bounty exige un compte, pas seulement une adresse de
            # contact : aucune recompense, aucun historique anti-fraude et
            # aucune deduplication ne tiennent sur un simple email jetable
            # (voir propose_bounty()). C'est la norme sur HackerOne, Bugcrowd,
            # Intigriti, YesWeHack : l'anonymat n'y est jamais l'unique souci,
            # le compte l'est.
            if anonymous:
                self.add_error(
                    "is_anonymous",
                    "Ce programme offre des récompenses : un signalement "
                    "anonyme n'est pas éligible. Créez un compte pour pouvoir "
                    "être récompensé.",
                )
            if not authenticated:
                self.add_error(
                    "program",
                    "Ce programme est un Bug Bounty : un compte est "
                    "obligatoire pour soumettre (attribution de récompense, "
                    "historique, lutte anti-fraude). Créez un compte ou "
                    "connectez-vous avant de signaler ici.",
                )
            elif not self.user.email_verified:
                # Comme le compte, la verification d'email n'est pas un
                # reglage optionnel par programme pour un Bug Bounty : c'est
                # la norme du secteur (HackerOne, Bugcrowd, Intigriti,
                # YesWeHack) des qu'une recompense est en jeu, pour garantir
                # que le declarant reste joignable au moment du paiement.
                self.add_error(
                    "program",
                    "Ce programme est un Bug Bounty : votre adresse email "
                    "doit être vérifiée avant de soumettre (pour rester "
                    "joignable au moment d'une récompense). Vérifiez-la "
                    "depuis votre profil.",
                )
            elif not self.user.mfa_enabled:
                # Meme logique que le compte et l'email verifie : un compte
                # a recompenser est une cible de prise de controle (solde,
                # historique de paiement). HackerOne impose le MFA a tout
                # compte pour cette raison precise. On ne bloque pas tout le
                # compte du chercheur (il reste libre de signaler sur un VDP
                # sans MFA), seulement la soumission a un programme Bug
                # Bounty specifiquement.
                self.add_error(
                    "program",
                    "Ce programme est un Bug Bounty : la double "
                    "authentification doit être activée avant de soumettre "
                    "(votre compte pourrait recevoir une récompense, il "
                    "doit être mieux protégé). Activez-la depuis votre "
                    "profil.",
                )
        elif anonymous and program is not None and not program.allows_anonymous_reports:
            self.add_error(
                "is_anonymous",
                "Ce programme n'accepte pas les signalements anonymes. "
                "Indiquez une adresse de contact ou connectez-vous.",
            )

        # Reglage additionnel, reserve aux VDP : un Bug Bounty l'exige deja
        # structurellement ci-dessus, quel que soit ce champ.
        if (
            program is not None
            and program.program_type != ProgramType.BUG_BOUNTY
            and program.requires_verified_email
            and not (
                self.user is not None
                and self.user.is_authenticated
                and self.user.email_verified
            )
        ):
            self.add_error(
                "program",
                "Ce programme exige une adresse email vérifiée : connectez-vous "
                "avec un compte dont l'email est vérifié pour signaler ici.",
            )
        return cleaned

    def save(self, commit=True):
        report = super().save(commit=False)
        contact = (self.cleaned_data.get("contact_email") or "").strip()
        if contact:
            report.reporter_email = contact
        report.accepted_policy = self.cleaned_data.get("accept_policy", False)
        if report.is_anonymous:
            # Coherence avec credit_for() (apps/disclosures/services.py) qui
            # ignore deja wants_credit en mode anonyme : normalise ici aussi
            # pour qu'aucun futur code ne puisse lire wants_credit=True sans
            # revalider is_anonymous en parallele.
            report.wants_credit = False
        if commit:
            report.save()
        return report


class TrackingCodeForm(forms.Form):
    code = forms.CharField(
        label="Code ou lien de suivi",
        max_length=120,
        widget=forms.TextInput(attrs={"placeholder": "Collez ici votre code de suivi"}),
    )

    def clean_code(self):
        value = (self.cleaned_data.get("code") or "").strip()
        # Tolerance : accepte aussi bien le code seul que le lien complet
        # colle par erreur (ex. https://.../suivi/<code>/).
        if "/" in value:
            value = value.rstrip("/").rsplit("/", 1)[-1]
        return value


class AttachmentUploadForm(forms.Form):
    file = forms.FileField(label="Fichier")
    description = forms.CharField(
        label="Description",
        max_length=255,
        required=False,
        widget=forms.TextInput(attrs={"placeholder": "Capture, trace, PoC…"}),
    )
