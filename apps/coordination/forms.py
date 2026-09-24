"""Formulaires de traitement des cases."""

from django import forms
from django.core.exceptions import ValidationError

from apps.accounts.models import User
from apps.accounts.roles import NATIONAL_ROLES
from apps.organizations.models import Organization, OrganizationStatus
from apps.programs.models import ProgramScope
from apps.vulnerabilities.constants import Severity
from apps.vulnerabilities.cvss import CVSSError, base_score
from apps.vulnerabilities.models import CVE, CWE

from .constants import Confidentiality
from .models import Case, channels_writable_by
from .workflow import CaseStatus


class CaseMessageForm(forms.Form):
    body = forms.CharField(
        label="Message",
        widget=forms.Textarea(attrs={"rows": 4, "placeholder": "Markdown autorisé…"}),
        max_length=20000,
    )
    confidentiality = forms.ChoiceField(
        label="Canal",
        choices=Confidentiality.choices,
        initial=Confidentiality.PARTICIPANTS,
    )

    def __init__(self, *args, user=None, case=None, **kwargs):
        super().__init__(*args, **kwargs)
        # Canaux etanches : chacun n'ecrit que la ou il peut lire.
        allowed = channels_writable_by(user, case) if (user and case) else set()
        choices = [
            (value, label) for value, label in Confidentiality.choices if value in allowed
        ]
        self.fields["confidentiality"].choices = choices
        if choices:
            self.fields["confidentiality"].initial = choices[0][0]

    def clean_body(self):
        body = (self.cleaned_data.get("body") or "").strip()
        if not body:
            raise ValidationError("Le message ne peut pas être vide.")
        return body


class WorkflowActionForm(forms.Form):
    """Un clic = une action du workflow v2, confirmee avec son commentaire."""

    action = forms.CharField(max_length=40, widget=forms.HiddenInput)
    comment = forms.CharField(
        label="Commentaire", required=False, widget=forms.Textarea(attrs={"rows": 3})
    )


class AdmissibilityForm(forms.ModelForm):
    """Checklist de recevabilite (etape 2)."""

    class Meta:
        model = Case
        fields = [
            "admissibility_scope_ok",
            "admissibility_organization_ok",
            "admissibility_attachment_ok",
        ]


class VendorSummaryForm(forms.ModelForm):
    """Version « organisation » du rapport (pre-requis de l'etape 5)."""

    class Meta:
        model = Case
        fields = ["vendor_summary"]
        widgets = {"vendor_summary": forms.Textarea(attrs={"rows": 10})}


class RemediationPlanForm(forms.ModelForm):
    """Plan de remediation de l'organisation (pre-requis de l'etape 6)."""

    class Meta:
        model = Case
        fields = ["remediation_plan", "remediation_due_date"]
        widgets = {
            "remediation_plan": forms.Textarea(attrs={"rows": 5}),
            "remediation_due_date": forms.DateInput(attrs={"type": "date"}),
        }


class FixForm(forms.ModelForm):
    """Correctif declare par l'organisation (pre-requis de l'etape 7)."""

    class Meta:
        model = Case
        fields = ["fix_description", "fix_version"]
        widgets = {"fix_description": forms.Textarea(attrs={"rows": 4})}


class FixVerificationForm(forms.ModelForm):
    """Contre-verification par l'analyste (pre-requis de l'etape 8)."""

    class Meta:
        model = Case
        fields = ["fix_verification_notes"]
        widgets = {"fix_verification_notes": forms.Textarea(attrs={"rows": 4})}


class EscalationForm(forms.Form):
    comment = forms.CharField(
        label="Motif de l'escalade", widget=forms.Textarea(attrs={"rows": 2})
    )


class TriageForm(forms.Form):
    """Qualification technique lors du triage.

    Le champ `scope` n'existe que pour un case rattache a un programme : il
    designe l'actif du perimetre concerne, dont depend la grille de
    recompense quand celle-ci varie par actif.
    """

    severity = forms.ChoiceField(label="Sévérité retenue", choices=Severity.choices)
    scope = forms.ModelChoiceField(
        label="Actif du périmètre",
        queryset=ProgramScope.objects.none(),
        required=False,
        help_text="Détermine la grille de récompense lorsqu'elle varie par actif.",
    )
    cvss_vector = forms.CharField(label="Vecteur CVSS (v3.1 ou v4.0)", required=False)
    cwe = forms.ModelChoiceField(label="CWE", queryset=CWE.objects.all(), required=False)
    organization = forms.ModelChoiceField(
        label="Organisation affectée",
        queryset=Organization.objects.filter(status=OrganizationStatus.ACTIVE),
        required=False,
    )
    tags = forms.CharField(
        label="Étiquettes", required=False, help_text="Séparées par des virgules."
    )

    def __init__(self, *args, case=None, **kwargs):
        super().__init__(*args, **kwargs)
        program = getattr(case, "program", None)
        if program is None:
            # Un case hors programme n'a pas de perimetre : le champ
            # n'aurait aucun choix a proposer.
            del self.fields["scope"]
        else:
            self.fields["scope"].queryset = program.in_scope_targets()

    def clean_cvss_vector(self):
        vector = (self.cleaned_data.get("cvss_vector") or "").strip()
        if not vector:
            return ""
        try:
            base_score(vector)
        except CVSSError as exc:
            raise ValidationError(str(exc)) from exc
        return vector

    def clean_tags(self):
        raw = self.cleaned_data.get("tags") or ""
        return [tag.strip()[:40] for tag in raw.split(",") if tag.strip()][:12]


class AssignmentForm(forms.Form):
    assignee = forms.ModelChoiceField(
        label="Analyste",
        queryset=User.objects.filter(is_active=True, role__in=NATIONAL_ROLES),
        required=False,
    )
    note = forms.CharField(label="Note", required=False, max_length=255)


class DuplicateForm(forms.Form):
    original_case_id = forms.CharField(label="Case original (EVDP-…)", max_length=32)
    comment = forms.CharField(
        label="Commentaire interne", widget=forms.Textarea(attrs={"rows": 2})
    )

    def clean_original_case_id(self):
        case_id = (self.cleaned_data.get("original_case_id") or "").strip().upper()
        original = Case.objects.filter(case_id=case_id).first()
        if original is None:
            raise ValidationError("Aucun case ne correspond à cette référence.")
        return original


class DisclosureScheduleForm(forms.Form):
    disclosure_date = forms.DateField(
        label="Date de divulgation", widget=forms.DateInput(attrs={"type": "date"})
    )


class CveLinkForm(forms.Form):
    cve_id = forms.CharField(label="Identifiant CVE", max_length=24)

    def clean_cve_id(self):
        value = (self.cleaned_data.get("cve_id") or "").strip().upper()
        cve, _ = CVE.objects.get_or_create(cve_id=value)
        return cve


class CaseFilterForm(forms.Form):
    """Filtres de la liste des cases (recherche globale incluse)."""

    q = forms.CharField(label="Recherche", required=False)
    status = forms.ChoiceField(
        label="Statut",
        required=False,
        choices=[("", "Tous les statuts")] + list(CaseStatus.choices),
    )
    severity = forms.ChoiceField(
        label="Sévérité",
        required=False,
        choices=[("", "Toutes severites")] + list(Severity.choices),
    )
    organization = forms.ModelChoiceField(
        label="Organisation",
        required=False,
        queryset=Organization.objects.all(),
        empty_label="Toutes les organisations",
    )
