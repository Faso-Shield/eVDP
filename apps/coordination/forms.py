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
from .models import Case
from .workflow import CaseStatus, allowed_targets


class CaseMessageForm(forms.Form):
    body = forms.CharField(
        label="Message",
        widget=forms.Textarea(attrs={"rows": 4, "placeholder": "Markdown autorise…"}),
        max_length=20000,
    )
    confidentiality = forms.ChoiceField(
        label="Confidentialite",
        choices=Confidentiality.choices,
        initial=Confidentiality.PARTICIPANTS,
    )

    def __init__(self, *args, user=None, **kwargs):
        super().__init__(*args, **kwargs)
        # Un chercheur ou une organisation ne peut pas publier en interne.
        from apps.accounts.roles import Capability

        if user is None or not user.has_capability(Capability.POST_INTERNAL_MESSAGE):
            self.fields["confidentiality"].choices = [
                (Confidentiality.PARTICIPANTS, Confidentiality.PARTICIPANTS.label)
            ]
        elif not (user.is_superuser or user.role == "NATIONAL_COORDINATOR"):
            self.fields["confidentiality"].choices = [
                (Confidentiality.PARTICIPANTS, Confidentiality.PARTICIPANTS.label),
                (Confidentiality.INTERNAL, Confidentiality.INTERNAL.label),
            ]

    def clean_body(self):
        body = (self.cleaned_data.get("body") or "").strip()
        if not body:
            raise ValidationError("Le message ne peut pas etre vide.")
        return body


class StatusTransitionForm(forms.Form):
    target_status = forms.ChoiceField(label="Nouveau statut")
    comment = forms.CharField(
        label="Commentaire", required=False, widget=forms.Textarea(attrs={"rows": 3})
    )

    def __init__(self, *args, case=None, user=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.case = case
        targets = allowed_targets(case.status, case.workflow) if case else []
        labels = dict(CaseStatus.choices)
        self.fields["target_status"].choices = [(t, labels[t]) for t in targets]


class TriageForm(forms.Form):
    """Qualification technique lors du triage.

    Le champ `scope` n'existe que pour un case rattache a un programme : il
    designe l'actif du perimetre concerne, dont depend la grille de
    recompense quand celle-ci varie par actif.
    """

    severity = forms.ChoiceField(label="Severite retenue", choices=Severity.choices)
    scope = forms.ModelChoiceField(
        label="Actif du perimetre",
        queryset=ProgramScope.objects.none(),
        required=False,
        help_text="Determine la grille de recompense lorsqu'elle varie par actif.",
    )
    cvss_vector = forms.CharField(label="Vecteur CVSS v3.1", required=False)
    cwe = forms.ModelChoiceField(label="CWE", queryset=CWE.objects.all(), required=False)
    organization = forms.ModelChoiceField(
        label="Organisation affectee",
        queryset=Organization.objects.filter(status=OrganizationStatus.ACTIVE),
        required=False,
    )
    tags = forms.CharField(
        label="Etiquettes", required=False, help_text="Separees par des virgules."
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
        label="Commentaire interne", required=False, widget=forms.Textarea(attrs={"rows": 2})
    )

    def clean_original_case_id(self):
        case_id = (self.cleaned_data.get("original_case_id") or "").strip().upper()
        original = Case.objects.filter(case_id=case_id).first()
        if original is None:
            raise ValidationError("Aucun case ne correspond a cette reference.")
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
        label="Severite",
        required=False,
        choices=[("", "Toutes severites")] + list(Severity.choices),
    )
    organization = forms.ModelChoiceField(
        label="Organisation",
        required=False,
        queryset=Organization.objects.all(),
        empty_label="Toutes les organisations",
    )
